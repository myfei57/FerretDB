// Copyright 2021 FerretDB Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wiretranscript

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/FerretDB/wire"
)

// RecorderOpts represents recorder configuration.
//
//nolint:vet // for readability
type RecorderOpts struct {
	// MaxBytes is the per-connection total size budget.
	// Zero or negative values select DefaultMaxBytes.
	MaxBytes int64

	// KeepAuthPayload disables authentication exchange placeholder redaction.
	// It defaults to false: authentication payloads are never stored.
	KeepAuthPayload bool

	// RedactFields are the top-level BSON fields redacted in credential-bearing commands.
	// Nil selects the default set ("pwd").
	RedactFields []string

	// Logger is used for recorder diagnostics; nil selects a discarded logger.
	Logger *slog.Logger
}

// Recorder records a bidirectional transcript of a single connection.
//
// All Record* methods are fail-safe: an I/O failure, budget exhaustion or panic never
// affects the production connection, it only disables further recording.
type Recorder struct {
	f   *os.File // nil when constructed directly with an io.WriteCloser
	wc  io.WriteCloser
	w   *bufio.Writer
	h   hash.Hash
	dir string

	maxBytes     int64
	written      int64
	redactFields []string
	keepAuth     bool
	headerFlags  uint32

	l *slog.Logger

	mu sync.Mutex

	seq             uint64
	frameCount      uint64
	dead            bool
	closed          bool
	budgetExhausted bool
	failed          bool
	path            string

	// authRequestIDs stores request identifiers of authentication exchange frames
	// so that their responses are stored as placeholders too.
	authRequestIDs map[int32]struct{}
}

// NewRecorder creates a transcript file in the given directory (creating it if needed)
// and writes its versioned header. The file is finalized by [Recorder.Close].
func NewRecorder(dir string, opts *RecorderOpts) (*Recorder, error) {
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return nil, err
	}

	f, err := os.CreateTemp(dir, "_*"+partialExt)
	if err != nil {
		return nil, err
	}

	r := newRecorder(f, dir, opts)
	r.f = f

	return r, nil
}

// Path returns the finalized transcript file path, or an empty string before [Recorder.Close].
func (r *Recorder) Path() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.path
}

// newRecorder writes the transcript header into the given writer.
func newRecorder(wc io.WriteCloser, dir string, opts *RecorderOpts) *Recorder {
	if opts == nil {
		opts = new(RecorderOpts)
	}

	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	redactFields := opts.RedactFields
	if redactFields == nil {
		redactFields = append([]string(nil), defaultRedactFields...)
	}

	l := opts.Logger
	if l == nil {
		l = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	flags := headerFlagIDSequential
	if !opts.KeepAuthPayload {
		flags |= headerFlagRedactAuth
	}

	r := &Recorder{
		wc:             wc,
		w:              bufio.NewWriter(wc),
		h:              sha256.New(),
		dir:            dir,
		maxBytes:       maxBytes,
		redactFields:   redactFields,
		keepAuth:       opts.KeepAuthPayload,
		headerFlags:    flags,
		l:              l,
		authRequestIDs: make(map[int32]struct{}),
	}

	r.writeHeader()

	return r
}

// writeHeader writes the versioned transcript header.
func (r *Recorder) writeHeader() {
	var buf bytes.Buffer

	buf.WriteString(fileMagic)
	_ = binary.Write(&buf, binary.LittleEndian, FormatVersion)
	_ = binary.Write(&buf, binary.LittleEndian, r.headerFlags)
	_ = binary.Write(&buf, binary.LittleEndian, uint64(r.maxBytes))
	_ = binary.Write(&buf, binary.LittleEndian, time.Now().UnixNano())

	crc := crc32.Checksum(buf.Bytes(), crc32.MakeTable(crc32.Castagnoli))
	_ = binary.Write(&buf, binary.LittleEndian, crc)

	if err := r.writeAll(buf.Bytes()); err != nil {
		r.markDead(err)
	}
}

// RecordRequest records a client request. It never returns an error and never panics:
// recording problems can not change the production response.
func (r *Recorder) RecordRequest(header *wire.MsgHeader, body wire.MsgBody) {
	r.safely(func() {
		payload, flags, masked := r.prepareRequest(header, body)
		r.recordFrame(DirectionRequest, header, payload, flags, masked)
	})
}

// RecordResponse records a server response. It never returns an error and never panics.
func (r *Recorder) RecordResponse(header *wire.MsgHeader, body wire.MsgBody) {
	r.safely(func() {
		payload, flags, masked := r.prepareResponse(header, body)
		r.recordFrame(DirectionResponse, header, payload, flags, masked)
	})
}

// prepareRequest applies the configured redaction policy to a request message.
func (r *Recorder) prepareRequest(header *wire.MsgHeader, body wire.MsgBody) (payload []byte, flags uint8, masked []string) {
	raw, err := marshalWire(header, body)
	if err != nil {
		r.markDead(err)
		return nil, 0, nil
	}

	if !r.keepAuth {
		if cmd, ok := authCommand(body); ok {
			r.mu.Lock()
			r.authRequestIDs[header.RequestID] = struct{}{}
			r.mu.Unlock()

			return nil, frameFlagAuthPlaceholder, []string{"payload:" + cmd}
		}
	}

	if _, ok := needsFieldRedaction(body, r.redactFields); ok {
		redacted, redactedFields, err := redactPayload(raw, r.redactFields)
		if err != nil {
			r.markDead(err)
			return nil, 0, nil
		}

		if len(redactedFields) > 0 {
			return redacted, frameFlagRedacted, redactedFields
		}
	}

	return raw, 0, nil
}

// prepareResponse applies the configured redaction policy to a response message.
func (r *Recorder) prepareResponse(header *wire.MsgHeader, body wire.MsgBody) (payload []byte, flags uint8, masked []string) {
	r.mu.Lock()
	_, isAuth := r.authRequestIDs[header.ResponseTo]
	r.mu.Unlock()

	if !r.keepAuth && isAuth {
		return nil, frameFlagAuthPlaceholder, []string{"payload:auth-response"}
	}

	raw, err := marshalWire(header, body)
	if err != nil {
		r.markDead(err)
		return nil, 0, nil
	}

	// Responses of credential commands do not carry secrets, but apply the same declared
	// field policy for symmetry whenever such fields are present.
	if _, ok := needsFieldRedaction(body, r.redactFields); ok {
		redacted, redactedFields, err := redactPayload(raw, r.redactFields)
		if err != nil {
			r.markDead(err)
			return nil, 0, nil
		}

		if len(redactedFields) > 0 {
			return redacted, frameFlagRedacted, redactedFields
		}
	}

	return raw, 0, nil
}

// recordFrame assembles, bounds and writes a single frame.
func (r *Recorder) recordFrame(direction Direction, header *wire.MsgHeader, payload []byte, flags uint8, masked []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.dead || r.closed {
		return
	}

	frame, err := r.buildFrame(direction, header, payload, flags, masked)
	if err != nil {
		r.markDeadLocked(err)
		return
	}

	// The budget covers header and frames; the fixed-size footer is always written
	// so that completeness remains judgeable.
	if r.written+int64(len(frame)) > r.maxBytes {
		r.budgetExhausted = true
		return
	}

	if err = r.writeAllLocked(frame); err != nil {
		r.markDeadLocked(err)
		return
	}

	r.seq++
	r.frameCount++
}

// buildFrame serializes a frame and computes its integrity checksum.
func (r *Recorder) buildFrame(
	direction Direction, header *wire.MsgHeader, payload []byte, flags uint8, masked []string,
) ([]byte, error) {
	var buf bytes.Buffer

	_ = binary.Write(&buf, binary.LittleEndian, frameMagic)

	// Frame length is patched after the full frame is assembled.
	sizePos := buf.Len()
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))

	buf.WriteByte(byte(direction))
	buf.WriteByte(flags)
	_ = binary.Write(&buf, binary.LittleEndian, r.seq)
	_ = binary.Write(&buf, binary.LittleEndian, int32(header.OpCode))
	_ = binary.Write(&buf, binary.LittleEndian, header.RequestID)
	_ = binary.Write(&buf, binary.LittleEndian, header.ResponseTo)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(payload)))
	buf.Write(payload)

	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(masked)))

	for _, path := range masked {
		pathBytes := []byte(path)
		if len(pathBytes) > 0xffff {
			return nil, fmt.Errorf("masked field path is too long: %d", len(pathBytes))
		}

		_ = binary.Write(&buf, binary.LittleEndian, uint16(len(pathBytes)))
		buf.Write(pathBytes)
	}

	frame := buf.Bytes()

	// Patch the frame length before computing the checksum so that both cover identical bytes.
	// The length includes the 4 checksum bytes appended below.
	binary.LittleEndian.PutUint32(frame[sizePos:sizePos+4], uint32(len(frame)+4))

	crc := crc32.Checksum(frame, crc32.MakeTable(crc32.Castagnoli))
	_ = binary.Write(&buf, binary.LittleEndian, crc)

	return buf.Bytes(), nil
}

// Close finalizes the transcript with the given end reason and, for file-backed
// recorders, renames the temporary file to its final name.
// It is safe to call multiple times.
func (r *Recorder) Close(reason EndReason) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}

	r.closed = true

	if !r.dead {
		if err := r.writeFooterLocked(reason); err != nil {
			r.markDeadLocked(err)
		}
	}

	if err := r.w.Flush(); err != nil {
		r.markDeadLocked(err)
	}

	if r.f != nil && !r.dead {
		// Sync before Close, like the legacy raw recorder does.
		if err := r.f.Sync(); err != nil {
			r.l.WarnContext(context.Background(), "Failed to sync transcript file", slog.String("error", err.Error()))
		}
	}

	closeErr := r.wc.Close()

	if r.f == nil {
		if r.dead {
			return fmt.Errorf("transcript recorder failed: %w", closeErr)
		}

		return nil
	}

	if r.dead {
		_ = os.Remove(r.f.Name())
		return fmt.Errorf("transcript recorder failed: %w", closeErr)
	}

	finalName := r.finalName()
	if err := os.Rename(r.f.Name(), finalName); err != nil {
		return fmt.Errorf("failed to finalize transcript: %w", err)
	}

	r.path = finalName

	return nil
}

// writeFooterLocked writes the finalization footer with the integrity boundary.
func (r *Recorder) writeFooterLocked(reason EndReason) error {
	var flags uint32
	if r.budgetExhausted {
		flags |= footerFlagBudgetExhausted
	}

	if r.failed {
		flags |= footerFlagRecorderFailure
	}

	var buf bytes.Buffer

	buf.WriteString(footerMagic)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(reason))
	_ = binary.Write(&buf, binary.LittleEndian, flags)
	_ = binary.Write(&buf, binary.LittleEndian, r.frameCount)
	_ = binary.Write(&buf, binary.LittleEndian, uint64(r.written))
	buf.Write(r.h.Sum(nil))

	crc := crc32.Checksum(buf.Bytes(), crc32.MakeTable(crc32.Castagnoli))
	_ = binary.Write(&buf, binary.LittleEndian, crc)

	return r.writeAllLocked(buf.Bytes())
}

// finalName builds the final file name from time and random suffix.
func (r *Recorder) finalName() string {
	var b [4]byte
	_, _ = rand.Read(b[:])

	name := fmt.Sprintf("%d-%x%s", time.Now().UnixNano(), b[:], FileExt)

	return filepath.Join(r.dir, name)
}

// writeAll writes bytes to the buffered writer, the running hash and the budget counter.
func (r *Recorder) writeAll(b []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.writeAllLocked(b)
}

// writeAllLocked is the locked variant of writeAll.
func (r *Recorder) writeAllLocked(b []byte) error {
	if _, err := r.w.Write(b); err != nil {
		return err
	}

	// Flush per write so the process never accumulates an unbounded buffer.
	if err := r.w.Flush(); err != nil {
		return err
	}

	_, _ = r.h.Write(b)
	r.written += int64(len(b))

	return nil
}

// markDead disables the recorder after a failure without affecting the caller.
func (r *Recorder) markDead(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.markDeadLocked(err)
}

// markDeadLocked is the locked variant of markDead.
func (r *Recorder) markDeadLocked(err error) {
	if r.dead {
		return
	}

	r.dead = true
	r.failed = true
	r.l.ErrorContext(context.Background(), "Wire transcript recording failed", slog.String("error", err.Error()))
}

// safely runs f while converting panics into recorder failures.
func (r *Recorder) safely(f func()) {
	defer func() {
		if p := recover(); p != nil {
			r.markDead(fmt.Errorf("panic: %v", p))
		}
	}()

	f()
}

// marshalWire serializes a complete wire message (header followed by body).
func marshalWire(header *wire.MsgHeader, body wire.MsgBody) ([]byte, error) {
	headerBytes, err := header.MarshalBinary()
	if err != nil {
		return nil, err
	}

	bodyBytes, err := body.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(headerBytes, bodyBytes...), nil
}
