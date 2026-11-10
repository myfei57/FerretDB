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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/FerretDB/wire"
)

// Open reads and validates a transcript file.
//
// A torn file (missing or invalid finalization footer) returns a [Transcript] together
// with an error wrapping [ErrIncomplete]; the last unvalidated response frame is marked
// and must never be treated as a successful recording. Structural problems (bad boundary,
// truncation, checksum or correlation failures) return a non-nil error wrapping one of
// the package sentinel errors together with the byte offset where it was detected.
func Open(path string) (*Transcript, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if int64(len(b)) > maxReadBytes {
		return nil, fmt.Errorf("%w: file size %d exceeds hard limit %d", ErrBadBoundary, len(b), maxReadBytes)
	}

	t := &Transcript{path: path}

	if len(b) < headerLen {
		return t, fmt.Errorf("%w: offset 0: header is truncated: got %d bytes, need %d", ErrTruncated, len(b), headerLen)
	}

	if err = parseHeader(b[:headerLen], t); err != nil {
		return t, err
	}

	offset := headerLen

	for offset < len(b) {
		// A footer may start at this offset.
		if len(b)-offset >= len(footerMagic) && string(b[offset:offset+len(footerMagic)]) == footerMagic {
			break
		}

		var frame *Frame
		if frame, offset, err = parseFrame(b, offset); err != nil {
			return t, err
		}

		t.Frames = append(t.Frames, frame)
	}

	if err = parseFooter(b, offset, t); err != nil {
		// The transcript is torn: keep parsed frames but flag incompleteness.
		t.Complete = false

		if len(t.Frames) > 0 && t.Frames[len(t.Frames)-1].Direction == DirectionResponse {
			t.Frames[len(t.Frames)-1].Incomplete = true
		}

		return t, err
	}

	t.Complete = true

	if err = verifyCorrelation(t); err != nil {
		return t, err
	}

	return t, nil
}

// parseHeader validates the fixed-size transcript header.
func parseHeader(b []byte, t *Transcript) error {
	if string(b[:len(fileMagic)]) != fileMagic {
		return fmt.Errorf("%w: offset 0: invalid file magic %q", ErrBadBoundary, b[:len(fileMagic)])
	}

	off := len(fileMagic)
	t.Version = binary.LittleEndian.Uint32(b[off:])
	off += 4

	if t.Version != FormatVersion {
		return fmt.Errorf("%w: %d (supported: %d)", ErrVersion, t.Version, FormatVersion)
	}

	t.Flags = binary.LittleEndian.Uint32(b[off:])
	off += 4
	t.MaxBytes = binary.LittleEndian.Uint64(b[off:])
	off += 8

	createdNano := int64(binary.LittleEndian.Uint64(b[off:]))
	off += 8
	t.CreatedAt = time.Unix(0, createdNano)

	wantCRC := binary.LittleEndian.Uint32(b[off:])
	gotCRC := crc32.Checksum(b[:off], crc32.MakeTable(crc32.Castagnoli))

	if wantCRC != gotCRC {
		return fmt.Errorf("%w: offset %d: header checksum %08x, calculated %08x", ErrChecksum, off, wantCRC, gotCRC)
	}

	return nil
}

// parseFrame parses a single frame starting at offset and returns the offset just past it.
func parseFrame(b []byte, offset int) (*Frame, int, error) {
	frameStart := int64(offset)

	if len(b)-offset < 4 {
		return nil, offset, fmt.Errorf("%w: offset %d: not enough bytes for frame boundary", ErrTruncated, offset)
	}

	if magic := binary.LittleEndian.Uint32(b[offset:]); magic != frameMagic {
		return nil, offset, fmt.Errorf("%w: offset %d: invalid frame magic %08x", ErrBadBoundary, offset, magic)
	}

	offset += 4

	if len(b)-offset < frameFixedLen-4 {
		return nil, offset, fmt.Errorf("%w: offset %d: frame header is truncated", ErrTruncated, frameStart)
	}

	frameLen := int(binary.LittleEndian.Uint32(b[offset:]))
	offset += 4

	if frameLen < frameMinLen {
		return nil, offset, fmt.Errorf("%w: offset %d: declared frame length %d is smaller than minimum %d",
			ErrTruncated, frameStart, frameLen, frameMinLen)
	}

	if frameLen > len(b)-int(frameStart) {
		return nil, offset, fmt.Errorf(
			"%w: offset %d: declared frame length %d but only %d bytes remain",
			ErrTruncated, frameStart, frameLen, len(b)-int(frameStart),
		)
	}

	frameEnd := int(frameStart) + frameLen
	frameBytes := b[frameStart:frameEnd]

	direction := Direction(frameBytes[8])
	flags := frameBytes[9]
	seq := binary.LittleEndian.Uint64(frameBytes[10:18])
	opcode := wire.OpCode(int32(binary.LittleEndian.Uint32(frameBytes[18:22])))
	requestID := int32(binary.LittleEndian.Uint32(frameBytes[22:26]))
	responseTo := int32(binary.LittleEndian.Uint32(frameBytes[26:30]))
	payloadLen := int(binary.LittleEndian.Uint32(frameBytes[30:34]))

	pos := frameFixedLen

	// Even with zero masked field declarations, the payload must leave room for
	// the masked count (2 bytes) and the frame checksum (4 bytes).
	if frameFixedLen+payloadLen+2+4 > frameLen {
		return nil, offset, fmt.Errorf("%w: offset %d: payload length %d exceeds frame bounds",
			ErrTruncated, frameStart, payloadLen)
	}

	payload := append([]byte(nil), frameBytes[pos:pos+payloadLen]...)
	pos += payloadLen

	maskedCount := int(binary.LittleEndian.Uint16(frameBytes[pos:]))
	pos += 2

	masked := make([]string, 0, maskedCount)

	for range maskedCount {
		if pos+2 > len(frameBytes)-4 {
			return nil, offset, fmt.Errorf("%w: offset %d: masked field declaration is truncated",
				ErrTruncated, frameStart)
		}

		pathLen := int(binary.LittleEndian.Uint16(frameBytes[pos:]))
		pos += 2

		if pos+pathLen > len(frameBytes)-4 {
			return nil, offset, fmt.Errorf("%w: offset %d: masked field path is truncated",
				ErrTruncated, frameStart)
		}

		masked = append(masked, string(frameBytes[pos:pos+pathLen]))
		pos += pathLen
	}

	if pos+4 != len(frameBytes) {
		return nil, offset, fmt.Errorf("%w: offset %d: frame has %d trailing bytes before checksum",
			ErrBadBoundary, frameStart, len(frameBytes)-pos-4)
	}

	wantCRC := binary.LittleEndian.Uint32(frameBytes[pos:])
	gotCRC := crc32.Checksum(frameBytes[:pos], crc32.MakeTable(crc32.Castagnoli))

	if wantCRC != gotCRC {
		return nil, offset, fmt.Errorf("%w: offset %d: frame %d checksum %08x, calculated %08x",
			ErrChecksum, frameStart, seq, wantCRC, gotCRC)
	}

	if _, ok := knownOpcodes[opcode]; !ok {
		return nil, offset, fmt.Errorf("%w: offset %d: frame %d carries unknown opcode %d",
			ErrUnknownOpcode, frameStart, seq, int32(opcode))
	}

	frame := &Frame{
		Seq:             seq,
		Direction:       direction,
		OpCode:          opcode,
		RequestID:       requestID,
		ResponseTo:      responseTo,
		Payload:         payload,
		MaskedFields:    masked,
		Offset:          frameStart,
		Redacted:        flags&frameFlagRedacted != 0,
		AuthPlaceholder: flags&frameFlagAuthPlaceholder != 0,
	}

	if frame.AuthPlaceholder {
		if payloadLen != 0 {
			return nil, offset, fmt.Errorf("%w: offset %d: authentication placeholder frame %d must have no payload",
				ErrBadBoundary, frameStart, seq)
		}
	} else if err := validatePayload(frame); err != nil {
		return nil, offset, err
	}

	return frame, frameEnd, nil
}

// validatePayload checks that the recorded payload is itself a complete wire message.
func validatePayload(frame *Frame) error {
	if len(frame.Payload) < wire.MsgHeaderLen {
		return fmt.Errorf("%w: offset %d: frame %d payload is shorter than wire header",
			ErrTruncated, frame.Offset, frame.Seq)
	}

	header, body, err := wire.ReadMessage(bufio.NewReader(bytes.NewReader(frame.Payload)))
	if err != nil {
		return fmt.Errorf("%w: offset %d: frame %d payload is not a complete wire message: %v",
			ErrTruncated, frame.Offset, frame.Seq, err)
	}

	if header.OpCode != frame.OpCode {
		return fmt.Errorf("%w: offset %d: frame %d opcode %s does not match payload opcode %s",
			ErrBadBoundary, frame.Offset, frame.Seq, frame.OpCode, header.OpCode)
	}

	if header.RequestID != frame.RequestID || header.ResponseTo != frame.ResponseTo {
		return fmt.Errorf("%w: offset %d: frame %d header identifiers do not match payload",
			ErrCorrelation, frame.Offset, frame.Seq)
	}

	if body == nil {
		return fmt.Errorf("%w: offset %d: frame %d payload has no body", ErrTruncated, frame.Offset, frame.Seq)
	}

	return nil
}

// parseFooter validates the finalization footer.
func parseFooter(b []byte, offset int, t *Transcript) error {
	if offset == len(b) {
		return fmt.Errorf("%w: missing finalization footer", ErrIncomplete)
	}

	if len(b)-offset < footerLen {
		return fmt.Errorf("%w: offset %d: footer is truncated: got %d bytes, need %d",
			ErrIncomplete, offset, len(b)-offset, footerLen)
	}

	if string(b[offset:offset+len(footerMagic)]) != footerMagic {
		return fmt.Errorf("%w: offset %d: invalid footer magic", ErrBadBoundary, offset)
	}

	pos := offset + len(footerMagic)
	t.EndReason = EndReason(binary.LittleEndian.Uint32(b[pos:]))
	pos += 4

	footerFlags := binary.LittleEndian.Uint32(b[pos:])
	pos += 4
	t.BudgetExhausted = footerFlags&footerFlagBudgetExhausted != 0
	t.RecorderFailure = footerFlags&footerFlagRecorderFailure != 0

	frameCount := binary.LittleEndian.Uint64(b[pos:])
	pos += 8

	if frameCount != uint64(len(t.Frames)) {
		return fmt.Errorf("%w: offset %d: footer declares %d frames, parsed %d",
			ErrIncomplete, offset, frameCount, len(t.Frames))
	}

	pos += 8 // data bytes

	wantSum := append([]byte(nil), b[pos:pos+sha256.Size]...)
	pos += sha256.Size

	gotSum := sha256.Sum256(b[:offset])
	if !bytes.Equal(wantSum, gotSum[:]) {
		return fmt.Errorf("%w: offset %d: footer digest does not match transcript contents", ErrChecksum, offset)
	}

	wantCRC := binary.LittleEndian.Uint32(b[pos:])
	gotCRC := crc32.Checksum(b[offset:pos], crc32.MakeTable(crc32.Castagnoli))

	if wantCRC != gotCRC {
		return fmt.Errorf("%w: offset %d: footer checksum %08x, calculated %08x",
			ErrChecksum, offset, wantCRC, gotCRC)
	}

	return nil
}

// verifyCorrelation verifies requestID/responseTo relationships and frame sequencing.
func verifyCorrelation(t *Transcript) error {
	requests := make(map[int32]int)
	answered := make(map[int32]int)

	for i, f := range t.Frames {
		if f.Seq != uint64(i) {
			return fmt.Errorf("%w: frame at index %d declares sequence %d", ErrCorrelation, i, f.Seq)
		}

		switch f.Direction {
		case DirectionRequest:
			if prev, ok := requests[f.RequestID]; ok {
				return fmt.Errorf("%w: offset %d: duplicate requestID %d (first seen at frame %d)",
					ErrCorrelation, f.Offset, f.RequestID, prev)
			}

			requests[f.RequestID] = i

		case DirectionResponse:
			reqIdx, ok := requests[f.ResponseTo]
			if !ok {
				return fmt.Errorf("%w: offset %d: response frame %d references unknown requestID %d",
					ErrCorrelation, f.Offset, i, f.ResponseTo)
			}

			if prev, dup := answered[f.ResponseTo]; dup {
				return fmt.Errorf("%w: offset %d: requestID %d is answered twice (frames %d and %d)",
					ErrCorrelation, f.Offset, f.ResponseTo, prev, i)
			}

			answered[f.ResponseTo] = i

			req := t.Frames[reqIdx]
			if req.AuthPlaceholder != f.AuthPlaceholder {
				return fmt.Errorf(
					"%w: offset %d: placeholder parity violated between request frame %d and response frame %d",
					ErrCorrelation, f.Offset, reqIdx, i,
				)
			}

		default:
			return fmt.Errorf("%w: offset %d: frame %d has unknown direction %d",
				ErrBadBoundary, f.Offset, i, f.Direction)
		}
	}

	return nil
}

// FindFiles returns the given file path or, when path is a directory, all transcript files
// (with [FileExt] extension) found recursively in it.
func FindFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{path}, nil
	}

	var files []string

	err = filepath.WalkDir(path, func(p string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if !entry.IsDir() && filepath.Ext(entry.Name()) == FileExt {
			files = append(files, p)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}
