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

// Package wiretranscript implements an explicitly enabled bidirectional wire protocol
// transcript format and its offline replay.
//
// A transcript records, for a single connection, the full logical sequence of requests
// and responses (including their wire opcodes, request identifiers, correlation identifiers
// and end reason), using a self-describing binary format with a versioned header, length
// bounded integrity-checked frames, a total size budget, and a finalization footer that
// allows readers to distinguish complete transcripts from torn ones.
//
// Authentication exchanges are never stored as payloads by default: credential-bearing
// frames are represented by non-replayable placeholders, and optional field-level
// redaction always keeps the remaining BSON legally encoded.
package wiretranscript

import (
	"errors"
	"time"

	"github.com/FerretDB/wire"
)

// Format-level constants.
const (
	// FormatVersion is the only supported transcript format version.
	FormatVersion uint32 = 1

	// fileMagic is the 8-byte magic number stored at the beginning of every transcript file.
	fileMagic = "FRRBWT01"

	// footerMagic is the 8-byte magic number stored at the beginning of the finalization footer.
	footerMagic = "FRRBWTE1"

	// frameMagic marks the start boundary of a frame.
	// Its little-endian on-disk bytes are 'F', 'R', 'T', 'F'.
	frameMagic uint32 = 0x46525446

	// headerLen is the fixed size of the transcript header.
	headerLen = 8 + 4 + 4 + 8 + 8 + 4

	// frameFixedLen is the fixed size of a frame without payload, masked field declarations
	// and the trailing checksum.
	frameFixedLen = 4 + 4 + 1 + 1 + 8 + 4 + 4 + 4 + 4

	// frameMinLen is the smallest possible frame (no payload and no masked fields).
	frameMinLen = frameFixedLen + 2 + 4

	// footerLen is the fixed size of the finalization footer.
	footerLen = 8 + 4 + 4 + 8 + 8 + 32 + 4

	// DefaultMaxBytes is the default per-connection total size budget.
	DefaultMaxBytes int64 = 256 << 20 // 256 MiB

	// maxReadBytes is the hard limit on the transcript size accepted by the reader.
	maxReadBytes int64 = 1 << 30 // 1 GiB

	// FileExt is the extension of finalized transcript files.
	FileExt = ".wt"

	// partialExt is the extension of not yet finalized transcript files.
	partialExt = ".wpartial"
)

// Header flags.
const (
	// headerFlagRedactAuth means that authentication exchange frames are stored
	// as non-replayable placeholders without payloads.
	headerFlagRedactAuth uint32 = 1 << 0

	// headerFlagIDSequential declares that request identifiers are remapped sequentially
	// during replay.
	headerFlagIDSequential uint32 = 1 << 1
)

// Frame flags.
const (
	// frameFlagRedacted means that the frame payload contains field-level redactions
	// declared in Frame.MaskedFields.
	frameFlagRedacted uint8 = 1 << 0

	// frameFlagAuthPlaceholder means that the frame is an authentication exchange frame
	// stored without a payload; it must never be replayed from the transcript.
	frameFlagAuthPlaceholder uint8 = 1 << 1
)

// Footer flags.
const (
	// footerFlagBudgetExhausted means that the size budget was reached and further frames
	// were not recorded.
	footerFlagBudgetExhausted uint32 = 1 << 0

	// footerFlagRecorderFailure means that the recorder encountered an I/O failure.
	footerFlagRecorderFailure uint32 = 1 << 1
)

// Direction of a recorded frame.
type Direction uint8

const (
	// DirectionRequest is a frame sent by the client to the server.
	DirectionRequest Direction = 1

	// DirectionResponse is a frame sent by the server to the client.
	DirectionResponse Direction = 2
)

// String implements [fmt.Stringer].
func (d Direction) String() string {
	switch d {
	case DirectionRequest:
		return "request"
	case DirectionResponse:
		return "response"
	default:
		return "unknown"
	}
}

// EndReason explains why the recorded connection ended.
type EndReason uint32

const (
	// EndReasonUnspecified is used when the reason is not known.
	EndReasonUnspecified EndReason = 0

	// EndReasonClientClosed means that the client closed the connection cleanly.
	EndReasonClientClosed EndReason = 1

	// EndReasonReadError means that reading a client message failed.
	EndReasonReadError EndReason = 2

	// EndReasonWriteError means that writing a server response failed.
	EndReasonWriteError EndReason = 3

	// EndReasonHandlerError means that the middleware could not produce a response.
	EndReasonHandlerError EndReason = 4

	// EndReasonPanic means that the connection goroutine panicked.
	EndReasonPanic EndReason = 5

	// EndReasonBudgetExhausted means that the transcript size budget was reached.
	EndReasonBudgetExhausted EndReason = 6

	// EndReasonRecorderFailure means that the recorder itself failed.
	EndReasonRecorderFailure EndReason = 7

	// EndReasonContextCanceled means that the connection context was canceled.
	EndReasonContextCanceled EndReason = 8
)

// String implements [fmt.Stringer].
func (r EndReason) String() string {
	switch r {
	case EndReasonClientClosed:
		return "client_closed"
	case EndReasonReadError:
		return "read_error"
	case EndReasonWriteError:
		return "write_error"
	case EndReasonHandlerError:
		return "handler_error"
	case EndReasonPanic:
		return "panic"
	case EndReasonBudgetExhausted:
		return "budget_exhausted"
	case EndReasonRecorderFailure:
		return "recorder_failure"
	case EndReasonContextCanceled:
		return "context_canceled"
	case EndReasonUnspecified:
		fallthrough
	default:
		return "unspecified"
	}
}

// Sentinel errors returned by the reader and the replayer.
var (
	// ErrVersion is returned when the transcript version is unsupported.
	ErrVersion = errors.New("unsupported transcript version")

	// ErrBadBoundary is returned when a frame or footer boundary magic is invalid.
	ErrBadBoundary = errors.New("bad transcript boundary")

	// ErrTruncated is returned when a declared frame does not have enough bytes.
	ErrTruncated = errors.New("truncated transcript frame")

	// ErrChecksum is returned when a frame, header or footer checksum does not match.
	ErrChecksum = errors.New("transcript checksum mismatch")

	// ErrUnknownOpcode is returned when a frame carries an unknown wire opcode.
	ErrUnknownOpcode = errors.New("unknown wire opcode")

	// ErrCorrelation is returned when requestID/responseTo correlation cannot be verified.
	ErrCorrelation = errors.New("request/response correlation error")

	// ErrIncomplete is returned when the transcript is missing a valid finalization footer.
	ErrIncomplete = errors.New("incomplete transcript")

	// ErrAuthPlaceholder is returned when replay reaches a non-replayable authentication frame.
	ErrAuthPlaceholder = errors.New("non-replayable authentication frame")

	// ErrUnmappedHandle is returned when a runtime handle (for example, a cursor ID)
	// has no mapping established from a real recorded response.
	ErrUnmappedHandle = errors.New("unmapped runtime handle")
)

// Frame is a single recorded bidirectional wire frame.
type Frame struct {
	// Seq is the zero-based logical sequence number of the frame on the connection.
	Seq uint64

	// Direction is the direction of the frame.
	Direction Direction

	// OpCode is the wire opcode copied from the message header.
	OpCode wire.OpCode

	// RequestID is the wire request identifier.
	RequestID int32

	// ResponseTo is the wire correlation identifier.
	ResponseTo int32

	// Payload is the complete marshaled wire message (header and body).
	// It is nil for authentication placeholders.
	Payload []byte

	// MaskedFields declares which comparisons are masked for this frame,
	// for example "pwd" for a redacted credential field
	// or "payload:saslStart" for a whole-payload authentication placeholder.
	MaskedFields []string

	// Offset is the byte offset of the frame in the transcript file.
	Offset int64

	// Redacted is true when the payload contains field-level redactions.
	Redacted bool

	// AuthPlaceholder is true when the frame is an authentication exchange placeholder.
	AuthPlaceholder bool

	// Incomplete is true when the frame could not be fully validated because
	// the transcript was torn before its finalization.
	Incomplete bool
}

// Transcript is a parsed transcript file.
type Transcript struct {
	// Version is the format version.
	Version uint32

	// Flags are the parsed header flags.
	Flags uint32

	// MaxBytes is the declared total size budget.
	MaxBytes uint64

	// CreatedAt is the transcript creation time.
	CreatedAt time.Time

	// Frames are the recorded frames in logical order.
	Frames []*Frame

	// EndReason is the connection end reason from the footer.
	EndReason EndReason

	// Complete is true only when the finalization footer is present and valid.
	Complete bool

	// BudgetExhausted is true when the recorder reached its size budget.
	BudgetExhausted bool

	// RecorderFailure is true when the recorder reported an I/O failure.
	RecorderFailure bool

	// path is the source file path.
	path string
}

// Path returns the source file path of the transcript.
func (t *Transcript) Path() string {
	return t.path
}

// knownOpcodes lists all wire opcodes the format accepts.
var knownOpcodes = map[wire.OpCode]struct{}{
	wire.OpCodeReply:       {},
	wire.OpCodeUpdate:      {},
	wire.OpCodeInsert:      {},
	wire.OpCodeGetByOID:    {},
	wire.OpCodeQuery:       {},
	wire.OpCodeGetMore:     {},
	wire.OpCodeDelete:      {},
	wire.OpCodeKillCursors: {},
	wire.OpCodeCompressed:  {},
	wire.OpCodeMsg:         {},
}
