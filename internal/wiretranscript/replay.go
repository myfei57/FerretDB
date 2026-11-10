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
	"fmt"
	"io"
	"log/slog"

	"github.com/pmezard/go-difflib/difflib"

	"github.com/FerretDB/wire"
	"github.com/FerretDB/wire/wirebson"

	"github.com/FerretDB/FerretDB/v2/internal/handler/middleware"
)

// Transport executes a single request against a real handler or a test transport.
// Replay never returns recorded answers: every replayed request goes through this function.
type Transport func(ctx context.Context, req *middleware.Request) (*middleware.Response, error)

// ReplayOpts configures transcript replay.
//
//nolint:vet // for readability
type ReplayOpts struct {
	// Transport is the handler-side transport used for every replayed request.
	Transport Transport

	// SkipAuth enables safe-subsequence mode: authentication exchange placeholders are
	// skipped and only the frames following the exchange are verified.
	SkipAuth bool

	// AuthSession, when non-nil, is invoked once before replay to inject an externally
	// established authenticated session. Authentication placeholders are still skipped,
	// because redacted content can never be used to forge a login.
	AuthSession func(ctx context.Context) error

	// Logger is used for diagnostics; nil selects a discarded logger.
	Logger *slog.Logger
}

// Status is the outcome of replaying (or skipping) a frame.
type Status int

const (
	// StatusMatched means the live response matches the recorded response.
	StatusMatched Status = iota

	// StatusMasked means the comparison matched with declared field-level masking.
	StatusMasked

	// StatusAuthSkipped means the authentication frame was skipped by policy.
	StatusAuthSkipped

	// StatusMismatch means the live response differs from the recorded response.
	StatusMismatch

	// StatusIncomplete means the frame was not fully recorded and can not be verified.
	StatusIncomplete

	// StatusTransportError means the transport failed while handling the request.
	StatusTransportError

	// StatusUnmappedHandle means a runtime handle had no mapping from a real response.
	StatusUnmappedHandle

	// StatusAuthBlocked means replay reached a non-replayable frame without an auth policy.
	StatusAuthBlocked
)

// String implements [fmt.Stringer].
func (s Status) String() string {
	switch s {
	case StatusMatched:
		return "matched"
	case StatusMasked:
		return "masked"
	case StatusAuthSkipped:
		return "auth_skipped"
	case StatusMismatch:
		return "mismatch"
	case StatusIncomplete:
		return "incomplete"
	case StatusTransportError:
		return "transport_error"
	case StatusUnmappedHandle:
		return "unmapped_handle"
	case StatusAuthBlocked:
		return "auth_blocked"
	default:
		return "unknown"
	}
}

// FrameResult describes what happened to one frame during replay.
type FrameResult struct {
	// Seq is the transcript frame sequence number.
	Seq uint64

	// Status is the outcome.
	Status Status

	// Detail is a human-readable explanation.
	Detail string

	// Diff is the unified diff between recorded and live responses for mismatches.
	Diff string
}

// Report is the replay outcome.
type Report struct {
	// Path is the replayed transcript path.
	Path string

	// Complete mirrors Transcript.Complete.
	Complete bool

	// EndReason is the recorded end reason.
	EndReason EndReason

	// HandlerCalls is the number of requests actually sent to the transport.
	HandlerCalls int

	// Results contains one entry per recorded frame.
	Results []*FrameResult

	// MaskedComparisons lists all declared comparisons that were masked.
	MaskedComparisons []string
}

// Replay drives the given transcript through the configured transport.
// It returns a report together with a non-nil error when replay could not verify
// the whole transcript (auth blocked, unmapped handle, torn tail, or transport failure).
func Replay(ctx context.Context, t *Transcript, opts *ReplayOpts) (*Report, error) {
	if opts == nil || opts.Transport == nil {
		return nil, fmt.Errorf("replay transport is not configured")
	}

	if t.Flags&headerFlagIDSequential == 0 {
		return nil, fmt.Errorf("transcript does not declare a supported requestID remapping policy")
	}

	l := opts.Logger
	if l == nil {
		l = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	report := &Report{
		Path:      t.path,
		Complete:  t.Complete,
		EndReason: t.EndReason,
	}

	if opts.AuthSession != nil {
		if err := opts.AuthSession(ctx); err != nil {
			return report, fmt.Errorf("failed to inject authentication session: %w", err)
		}
	}

	// responseBy maps request frame sequence to its response frame.
	responseBy := make(map[uint64]*Frame)

	for _, f := range t.Frames {
		if f.Direction == DirectionResponse {
			responseBy[uint64(f.ResponseTo)] = f
		}
	}

	idMap := make(map[int32]int32)
	nextID := int32(1)

	// Bidirectional cursor handle mappings established from real responses.
	recToLive := make(map[int64]int64)
	liveToRec := make(map[int64]int64)

	var firstErr error

	addResult := func(seq uint64, status Status, detail, diff string) {
		report.Results = append(report.Results, &FrameResult{
			Seq:    seq,
			Status: status,
			Detail: detail,
			Diff:   diff,
		})

		if firstErr == nil && status == StatusMismatch {
			firstErr = fmt.Errorf("frame %d: recorded and live responses differ", seq)
			l.WarnContext(ctx, "Replay mismatch", slog.Uint64("frame_seq", seq), slog.String("diff", diff))
		}
	}

	for _, reqFrame := range t.Frames {
		if reqFrame.Direction != DirectionRequest {
			continue
		}

		respFrame := responseBy[uint64(reqFrame.RequestID)]

		if reqFrame.AuthPlaceholder {
			detail := fmt.Sprintf("authentication frame %d (%s) is not replayable", reqFrame.Seq, reqFrame.MaskedFields)

			if opts.AuthSession == nil && !opts.SkipAuth {
				addResult(reqFrame.Seq, StatusAuthBlocked, detail, "")

				if respFrame != nil {
					addResult(respFrame.Seq, StatusAuthBlocked, "authentication response frame is not replayable", "")
				}

				return report, fmt.Errorf("%w: inject an authentication session or enable safe-subsequence mode",
					ErrAuthPlaceholder)
			}

			addResult(reqFrame.Seq, StatusAuthSkipped, detail, "")
			report.MaskedComparisons = append(report.MaskedComparisons, reqFrame.MaskedFields...)

			if respFrame != nil {
				addResult(respFrame.Seq, StatusAuthSkipped, "authentication response frame skipped", "")
			}

			continue
		}

		if respFrame != nil && respFrame.Incomplete {
			addResult(reqFrame.Seq, StatusIncomplete, "request before an incompletely recorded response", "")
			addResult(respFrame.Seq, StatusIncomplete, "last response was not fully recorded; not treated as success", "")

			if firstErr == nil {
				firstErr = fmt.Errorf("%w: frame %d", ErrIncomplete, respFrame.Seq)
			}

			continue
		}

		newID := nextID
		nextID++
		idMap[reqFrame.RequestID] = newID

		req, err := buildReplayRequest(reqFrame, newID, recToLive)
		if err != nil {
			addResult(reqFrame.Seq, StatusUnmappedHandle, err.Error(), "")

			return report, err
		}

		liveResp, err := opts.Transport(ctx, req)
		report.HandlerCalls++

		if err != nil {
			addResult(reqFrame.Seq, StatusTransportError, err.Error(), "")
			return report, fmt.Errorf("frame %d: transport failed: %w", reqFrame.Seq, err)
		}

		if liveResp == nil {
			addResult(reqFrame.Seq, StatusTransportError, "transport returned nil response", "")
			return report, fmt.Errorf("frame %d: transport returned nil response", reqFrame.Seq)
		}

		if respFrame == nil {
			addResult(reqFrame.Seq, StatusIncomplete, "request has no recorded response", "")
			continue
		}

		result, diff, err := compareResponse(respFrame, liveResp, newID, idMap, recToLive, liveToRec)
		if err != nil {
			addResult(respFrame.Seq, result, err.Error(), diff)
			return report, fmt.Errorf("frame %d: %w", respFrame.Seq, err)
		}

		if len(respFrame.MaskedFields) > 0 {
			report.MaskedComparisons = append(report.MaskedComparisons, respFrame.MaskedFields...)

			if result == StatusMatched {
				result = StatusMasked
			}
		}

		addResult(reqFrame.Seq, StatusMatched, "request handled by transport", "")
		addResult(respFrame.Seq, result, "response compared against live handler output", diff)
	}

	if !t.Complete && firstErr == nil {
		firstErr = fmt.Errorf("%w: missing finalization footer", ErrIncomplete)
	}

	return report, firstErr
}

// buildReplayRequest reconstructs a middleware request from a recorded frame,
// remapping its request identifier and any known runtime handles.
func buildReplayRequest(frame *Frame, newID int32, recToLive map[int64]int64) (*middleware.Request, error) {
	header, body, err := wire.ReadMessage(bufio.NewReader(bytes.NewReader(frame.Payload)))
	if err != nil {
		return nil, fmt.Errorf("frame %d: cannot parse recorded request: %w", frame.Seq, err)
	}

	header.RequestID = newID

	msg, ok := body.(*wire.OpMsg)
	if !ok {
		// Legacy OP_QUERY carries no cursor handles remapped by this implementation.
		header.ResponseTo = remapID(header.ResponseTo, nil)

		return middleware.RequestWire(header, body)
	}

	// Deep decoding is required to obtain editable arrays (for example, killCursors cursors);
	// shallow decoding would leave nested values as wirebson.RawArray.
	doc, err := msg.DocumentDeep()
	if err != nil {
		return nil, fmt.Errorf("frame %d: cannot decode request document: %w", frame.Seq, err)
	}

	copyDoc := doc.Copy()

	switch copyDoc.Command() {
	case "getMore":
		recordedID, ok := copyDoc.Get("getMore").(int64)
		if !ok {
			return nil, fmt.Errorf("frame %d: getMore command has no int64 cursor handle", frame.Seq)
		}

		liveID, ok := recToLive[recordedID]
		if !ok {
			return nil, fmt.Errorf("%w: frame %d: getMore cursor %d was never returned by a recorded response",
				ErrUnmappedHandle, frame.Seq, recordedID)
		}

		if err = copyDoc.Replace("getMore", liveID); err != nil {
			return nil, err
		}

	case "killCursors":
		arr, ok := copyDoc.Get("cursors").(*wirebson.Array)
		if !ok {
			return nil, fmt.Errorf("frame %d: killCursors command has no cursors array", frame.Seq)
		}

		newArr := wirebson.MakeArray(arr.Len())

		for _, v := range arr.All() {
			recordedID, ok := v.(int64)
			if !ok {
				return nil, fmt.Errorf("frame %d: killCursors contains non-int64 cursor handle", frame.Seq)
			}

			liveID, ok := recToLive[recordedID]
			if !ok {
				return nil, fmt.Errorf("%w: frame %d: killCursors cursor %d has no mapping",
					ErrUnmappedHandle, frame.Seq, recordedID)
			}

			_ = newArr.Add(liveID)
		}

		if err = copyDoc.Replace("cursors", newArr); err != nil {
			return nil, err
		}
	}

	newBody, err := wire.NewOpMsg(copyDoc)
	if err != nil {
		return nil, err
	}

	header.MessageLength = int32(wire.MsgHeaderLen + newBody.Size())

	return middleware.RequestWire(header, newBody)
}

// compareResponse compares the recorded response frame with the live response,
// extending the cursor handle mappings from the real response.
func compareResponse(
	frame *Frame, liveResp *middleware.Response, newID int32, idMap map[int32]int32,
	recToLive map[int64]int64, liveToRec map[int64]int64,
) (Status, string, error) {
	recHeader, recBody, err := wire.ReadMessage(bufio.NewReader(bytes.NewReader(frame.Payload)))
	if err != nil {
		return StatusIncomplete, "", fmt.Errorf("cannot parse recorded response: %w", err)
	}

	liveHeader := liveResp.WireHeader()

	if liveHeader.OpCode != recHeader.OpCode {
		return StatusMismatch, "", fmt.Errorf("opcode mismatch: recorded %s, live %s", recHeader.OpCode, liveHeader.OpCode)
	}

	if liveHeader.ResponseTo != newID {
		return StatusMismatch, "", fmt.Errorf(
			"responseTo mismatch: live %d, expected remapped %d", liveHeader.ResponseTo, newID,
		)
	}

	mappedResponseTo, ok := idMap[recHeader.ResponseTo]
	if !ok || mappedResponseTo != newID {
		return StatusMismatch, "", fmt.Errorf(
			"recorded responseTo %d does not correlate with remapped request %d", recHeader.ResponseTo, newID,
		)
	}

	recMsg, recOK := recBody.(*wire.OpMsg)
	if !recOK {
		return compareLegacyReply(frame, recBody, liveResp)
	}

	liveMsg, ok := liveResp.WireBody().(*wire.OpMsg)
	if !ok {
		return StatusMismatch, "", fmt.Errorf("live response is not OP_MSG")
	}

	recDoc, err := recMsg.DocumentDeep()
	if err != nil {
		return StatusIncomplete, "", fmt.Errorf("cannot decode recorded document: %w", err)
	}

	liveDoc, err := liveMsg.DocumentDeep()
	if err != nil {
		return StatusTransportError, "", fmt.Errorf("cannot decode live document: %w", err)
	}

	// Establish the bidirectional cursor mapping from the real response before comparison.
	recCursor, recHasCursor := cursorID(recDoc)
	liveCursor, liveHasCursor := cursorID(liveDoc)

	if recHasCursor && liveHasCursor {
		// The bidirectional mapping is established only from real responses.
		recToLive[recCursor] = liveCursor
		liveToRec[liveCursor] = recCursor

		recordedID, ok := liveToRec[liveCursor]
		if !ok {
			return StatusUnmappedHandle, "", fmt.Errorf("%w: live cursor %d has no reverse mapping",
				ErrUnmappedHandle, liveCursor)
		}

		liveDoc = replaceCursorID(liveDoc, recordedID)
	}

	recDoc = maskDocument(recDoc, frame.MaskedFields)
	liveDoc = maskDocument(liveDoc, frame.MaskedFields)

	if wirebson.Equal(recDoc, liveDoc) {
		return StatusMatched, "", nil
	}

	diff, err := diffDocuments(recDoc, liveDoc)
	if err != nil {
		return StatusMismatch, "", err
	}

	return StatusMismatch, diff, nil
}

// compareLegacyReply compares OP_REPLY bodies used with legacy OP_QUERY requests.
func compareLegacyReply(frame *Frame, recBody wire.MsgBody, liveResp *middleware.Response) (Status, string, error) {
	recReply, ok := recBody.(*wire.OpReply)
	if !ok {
		return StatusMismatch, "", fmt.Errorf("recorded body type %T is not supported", recBody)
	}

	liveReply, ok := liveResp.WireBody().(*wire.OpReply)
	if !ok {
		return StatusMismatch, "", fmt.Errorf("live response body type %T is not OP_REPLY", liveResp.WireBody())
	}

	recDoc, err := recReply.Document()
	if err != nil {
		return StatusIncomplete, "", err
	}

	liveDoc, err := liveReply.Document()
	if err != nil {
		return StatusTransportError, "", err
	}

	recDoc = maskDocument(recDoc, frame.MaskedFields)
	liveDoc = maskDocument(liveDoc, frame.MaskedFields)

	if wirebson.Equal(recDoc, liveDoc) {
		return StatusMatched, "", nil
	}

	diff, err := diffDocuments(recDoc, liveDoc)
	if err != nil {
		return StatusMismatch, "", err
	}

	return StatusMismatch, diff, nil
}

// cursorID extracts the "cursor.id" int64 handle from a response document, if present.
func cursorID(doc *wirebson.Document) (int64, bool) {
	cursor, ok := doc.Get("cursor").(*wirebson.Document)
	if !ok {
		return 0, false
	}

	id, ok := cursor.Get("id").(int64)

	return id, ok
}

// replaceCursorID returns a deep copy of doc with cursor.id replaced by the recorded value,
// so that runtime-assigned handles do not show up as response differences.
func replaceCursorID(doc *wirebson.Document, recordedID int64) *wirebson.Document {
	raw, err := doc.Encode()
	if err != nil {
		panic(err)
	}

	deep, err := raw.DecodeDeep()
	if err != nil {
		panic(err)
	}

	cursor, ok := deep.Get("cursor").(*wirebson.Document)
	if !ok {
		return deep
	}

	_ = cursor.Replace("id", recordedID)

	return deep
}

// remapID remaps a correlation identifier using the given map.
// A zero identifier (used by client requests) is always preserved.
func remapID(id int32, idMap map[int32]int32) int32 {
	if id == 0 {
		return 0
	}

	if mapped, ok := idMap[id]; ok {
		return mapped
	}

	return id
}

// diffDocuments builds a unified diff between two decoded documents.
func diffDocuments(recorded, live *wirebson.Document) (string, error) {
	return difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(wirebson.LogMessageIndent(recorded)),
		FromFile: "recorded",
		B:        difflib.SplitLines(wirebson.LogMessageIndent(live)),
		ToFile:   "live",
		Context:  2,
	})
}
