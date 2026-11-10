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

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/AlekSi/lazyerrors"
	"github.com/FerretDB/wire/wirebson"

	"github.com/FerretDB/FerretDB/v2/internal/dataapi/api"
	"github.com/FerretDB/FerretDB/v2/internal/util/logging"
)

// streamBatchSize is the batchSize value sent to the backend with find/getMore.
// It bounds the number of documents a single backend round-trip produces.
const streamBatchSize int32 = 1000

const (
	// streamWriteTimeout is the per-write (and per-flush) deadline.
	// A slow reader blocks the handler for at most that long on each write,
	// which provides backpressure without allowing a stuck reader forever.
	streamWriteTimeout = 30 * time.Second

	// streamCleanupTimeout bounds the killCursors cleanup call.
	// The underlying cursor close itself waits up to 3 seconds.
	streamCleanupTimeout = 5 * time.Second
)

// Stream budgets. They are variables (not constants) so tests can use smaller
// values, but they must not be modified outside tests.
var (
	// streamMaxDocuments bounds the total number of document lines written.
	streamMaxDocuments int64 = 10_000_000

	// streamMaxBytes bounds the total number of bytes written, including line envelopes.
	streamMaxBytes int64 = 256 << 20 // 256 MiB

	// streamMaxDuration bounds the whole stream, including backend round-trips.
	streamMaxDuration = 10 * time.Minute
)

// streamMaxEmptyBatches bounds the number of consecutive batches with zero
// documents while the cursor is still open.
//
// A non-tailable cursor should return documents or close, so an endless
// sequence of empty batches is a backend misbehavior worth stopping on.
//
// It is a variable (not a constant) only so tests can use a smaller value.
var streamMaxEmptyBatches int64 = 100

// NDJSON line types.
const (
	streamLineTypeDocument = "document"
	streamLineTypeEnd      = "end"
	streamLineTypeError    = "error"
)

// Error codes used in typed trailing error records.
const (
	// streamErrorBackend is used when the backend fails after streaming started
	// (a failed getMore, a nil response, or a malformed response).
	streamErrorBackend = "BackendError"

	// streamErrorBudget is used when one of the stream budgets is exceeded.
	streamErrorBudget = "BudgetExceeded"

	// streamErrorInternal is used for unexpected server-side failures,
	// such as a document that cannot be encoded.
	streamErrorInternal = "InternalError"
)

// Budget exceed reasons used in the "reason" field of typed trailing error records.
const (
	streamReasonDocuments    = "documents"
	streamReasonBytes        = "bytes"
	streamReasonDuration     = "duration"
	streamReasonEmptyBatches = "empty_batches"
)

// streamDocumentLine is a single result document line of the NDJSON response.
type streamDocumentLine struct {
	Type     string          `json:"type"`
	Document json.RawMessage `json:"document"`
}

// streamEndLine is the terminal line written exactly once on successful completion.
type streamEndLine struct {
	Type string `json:"type"`
}

// streamErrorLine is a typed terminal line written when an error occurs
// after the response headers were already sent. It is never followed
// by an end line.
type streamErrorLine struct {
	Type      string `json:"type"`
	ErrorCode string `json:"error_code"`
	Reason    string `json:"reason,omitempty"`
	Error     string `json:"error"`
}

// ndjsonWriter writes complete JSON lines to [http.ResponseWriter],
// flushing after every line and applying a per-write deadline.
type ndjsonWriter struct {
	rw http.ResponseWriter
	rc *http.ResponseController
}

// newNDJSONWriter creates a writer for the streaming response.
func newNDJSONWriter(rw http.ResponseWriter) *ndjsonWriter {
	return &ndjsonWriter{
		rw: rw,
		rc: http.NewResponseController(rw),
	}
}

// write sends one complete line to the client and flushes it immediately.
//
// It blocks while the client is not reading (backpressure); the per-write
// deadline and the request context ensure it cannot block forever.
func (w *ndjsonWriter) write(line []byte) error {
	// Best effort: some [http.ResponseWriter] implementations (test recorders,
	// for example) do not support write deadlines.
	if err := w.rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout)); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		return lazyerrors.Error(err)
	}

	if _, err := w.rw.Write(line); err != nil {
		return lazyerrors.Error(err)
	}

	if err := w.rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return lazyerrors.Error(err)
	}

	return nil
}

// flush sends buffered headers and data to the client.
func (w *ndjsonWriter) flush() error {
	if err := w.rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return lazyerrors.Error(err)
	}

	return nil
}

// FindStream implements the streaming find endpoint: POST /action/findStream.
//
// The request body is the same as for Find, but the response is a stream
// of newline-delimited JSON records (application/x-ndjson), one canonical
// Extended JSON document per line, consumed from the backend through
// the existing find/getMore commands:
//
//   - {"type":"document","document":<Extended JSON document>} for each result document;
//   - {"type":"end"} as the single terminal record of a successfully completed stream;
//   - {"type":"error",...} as the typed terminal record of a stream interrupted by an error.
//
// An empty result is a stream that contains only the end record. A stream
// without an end record (either an error record or a closed connection) is
// truncated.
//
// Authentication (AuthMiddleware), request ConnInfo (ConnInfoMiddleware),
// parameter validation, and the initial backend find call all happen before
// any response header is written, so their failures are reported as usual
// HTTP errors, exactly as for Find.
func (s *Server) FindStream(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req api.FindManyRequestBody

	if err := decodeJSONRequest(r, &req); err != nil {
		writeError(rw, api.Error{
			Error:     lazyerrors.Error(err).Error(),
			ErrorCode: "InvalidParameter",
		}, http.StatusBadRequest)

		return
	}

	if req.Database == "" || req.Collection == "" {
		writeError(rw, api.Error{
			Error:     "database and collection are required parameters",
			ErrorCode: "MissingParameter",
		}, http.StatusBadRequest)

		return
	}

	msg, err := prepareRequest(
		"find", req.Collection,
		"$db", req.Database,
		"filter", req.Filter,
		"limit", req.Limit,
		"projection", req.Projection,
		"skip", req.Skip,
		"sort", req.Sort,
		// bound the size of the first and every subsequent batch
		"batchSize", streamBatchSize,
	)
	if err != nil {
		http.Error(rw, lazyerrors.Error(err).Error(), http.StatusInternalServerError)
		return
	}

	resp := s.m.Handle(ctx, msg)
	if resp == nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}

	if !resp.OK() {
		s.writeJSONError(ctx, rw, resp)
		return
	}

	cursorID, firstBatch, ok := cursorBatch(resp.Document(), "firstBatch")
	if !ok {
		http.Error(rw, "malformed backend response", http.StatusInternalServerError)
		return
	}

	// All pre-output checks passed; from this point the response is an NDJSON
	// stream and every failure must be reported as a typed trailing error
	// record (or not reported at all if the client is already gone),
	// never as an HTTP status and never followed by a successful end record.
	rw.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("X-Content-Type-Options", "nosniff")

	rw.WriteHeader(http.StatusOK)

	// The stream budget context is derived from the request context,
	// so client cancellation stops backend getMore calls immediately.
	streamCtx, streamCancel := context.WithTimeout(ctx, streamMaxDuration)
	defer streamCancel()

	st := &streamState{
		s:         s,
		req:       &req,
		w:         newNDJSONWriter(rw),
		ctx:       ctx,
		streamCtx: streamCtx,
		cursorID:  cursorID,
	}

	// Kill the cursor if it is still open when the stream ends for any reason,
	// including a failure to flush the headers below.
	// The cleanup uses an independent bounded context that keeps the request
	// values (including the authenticated ConnInfo) but is not canceled when
	// the client disconnects, so killCursors can still reclaim the persistent
	// backend connection.
	defer st.cleanup()

	// Send the status line and headers before any potentially blocking work.
	if err = st.w.flush(); err != nil {
		s.l.DebugContext(ctx, "Failed to flush stream headers", logging.Error(err))
		return
	}

	batch := firstBatch

	for {
		stop, code, reason, m := st.writeBatch(batch)
		if stop {
			if code != "" {
				st.fail(code, reason, m)
			}

			return
		}

		// Cursor exhausted by the backend; it already closed and removed it.
		if st.cursorID == 0 {
			st.end()
			return
		}

		if stop, code, reason, m = st.beforeGetMore(); stop {
			if code != "" {
				st.fail(code, reason, m)
			}

			return
		}

		getMsg, err := prepareRequest(
			"getMore", st.cursorID,
			"collection", st.req.Collection,
			"$db", st.req.Database,
			"batchSize", streamBatchSize,
		)
		if err != nil {
			st.fail(streamErrorInternal, "", lazyerrors.Error(err).Error())
			return
		}

		resp = s.m.Handle(st.streamCtx, getMsg)

		// Request context is checked first: if the client disconnected,
		// nothing can (or should) be written.
		if st.ctx.Err() != nil {
			s.l.DebugContext(ctx, "Stream stopped: client disconnected", logging.Error(st.ctx.Err()))
			return
		}

		// The stream deadline expired while the client is still connected.
		if st.streamCtx.Err() != nil {
			st.fail(streamErrorBudget, streamReasonDuration,
				"stream budget exceeded: maximum duration reached")
			return
		}

		if resp == nil {
			st.fail(streamErrorBackend, "", "backend did not return a getMore response")
			return
		}

		if !resp.OK() {
			codeName := resp.ErrorName()
			if codeName == "" {
				codeName = streamErrorBackend
			}

			errmsg, _ := resp.Document().Get("errmsg").(string)

			st.fail(codeName, "", errmsg)
			return
		}

		var nextID int64

		nextID, batch, ok = cursorBatch(resp.Document(), "nextBatch")
		if !ok {
			st.fail(streamErrorInternal, "", "malformed backend getMore response")
			return
		}

		st.cursorID = nextID
	}
}

// streamState holds the mutable state of a single FindStream invocation.
type streamState struct {
	s   *Server
	req *api.FindManyRequestBody
	w   *ndjsonWriter

	// ctx is the request context, canceled when the client disconnects.
	ctx context.Context

	// streamCtx is the request context with the total stream duration budget.
	streamCtx context.Context

	// cursorID is the currently open backend cursor ID, or zero if it is closed.
	cursorID int64

	docCount     int64
	bytesWritten int64
	emptyBatches int64
}

// writeBatch writes all documents of one batch as document lines and updates
// the consecutive empty-batch counter.
//
// It returns stop=true when the stream must stop. When it stops because
// of an error, code is non-empty and a typed error record should be emitted
// by the caller (unless the client is gone).
func (st *streamState) writeBatch(batch wirebson.AnyArray) (stop bool, code, reason, msg string) {
	docs, err := batch.Decode()
	if err != nil {
		return true, streamErrorInternal, "", lazyerrors.Error(err).Error()
	}

	if docs.Len() == 0 {
		st.emptyBatches++
	} else {
		st.emptyBatches = 0
	}

	for i := range docs.Len() {
		if st.ctx.Err() != nil {
			return true, "", "", ""
		}

		if st.docCount >= streamMaxDocuments {
			return true, streamErrorBudget, streamReasonDocuments,
				"stream budget exceeded: maximum number of documents reached"
		}

		doc, ok := docs.Get(i).(wirebson.AnyDocument)
		if !ok {
			return true, streamErrorInternal, "", "malformed backend document in batch"
		}

		line, err := marshalDocumentLine(doc)
		if err != nil {
			return true, streamErrorInternal, "", lazyerrors.Error(err).Error()
		}

		if st.bytesWritten+int64(len(line)) > streamMaxBytes {
			return true, streamErrorBudget, streamReasonBytes,
				"stream budget exceeded: maximum response size reached"
		}

		if err = st.w.write(line); err != nil {
			// Client disconnected or the write deadline expired.
			st.s.l.DebugContext(st.ctx, "Stream stopped: write failed", logging.Error(err))
			return true, "", "", ""
		}

		st.docCount++
		st.bytesWritten += int64(len(line))
	}

	return false, "", "", ""
}

// beforeGetMore decides whether another getMore should be issued.
func (st *streamState) beforeGetMore() (stop bool, code, reason, msg string) {
	// Client gone: stop silently.
	if st.ctx.Err() != nil {
		return true, "", "", ""
	}

	// An empty batch with an open cursor: a non-tailable cursor is expected
	// to return documents or close; bound the number of such round-trips
	// to detect a misbehaving backend that produces empty batches forever.
	if st.emptyBatches >= streamMaxEmptyBatches {
		return true, streamErrorBudget, streamReasonEmptyBatches,
			"stream budget exceeded: maximum number of consecutive empty batches reached"
	}

	if err := st.streamCtx.Err(); err != nil {
		return true, streamErrorBudget, streamReasonDuration,
			"stream budget exceeded: maximum duration reached"
	}

	return false, "", "", ""
}

// end writes the single successful terminal record.
func (st *streamState) end() {
	line, err := json.Marshal(streamEndLine{Type: streamLineTypeEnd})
	if err != nil {
		// json.Marshal of a static structure cannot realistically fail.
		st.s.l.ErrorContext(st.ctx, "Failed to marshal end line", logging.Error(err))
		return
	}

	line = append(line, '\n')

	if err = st.w.write(line); err != nil {
		st.s.l.DebugContext(st.ctx, "Failed to write end line", logging.Error(err))
	}
}

// fail writes a typed terminal error record, unless the client is gone.
// It never writes an end record.
func (st *streamState) fail(code, reason, msg string) {
	if st.ctx.Err() != nil {
		st.s.l.DebugContext(st.ctx, "Not writing stream error record: client disconnected")
		return
	}

	if msg == "" {
		msg = "stream failed"
	}

	line, err := json.Marshal(streamErrorLine{
		Type:      streamLineTypeError,
		ErrorCode: code,
		Reason:    reason,
		Error:     msg,
	})
	if err != nil {
		st.s.l.ErrorContext(st.ctx, "Failed to marshal error line", logging.Error(err))
		return
	}

	line = append(line, '\n')

	if err = st.w.write(line); err != nil {
		st.s.l.DebugContext(st.ctx, "Failed to write error line", logging.Error(err))
	}
}

// cleanup sends killCursors for the still-open cursor, if any.
//
// It is called at most once per request. The cleanup context is independent
// of the (potentially already canceled) request context but carries its
// values, notably the authenticated ConnInfo, so the cursor is reclaimed
// under the same user identity. Only this request's cursor ID is included,
// so cursors of other requests can never be killed here.
func (st *streamState) cleanup() {
	id := st.cursorID
	if id == 0 {
		return
	}

	// Mark the cursor as cleaned up before the call so it is never sent twice.
	st.cursorID = 0

	ctx, cancel := context.WithTimeout(context.WithoutCancel(st.ctx), streamCleanupTimeout)
	defer cancel()

	msg, err := prepareRequest(
		"killCursors", st.req.Collection,
		"$db", st.req.Database,
		"cursors", wirebson.MustArray(id),
	)
	if err != nil {
		st.s.l.ErrorContext(ctx, "Failed to prepare killCursors", logging.Error(err))
		return
	}

	resp := st.s.m.Handle(ctx, msg)
	if resp == nil {
		st.s.l.WarnContext(ctx, "Backend did not process killCursors", slog.Int64("cursor_id", id))
		return
	}

	if !resp.OK() {
		st.s.l.WarnContext(ctx, "killCursors failed",
			slog.Int64("cursor_id", id), slog.Any("errmsg", resp.Document().Get("errmsg")))
	}
}

// marshalDocumentLine converts one backend document into a complete NDJSON
// document line in canonical Extended JSON form.
func marshalDocumentLine(doc wirebson.AnyDocument) ([]byte, error) {
	raw, err := marshalSingleJSON(doc)
	if err != nil {
		return nil, lazyerrors.Error(err)
	}

	// marshalSingleJSON uses json.Encoder.Encode, which terminates the value
	// with a newline; strip it so it can be embedded into the line envelope.
	raw = bytes.TrimSuffix(raw, []byte{'\n'})

	line, err := json.Marshal(streamDocumentLine{
		Type:     streamLineTypeDocument,
		Document: raw,
	})
	if err != nil {
		return nil, lazyerrors.Error(err)
	}

	return append(line, '\n'), nil
}

// cursorBatch extracts the cursor ID and the named batch (firstBatch or
// nextBatch) from a find/getMore response document.
func cursorBatch(doc *wirebson.Document, batchField string) (int64, wirebson.AnyArray, bool) {
	cursorV, ok := doc.Get("cursor").(wirebson.AnyDocument)
	if !ok {
		return 0, nil, false
	}

	cursor, err := cursorV.Decode()
	if err != nil {
		return 0, nil, false
	}

	id, ok := cursor.Get("id").(int64)
	if !ok {
		return 0, nil, false
	}

	batch, ok := cursor.Get(batchField).(wirebson.AnyArray)
	if !ok {
		return 0, nil, false
	}

	return id, batch, true
}
