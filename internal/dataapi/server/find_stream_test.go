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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/FerretDB/wire/wirebson"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/FerretDB/FerretDB/v2/internal/clientconn/conninfo"
	"github.com/FerretDB/FerretDB/v2/internal/handler/middleware"
	"github.com/FerretDB/FerretDB/v2/internal/util/testutil"
)

// fakeStep describes one scripted getMore response of a fake cursor.
type fakeStep struct {
	docs  []*wirebson.Document
	id    int64
	fail  bool // respond with a backend error
	block bool // block until the request context is canceled
}

// fakeCursor is a scripted backend cursor.
type fakeCursor struct {
	id    int64
	first []*wirebson.Document
	steps []fakeStep
	calls int
}

// killRecord stores what the backend saw in a killCursors command.
type killRecord struct {
	ids    []int64
	ci     *conninfo.ConnInfo
	ctxErr error
}

// fakeBackend is a real middleware.Handler with fully scripted,
// controllable find/getMore/killCursors behavior.
type fakeBackend struct {
	t *testing.T

	mu sync.Mutex

	// pending cursors are returned by subsequent find calls in FIFO order.
	pending []*fakeCursor

	// open cursors by ID; stands in for the DocumentDB cursor registry.
	cursors map[int64]*fakeCursor

	findCalls    int
	getMoreCalls int
	killCalls    int
	findError    bool
	findCIs      map[int64]*conninfo.ConnInfo
	getMoreCIs   []*conninfo.ConnInfo
	getMoreIDs   []int64
	getMoreSizes []int32
	kills        []killRecord

	// killed is signaled (non-blocking) after every killCursors command.
	killed chan killRecord
}

func newFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()

	return &fakeBackend{
		t:       t,
		cursors: map[int64]*fakeCursor{},
		findCIs: map[int64]*conninfo.ConnInfo{},
		killed:  make(chan killRecord, 32),
	}
}

func (b *fakeBackend) enqueue(c *fakeCursor) {
	b.mu.Lock()
	b.pending = append(b.pending, c)
	b.mu.Unlock()
}

// Run implements [middleware.Handler].
func (b *fakeBackend) Run(ctx context.Context) {
	<-ctx.Done()
}

// Describe implements [prometheus.Collector].
func (b *fakeBackend) Describe(chan<- *prometheus.Desc) {}

// Collect implements [prometheus.Collector].
func (b *fakeBackend) Collect(chan<- prometheus.Metric) {}

// Handle implements [middleware.Handler].
func (b *fakeBackend) Handle(ctx context.Context, req *middleware.Request) (*middleware.Response, error) {
	doc := req.Document()

	switch doc.Command() {
	case "find":
		return b.handleFind(ctx, req)
	case "getMore":
		return b.handleGetMore(ctx, req)
	case "killCursors":
		return b.handleKillCursors(ctx, req)
	default:
		return middleware.ResponseDoc(req, wirebson.MustDocument(
			"ok", float64(0),
			"errmsg", "unexpected command "+doc.Command(),
			"code", int32(1),
			"codeName", "BadValue",
		))
	}
}

func (b *fakeBackend) handleFind(ctx context.Context, req *middleware.Request) (*middleware.Response, error) {
	b.mu.Lock()

	b.findCalls++

	if b.findError {
		b.mu.Unlock()

		return middleware.ResponseDoc(req, wirebson.MustDocument(
			"ok", float64(0),
			"errmsg", "find boom",
			"code", int32(1),
			"codeName", "InternalError",
		))
	}

	require.NotEmpty(b.t, b.pending, "unexpected find: no scripted cursor")

	c := b.pending[0]
	b.pending = b.pending[1:]

	b.findCIs[c.id] = conninfo.Get(ctx)

	if c.id != 0 {
		b.cursors[c.id] = c
	}

	b.mu.Unlock()

	return middleware.ResponseDoc(req, wirebson.MustDocument(
		"cursor", wirebson.MustDocument(
			"id", c.id,
			"ns", "testdb.testcoll",
			"firstBatch", docsArray(c.first),
		),
		"ok", float64(1),
	))
}

func (b *fakeBackend) handleGetMore(ctx context.Context, req *middleware.Request) (*middleware.Response, error) {
	doc := req.Document()

	id, ok := doc.Get("getMore").(int64)
	require.True(b.t, ok, "getMore id has wrong type %T", doc.Get("getMore"))

	batchSize, _ := doc.Get("batchSize").(int32)

	b.mu.Lock()

	b.getMoreCalls++
	b.getMoreIDs = append(b.getMoreIDs, id)
	b.getMoreSizes = append(b.getMoreSizes, batchSize)
	b.getMoreCIs = append(b.getMoreCIs, conninfo.Get(ctx))

	c := b.cursors[id]
	if c == nil {
		b.mu.Unlock()

		return middleware.ResponseDoc(req, wirebson.MustDocument(
			"ok", float64(0),
			"errmsg", "cursor not found",
			"code", int32(43),
			"codeName", "CursorNotFound",
		))
	}

	n := c.calls
	c.calls++

	var step fakeStep
	if n < len(c.steps) {
		step = c.steps[n]
	} else {
		// Past the scripted steps the cursor stays open and returns empty batches,
		// emulating a misbehaving backend.
		step = fakeStep{id: c.id}
	}

	b.mu.Unlock()

	if step.block {
		<-ctx.Done()

		// The real handler converts backend errors into a mongo error response,
		// it never returns (nil, error) past the middleware.
		return middleware.ResponseDoc(req, wirebson.MustDocument(
			"ok", float64(0),
			"errmsg", ctx.Err().Error(),
			"code", int32(1),
			"codeName", "Interrupted",
		))
	}

	if step.fail {
		return middleware.ResponseDoc(req, wirebson.MustDocument(
			"ok", float64(0),
			"errmsg", "boom",
			"code", int32(1),
			"codeName", "InternalError",
		))
	}

	b.mu.Lock()
	if step.id == 0 {
		delete(b.cursors, id)
	}
	b.mu.Unlock()

	return middleware.ResponseDoc(req, wirebson.MustDocument(
		"cursor", wirebson.MustDocument(
			"id", step.id,
			"ns", "testdb.testcoll",
			"nextBatch", docsArray(step.docs),
		),
		"ok", float64(1),
	))
}

func (b *fakeBackend) handleKillCursors(ctx context.Context, req *middleware.Request) (*middleware.Response, error) {
	doc := req.Document()

	arrV, ok := doc.Get("cursors").(wirebson.AnyArray)
	require.True(b.t, ok)

	arr, err := arrV.Decode()
	require.NoError(b.t, err)

	ids := make([]int64, arr.Len())

	for i := range arr.Len() {
		ids[i] = arr.Get(i).(int64)
	}

	b.mu.Lock()

	killed := make([]int64, 0, len(ids))
	notFound := make([]int64, 0, len(ids))

	for _, id := range ids {
		if _, ok := b.cursors[id]; ok {
			delete(b.cursors, id)
			killed = append(killed, id)
		} else {
			notFound = append(notFound, id)
		}
	}

	ci := conninfo.Get(ctx)
	rec := killRecord{
		ids:    append([]int64(nil), ids...),
		ci:     ci,
		ctxErr: ctx.Err(),
	}

	b.killCalls++
	b.kills = append(b.kills, rec)

	b.mu.Unlock()

	select {
	case b.killed <- rec:
	default:
	}

	return middleware.ResponseDoc(req, wirebson.MustDocument(
		"cursorsKilled", int64Array(killed),
		"cursorsNotFound", int64Array(notFound),
		"cursorsAlive", wirebson.MustArray(),
		"cursorsUnknown", wirebson.MustArray(),
		"ok", float64(1),
	))
}

// snapshot returns the backend counters under lock.
func (b *fakeBackend) snapshot() (find, getMore, kill int, open int, kills []killRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()

	kills = append([]killRecord(nil), b.kills...)

	return b.findCalls, b.getMoreCalls, b.killCalls, len(b.cursors), kills
}

// findCIByID returns the ConnInfo of the find that created the given cursor.
func (b *fakeBackend) findCIByID(id int64) *conninfo.ConnInfo {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.findCIs[id]
}

// getMoreInfo returns aligned copies of getMore cursor IDs, batch sizes
// and ConnInfos.
func (b *fakeBackend) getMoreInfo() (ids []int64, sizes []int32, cis []*conninfo.ConnInfo) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]int64(nil), b.getMoreIDs...),
		append([]int32(nil), b.getMoreSizes...),
		append([]*conninfo.ConnInfo(nil), b.getMoreCIs...)
}

func docsArray(docs []*wirebson.Document) *wirebson.Array {
	values := make([]any, len(docs))

	for i, doc := range docs {
		values[i] = doc
	}

	return wirebson.MustArray(values...)
}

func int64Array(ids []int64) *wirebson.Array {
	values := make([]any, len(ids))

	for i, id := range ids {
		values[i] = id
	}

	return wirebson.MustArray(values...)
}

func makeDoc(id int32) *wirebson.Document {
	return wirebson.MustDocument("_id", id)
}

const streamTestBody = `{"database":"testdb","collection":"testcoll","filter":{}}`

// streamLine is a parsed NDJSON response line.
type streamLine struct {
	Type      string          `json:"type"`
	Document  json.RawMessage `json:"document"`
	ErrorCode string          `json:"error_code"`
	Reason    string          `json:"reason"`
	Error     string          `json:"error"`
}

func newStreamTestServer(t *testing.T, b *fakeBackend) (*Server, *httptest.Server) {
	t.Helper()

	l := testutil.Logger(t)

	m := middleware.New(&middleware.NewOpts{
		Mode:    middleware.NormalMode,
		DocDB:   b,
		Metrics: middleware.NewMetrics(),
		L:       l,
	})

	s := New(l, m)

	h := s.ConnInfoMiddleware(http.HandlerFunc(s.FindStream))

	return s, httptest.NewServer(h)
}

func openStream(t *testing.T, ctx context.Context, ts *httptest.Server, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/action/findStream", strings.NewReader(body))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	res, err := ts.Client().Do(req)
	require.NoError(t, err)

	return res
}

// readLines reads all complete NDJSON lines until EOF.
func readLines(t *testing.T, r io.Reader) []streamLine {
	t.Helper()

	var lines []streamLine

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	for scanner.Scan() {
		var l streamLine
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &l), "line %q", scanner.Text())

		lines = append(lines, l)
	}

	require.NoError(t, scanner.Err())

	return lines
}

func docID(t *testing.T, raw json.RawMessage) int32 {
	t.Helper()

	var doc struct {
		ID int32 `json:"_id"`
	}

	require.NoError(t, json.Unmarshal(raw, &doc))

	return doc.ID
}

func lineIDs(t *testing.T, lines []streamLine) []int32 {
	t.Helper()

	var ids []int32

	for _, l := range lines {
		require.Equal(t, streamLineTypeDocument, l.Type)
		ids = append(ids, docID(t, l.Document))
	}

	return ids
}

func waitKill(t *testing.T, b *fakeBackend) killRecord {
	t.Helper()

	select {
	case rec := <-b.killed:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for killCursors")
		return killRecord{}
	}
}

func TestFindStreamMultiBatch(t *testing.T) {
	b := newFakeBackend(t)

	doc3 := wirebson.MustDocument("_id", int32(3), "big", int64(9007199254740993))

	b.enqueue(&fakeCursor{
		id:    42,
		first: []*wirebson.Document{makeDoc(1), makeDoc(2)},
		steps: []fakeStep{
			{docs: []*wirebson.Document{doc3}, id: 42},
			{docs: []*wirebson.Document{makeDoc(4), makeDoc(5)}, id: 0},
		},
	})

	_, ts := newStreamTestServer(t, b)
	defer ts.Close()

	res := openStream(t, context.Background(), ts, streamTestBody)
	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.True(t, strings.HasPrefix(res.Header.Get("Content-Type"), "application/x-ndjson"))
	assert.Empty(t, res.Header.Get("Content-Length"), "streamed response must not have a content length")

	lines := readLines(t, res.Body)

	require.Len(t, lines, 6)
	assert.Equal(t, []int32{1, 2, 3, 4, 5}, lineIDs(t, lines[:5]))
	assert.Equal(t, streamLineTypeEnd, lines[5].Type)

	// Documents are encoded with the same canonical JSON encoder as Find:
	// int64 values survive losslessly even outside float safe range.
	assert.Contains(t, string(lines[2].Document), `"big":9007199254740993`)

	findN, getMoreN, killN, openCursors, _ := b.snapshot()
	assert.Equal(t, 1, findN)
	assert.Equal(t, 2, getMoreN)
	assert.Equal(t, 0, killN, "naturally exhausted cursor must not be killed")
	assert.Zero(t, openCursors, "backend cursor resources must be zero")

	ids, sizes, cis := b.getMoreInfo()
	assert.Equal(t, []int64{42, 42}, ids)
	assert.Equal(t, []int32{streamBatchSize, streamBatchSize}, sizes)

	// Every getMore uses the same authenticated ConnInfo as the find.
	findCI := b.findCIByID(42)
	for _, ci := range cis {
		assert.Same(t, findCI, ci)
	}
}

func TestFindStreamEmptyCollection(t *testing.T) {
	b := newFakeBackend(t)
	b.enqueue(&fakeCursor{id: 0})

	_, ts := newStreamTestServer(t, b)
	defer ts.Close()

	res := openStream(t, context.Background(), ts, streamTestBody)
	defer res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)

	lines := readLines(t, res.Body)
	require.Len(t, lines, 1)
	assert.Equal(t, streamLineTypeEnd, lines[0].Type)

	findN, getMoreN, killN, openCursors, _ := b.snapshot()
	assert.Equal(t, 1, findN)
	assert.Equal(t, 0, getMoreN)
	assert.Equal(t, 0, killN)
	assert.Zero(t, openCursors)
}

func TestFindStreamEmptyBatchesContinue(t *testing.T) {
	b := newFakeBackend(t)
	b.enqueue(&fakeCursor{
		id:    42,
		first: []*wirebson.Document{makeDoc(1)},
		steps: []fakeStep{
			{docs: nil, id: 42},
			{docs: []*wirebson.Document{makeDoc(2)}, id: 42},
			{docs: nil, id: 42},
			{docs: []*wirebson.Document{makeDoc(3)}, id: 0},
		},
	})

	_, ts := newStreamTestServer(t, b)
	defer ts.Close()

	res := openStream(t, context.Background(), ts, streamTestBody)
	defer res.Body.Close()

	lines := readLines(t, res.Body)

	require.Len(t, lines, 4)
	assert.Equal(t, []int32{1, 2, 3}, lineIDs(t, lines[:3]))
	assert.Equal(t, streamLineTypeEnd, lines[3].Type)

	findN, getMoreN, _, openCursors, _ := b.snapshot()
	assert.Equal(t, 1, findN)
	assert.Equal(t, 4, getMoreN, "empty open batches must be consumed")
	assert.Zero(t, openCursors)
}

func TestFindStreamEmptyBatchBudget(t *testing.T) {
	old := streamMaxEmptyBatches
	streamMaxEmptyBatches = 2

	t.Cleanup(func() {
		streamMaxEmptyBatches = old
	})

	b := newFakeBackend(t)
	b.enqueue(&fakeCursor{
		id:    42,
		first: []*wirebson.Document{makeDoc(1)},
		// no steps: every getMore returns an empty batch with the cursor open
	})

	_, ts := newStreamTestServer(t, b)
	defer ts.Close()

	res := openStream(t, context.Background(), ts, streamTestBody)
	defer res.Body.Close()

	lines := readLines(t, res.Body)

	require.Len(t, lines, 2)
	assert.Equal(t, int32(1), docID(t, lines[0].Document))
	assert.Equal(t, streamLineTypeError, lines[1].Type)
	assert.Equal(t, streamErrorBudget, lines[1].ErrorCode)
	assert.Equal(t, streamReasonEmptyBatches, lines[1].Reason)

	_, getMoreN, killN, openCursors, kills := b.snapshot()
	assert.Equal(t, 2, getMoreN, "stream must stop after the empty-batch budget")
	assert.Equal(t, 1, killN)
	assert.Zero(t, openCursors, "cursor must be reclaimed through killCursors")
	require.Len(t, kills, 1)
	assert.Equal(t, []int64{42}, kills[0].ids)
	assert.NoError(t, kills[0].ctxErr, "cleanup context must not be canceled")
	assert.Same(t, b.findCIByID(42), kills[0].ci)
}

func TestFindStreamBackendError(t *testing.T) {
	b := newFakeBackend(t)
	b.enqueue(&fakeCursor{
		id:    42,
		first: []*wirebson.Document{makeDoc(1)},
		steps: []fakeStep{
			{docs: []*wirebson.Document{makeDoc(2)}, id: 42},
			{fail: true},
		},
	})

	_, ts := newStreamTestServer(t, b)
	defer ts.Close()

	res := openStream(t, context.Background(), ts, streamTestBody)
	defer res.Body.Close()

	lines := readLines(t, res.Body)

	require.Len(t, lines, 3)
	assert.Equal(t, []int32{1, 2}, lineIDs(t, lines[:2]))
	assert.Equal(t, streamLineTypeError, lines[2].Type)
	assert.Equal(t, "InternalError", lines[2].ErrorCode)
	assert.Contains(t, lines[2].Error, "boom")

	_, _, killN, openCursors, kills := b.snapshot()
	assert.Equal(t, 1, killN)
	assert.Zero(t, openCursors)
	require.Len(t, kills, 1)
	assert.Equal(t, []int64{42}, kills[0].ids)
	assert.Same(t, b.findCIByID(42), kills[0].ci)
}

func TestFindStreamDocumentBudget(t *testing.T) {
	old := streamMaxDocuments
	streamMaxDocuments = 2

	t.Cleanup(func() {
		streamMaxDocuments = old
	})

	b := newFakeBackend(t)
	b.enqueue(&fakeCursor{
		id:    42,
		first: []*wirebson.Document{makeDoc(1)},
		steps: []fakeStep{
			{docs: []*wirebson.Document{makeDoc(2), makeDoc(3)}, id: 42},
			{docs: []*wirebson.Document{makeDoc(4)}, id: 0},
		},
	})

	_, ts := newStreamTestServer(t, b)
	defer ts.Close()

	res := openStream(t, context.Background(), ts, streamTestBody)
	defer res.Body.Close()

	lines := readLines(t, res.Body)

	require.Len(t, lines, 3)
	assert.Equal(t, []int32{1, 2}, lineIDs(t, lines[:2]))
	assert.Equal(t, streamLineTypeError, lines[2].Type)
	assert.Equal(t, streamErrorBudget, lines[2].ErrorCode)
	assert.Equal(t, streamReasonDocuments, lines[2].Reason)

	_, _, killN, openCursors, _ := b.snapshot()
	assert.Equal(t, 1, killN)
	assert.Zero(t, openCursors)
}

func TestFindStreamByteBudget(t *testing.T) {
	firstLine, err := marshalDocumentLine(makeDoc(1))
	require.NoError(t, err)

	old := streamMaxBytes
	streamMaxBytes = int64(len(firstLine))

	t.Cleanup(func() {
		streamMaxBytes = old
	})

	b := newFakeBackend(t)
	b.enqueue(&fakeCursor{
		id:    42,
		first: []*wirebson.Document{makeDoc(1)},
		steps: []fakeStep{
			{docs: []*wirebson.Document{makeDoc(2)}, id: 42},
		},
	})

	_, ts := newStreamTestServer(t, b)
	defer ts.Close()

	res := openStream(t, context.Background(), ts, streamTestBody)
	defer res.Body.Close()

	lines := readLines(t, res.Body)

	require.Len(t, lines, 2)
	assert.Equal(t, int32(1), docID(t, lines[0].Document))
	assert.Equal(t, streamLineTypeError, lines[1].Type)
	assert.Equal(t, streamReasonBytes, lines[1].Reason)

	_, _, killN, openCursors, _ := b.snapshot()
	assert.Equal(t, 1, killN)
	assert.Zero(t, openCursors)
}

func TestFindStreamDurationBudget(t *testing.T) {
	old := streamMaxDuration
	streamMaxDuration = 100 * time.Millisecond

	t.Cleanup(func() {
		streamMaxDuration = old
	})

	b := newFakeBackend(t)
	b.enqueue(&fakeCursor{
		id:    42,
		first: []*wirebson.Document{makeDoc(1)},
		steps: []fakeStep{
			{block: true}, // unblocks only when the stream context expires
		},
	})

	_, ts := newStreamTestServer(t, b)
	defer ts.Close()

	res := openStream(t, context.Background(), ts, streamTestBody)
	defer res.Body.Close()

	lines := readLines(t, res.Body)

	require.Len(t, lines, 2)
	assert.Equal(t, int32(1), docID(t, lines[0].Document))
	assert.Equal(t, streamLineTypeError, lines[1].Type)
	assert.Equal(t, streamReasonDuration, lines[1].Reason)

	rec := waitKill(t, b)
	assert.Equal(t, []int64{42}, rec.ids)
	assert.NoError(t, rec.ctxErr)
}

func TestFindStreamClientCancellation(t *testing.T) {
	b := newFakeBackend(t)
	b.enqueue(&fakeCursor{
		id:    42,
		first: []*wirebson.Document{makeDoc(1)},
		steps: []fakeStep{
			{block: true}, // getMore in flight when the client goes away
		},
	})

	_, ts := newStreamTestServer(t, b)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	res := openStream(t, ctx, ts, streamTestBody)
	defer res.Body.Close()

	scanner := bufio.NewScanner(res.Body)
	require.True(t, scanner.Scan(), "first document line must arrive")

	var first streamLine
	require.NoError(t, json.Unmarshal(scanner.Bytes(), &first))
	assert.Equal(t, streamLineTypeDocument, first.Type)
	assert.Equal(t, int32(1), docID(t, first.Document))

	// Client disconnects while getMore is in flight.
	cancel()

	// The server must immediately stop issuing getMore calls and reclaim
	// the cursor through killCursors using an independent, non-canceled
	// context that keeps the same authenticated ConnInfo.
	rec := waitKill(t, b)
	assert.Equal(t, []int64{42}, rec.ids)
	assert.NoError(t, rec.ctxErr, "cleanup must not reuse the canceled request context")
	assert.Same(t, b.findCIByID(42), rec.ci, "cleanup must keep the same authenticated ConnInfo")

	_, getMoreN, killN, openCursors, _ := b.snapshot()
	assert.Equal(t, 1, getMoreN, "no further getMore after cancellation")
	assert.Equal(t, 1, killN)
	assert.Zero(t, openCursors, "persistent backend connection must be reclaimed")

	_, _, cis := b.getMoreInfo()
	for _, ci := range cis {
		assert.Same(t, b.findCIByID(42), ci)
	}
}

// failingWriter is an http.ResponseWriter whose Write fails starting at
// failAt-th write, emulating a short write / closed connection.
type failingWriter struct {
	header     http.Header
	status     int
	writes     [][]byte
	failAt     int
	flushCount int
}

func (w *failingWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}

	return w.header
}

func (w *failingWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}

func (w *failingWriter) Write(p []byte) (int, error) {
	n := len(w.writes)

	if n >= w.failAt {
		return 0, errors.New("short write")
	}

	cp := append([]byte(nil), p...)
	w.writes = append(w.writes, cp)

	return len(p), nil
}

func (w *failingWriter) Flush() {
	w.flushCount++
}

func TestFindStreamShortWrite(t *testing.T) {
	b := newFakeBackend(t)
	b.enqueue(&fakeCursor{
		id:    42,
		first: []*wirebson.Document{makeDoc(1)},
		steps: []fakeStep{
			{docs: []*wirebson.Document{makeDoc(2)}, id: 42},
		},
	})

	s, _ := newStreamTestServer(t, b)

	req := httptest.NewRequest(http.MethodPost, "/action/findStream", strings.NewReader(streamTestBody))
	req.Header.Set("Content-Type", "application/json")

	fw := &failingWriter{failAt: 1}

	s.ConnInfoMiddleware(http.HandlerFunc(s.FindStream)).ServeHTTP(fw, req)

	assert.Equal(t, http.StatusOK, fw.status)
	require.Len(t, fw.writes, 1, "only the first document line could be written")
	assert.Contains(t, string(fw.writes[0]), `"type":"document"`)
	assert.NotContains(t, string(fw.writes[0]), streamLineTypeEnd)

	_, getMoreN, killN, openCursors, kills := b.snapshot()
	assert.Equal(t, 1, getMoreN)
	assert.Equal(t, 1, killN, "cursor must still be reclaimed after a failed write")
	assert.Zero(t, openCursors)
	require.Len(t, kills, 1)
	assert.Equal(t, []int64{42}, kills[0].ids)
	assert.NoError(t, kills[0].ctxErr)
}

// failingFlushWriter fails the very first flush, emulating a broken
// connection before the headers reach the client.
type failingFlushWriter struct {
	header http.Header
	status int
}

func (w *failingFlushWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}

	return w.header
}

func (w *failingFlushWriter) WriteHeader(statusCode int) {
	w.status = statusCode
}

func (w *failingFlushWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

// FlushError returns an error; [http.ResponseController] recognizes it.
func (w *failingFlushWriter) FlushError() error {
	return errors.New("flush failed")
}

func TestFindStreamHeaderFlushFailureReclaimsCursor(t *testing.T) {
	b := newFakeBackend(t)
	b.enqueue(&fakeCursor{
		id:    42,
		first: nil, // open cursor with an empty first batch
		steps: []fakeStep{
			{docs: []*wirebson.Document{makeDoc(1)}, id: 0},
		},
	})

	s, _ := newStreamTestServer(t, b)

	req := httptest.NewRequest(http.MethodPost, "/action/findStream", strings.NewReader(streamTestBody))
	req.Header.Set("Content-Type", "application/json")

	fw := &failingFlushWriter{}

	s.ConnInfoMiddleware(http.HandlerFunc(s.FindStream)).ServeHTTP(fw, req)

	assert.Equal(t, http.StatusOK, fw.status)

	rec := waitKill(t, b)
	assert.Equal(t, []int64{42}, rec.ids)
	assert.NoError(t, rec.ctxErr)

	_, _, _, openCursors, _ := b.snapshot()
	assert.Zero(t, openCursors, "cursor must be reclaimed even if header flush failed")
}

func TestFindStreamPreHeaderErrors(t *testing.T) {
	t.Run("InvalidJSON", func(t *testing.T) {
		b := newFakeBackend(t)
		_, ts := newStreamTestServer(t, b)
		defer ts.Close()

		req, err := http.NewRequest(http.MethodPost, ts.URL+"/action/findStream", strings.NewReader("{not json"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		res, err := ts.Client().Do(req)
		require.NoError(t, err)
		defer res.Body.Close()

		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.True(t, strings.HasPrefix(res.Header.Get("Content-Type"), "application/json"))

		var apiErr struct {
			Error     string `json:"error"`
			ErrorCode string `json:"error_code"`
		}

		require.NoError(t, json.NewDecoder(res.Body).Decode(&apiErr))
		assert.Equal(t, "InvalidParameter", apiErr.ErrorCode)
		assert.NotEmpty(t, apiErr.Error)

		findN, _, _, _, _ := b.snapshot()
		assert.Zero(t, findN, "backend must not be called for invalid parameters")
	})

	t.Run("MissingParameters", func(t *testing.T) {
		b := newFakeBackend(t)
		_, ts := newStreamTestServer(t, b)
		defer ts.Close()

		res := openStream(t, context.Background(), ts, `{"database":"","collection":""}`)
		defer res.Body.Close()

		assert.Equal(t, http.StatusBadRequest, res.StatusCode)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "MissingParameter")

		findN, _, _, _, _ := b.snapshot()
		assert.Zero(t, findN)
	})

	t.Run("BackendFindError", func(t *testing.T) {
		b := newFakeBackend(t)
		b.findError = true
		_, ts := newStreamTestServer(t, b)
		defer ts.Close()

		res := openStream(t, context.Background(), ts, streamTestBody)
		defer res.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		assert.True(t, strings.HasPrefix(res.Header.Get("Content-Type"), "application/json"))
		assert.NotContains(t, res.Header.Get("Content-Type"), "x-ndjson")

		body, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "find boom")
	})
}

func TestFindStreamCursorIsolation(t *testing.T) {
	b := newFakeBackend(t)

	// Cursor A is exhausted normally across several concurrent requests' batches.
	b.enqueue(&fakeCursor{
		id:    101,
		first: []*wirebson.Document{makeDoc(1)},
		steps: []fakeStep{
			{docs: []*wirebson.Document{makeDoc(2)}, id: 101},
			{docs: []*wirebson.Document{makeDoc(3)}, id: 0},
		},
	})

	// Cursor B fails mid-stream and must be killed.
	b.enqueue(&fakeCursor{
		id:    202,
		first: []*wirebson.Document{makeDoc(10)},
		steps: []fakeStep{
			{fail: true},
		},
	})

	_, ts := newStreamTestServer(t, b)
	defer ts.Close()

	var wg sync.WaitGroup

	results := make([][]streamLine, 2)

	stream := func(i int) {
		defer wg.Done()

		res := openStream(t, context.Background(), ts, streamTestBody)
		defer res.Body.Close()

		results[i] = readLines(t, res.Body)
	}

	wg.Add(2)
	go stream(0)
	go stream(1)
	wg.Wait()

	// Classify responses by their content because find assignment order
	// between concurrent requests is not deterministic.
	var linesA, linesB []streamLine

	for _, lines := range results {
		require.NotEmpty(t, lines)

		if docID(t, lines[0].Document) == 10 {
			linesB = lines
		} else {
			linesA = lines
		}
	}

	require.NotNil(t, linesA)
	require.NotNil(t, linesB)

	assert.Equal(t, []int32{1, 2, 3}, lineIDs(t, linesA[:len(linesA)-1]))
	require.Equal(t, streamLineTypeEnd, linesA[len(linesA)-1].Type)

	assert.Equal(t, []int32{10}, lineIDs(t, linesB[:len(linesB)-1]))
	require.Equal(t, streamLineTypeError, linesB[len(linesB)-1].Type)

	findN, getMoreN, killN, openCursors, kills := b.snapshot()
	assert.Equal(t, 2, findN)
	assert.Equal(t, 3, getMoreN)
	assert.Equal(t, 1, killN, "only the failed cursor must be killed")
	assert.Zero(t, openCursors)

	require.Len(t, kills, 1)
	assert.Equal(t, []int64{202}, kills[0].ids, "cleanup must not kill another request's cursor")

	// Both HTTP requests have distinct ConnInfos; getMore calls for each
	// cursor keep the ConnInfo of its own find, and cleanup uses B's.
	ciA := b.findCIByID(101)
	ciB := b.findCIByID(202)
	assert.NotSame(t, ciA, ciB, "each request must have its own ConnInfo")
	assert.Same(t, ciB, kills[0].ci)

	getMoreIDs, _, getMoreCIs := b.getMoreInfo()
	require.Len(t, getMoreIDs, 3)

	for i, id := range getMoreIDs {
		switch id {
		case 101:
			assert.Same(t, ciA, getMoreCIs[i], "getMore for cursor A must keep A's ConnInfo")
		case 202:
			assert.Same(t, ciB, getMoreCIs[i], "getMore for cursor B must keep B's ConnInfo")
		default:
			t.Fatalf("unexpected cursor id %d", id)
		}
	}
}
