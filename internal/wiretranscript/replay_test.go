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
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/FerretDB/wire"
	"github.com/FerretDB/wire/wirebson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/FerretDB/FerretDB/v2/internal/handler/middleware"
	"github.com/FerretDB/FerretDB/v2/internal/util/must"
	"github.com/FerretDB/FerretDB/v2/internal/util/testutil"
)

// fakeTransport counts real handler invocations and scripted responses.
type fakeTransport struct {
	mu      sync.Mutex
	calls   int
	seenIDs []int32
	fn      func(req *middleware.Request) (*middleware.Response, error)
}

func (f *fakeTransport) handle() Transport {
	return func(ctx context.Context, req *middleware.Request) (*middleware.Response, error) {
		f.mu.Lock()
		f.calls++
		f.seenIDs = append(f.seenIDs, req.WireHeader().RequestID)
		f.mu.Unlock()

		return f.fn(req)
	}
}

// respond builds a successful OP_MSG response through the real middleware constructor.
func respond(req *middleware.Request, pairs ...any) *middleware.Response {
	return must.NotFail(middleware.ResponseDoc(req, wirebson.MustDocument(pairs...)))
}

// respondDoc builds a response from the given document through the real middleware constructor.
func respondDoc(req *middleware.Request, doc *wirebson.Document) *middleware.Response {
	return must.NotFail(middleware.ResponseDoc(req, doc))
}

// cursorDoc builds a cursor-bearing response document.
func cursorDoc(id int64, batchField string) *wirebson.Document {
	return wirebson.MustDocument(
		"cursor", wirebson.MustDocument(
			"id", id,
			"ns", "db.coll",
			batchField, wirebson.MustArray(),
		),
		"ok", float64(1),
	)
}

// statuses collects replay result statuses by frame sequence.
func statuses(report *Report) map[uint64]Status {
	res := make(map[uint64]Status, len(report.Results))
	for _, r := range report.Results {
		res[r.Seq] = r.Status
	}

	return res
}

func TestReplayMatchedWithCursorMapping(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, &RecorderOpts{Logger: testutil.Logger(t)})

	recordPair(t, r, 10,
		wire.MustOpMsg("find", "coll", "$db", "db"),
		must.NotFail(wire.NewOpMsg(cursorDoc(100, "firstBatch"))),
	)
	recordPair(t, r, 20,
		wire.MustOpMsg("getMore", int64(100), "collection", "coll", "$db", "db"),
		must.NotFail(wire.NewOpMsg(cursorDoc(100, "nextBatch"))),
	)
	recordPair(t, r, 30,
		wire.MustOpMsg(
			"killCursors", "coll",
			"cursors", wirebson.MustArray(int64(100)),
			"$db", "db",
		),
		wire.MustOpMsg("ok", float64(1)),
	)

	tr := finalize(t, r, EndReasonClientClosed)

	ft := &fakeTransport{}
	ft.fn = func(req *middleware.Request) (*middleware.Response, error) {
		doc := req.Document()

		switch doc.Command() {
		case "find":
			return respondDoc(req, cursorDoc(200, "firstBatch")), nil

		case "getMore":
			// The recorded handle 100 must be remapped to the real handle 200.
			require.Equal(t, int64(200), doc.Get("getMore"))
			return respondDoc(req, cursorDoc(200, "nextBatch")), nil

		case "killCursors":
			deep, err := req.DocumentDeep()
			require.NoError(t, err)

			arr := deep.Get("cursors").(*wirebson.Array)
			var values []any
			for _, v := range arr.All() {
				values = append(values, v)
			}

			require.Equal(t, []any{int64(200)}, values)
			return respond(req, "ok", float64(1)), nil

		default:
			t.Fatalf("unexpected command %s", doc.Command())
			return nil, nil
		}
	}

	report, err := Replay(context.Background(), tr, &ReplayOpts{Transport: ft.handle()})
	require.NoError(t, err)

	assert.Equal(t, 3, ft.calls, "every replayed request must reach the handler once")
	assert.Equal(t, []int32{1, 2, 3}, ft.seenIDs, "request identifiers must be remapped sequentially")

	for seq, status := range statuses(report) {
		assert.Equal(t, StatusMatched, status, "frame %d", seq)
	}
}

func TestReplayUnmappedCursorIsError(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)

	recordPair(t, r, 20,
		wire.MustOpMsg("getMore", int64(999), "collection", "coll", "$db", "db"),
		must.NotFail(wire.NewOpMsg(cursorDoc(999, "nextBatch"))),
	)

	tr := finalize(t, r, EndReasonClientClosed)

	ft := &fakeTransport{}
	ft.fn = func(req *middleware.Request) (*middleware.Response, error) {
		t.Fatal("handler must not be called for an unmapped handle")
		return nil, nil
	}

	report, err := Replay(context.Background(), tr, &ReplayOpts{Transport: ft.handle()})
	require.ErrorIs(t, err, ErrUnmappedHandle)
	assert.Equal(t, 0, ft.calls)
	assert.Equal(t, StatusUnmappedHandle, statuses(report)[0])
}

func TestReplayDoesNotBlanketReplaceIntegers(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)

	// batchSize happens to have the same numeric value as the cursor handle,
	// but it is not a handle field and must remain untouched.
	recordPair(t, r, 10,
		wire.MustOpMsg("find", "coll", "batchSize", int64(100), "$db", "db"),
		must.NotFail(wire.NewOpMsg(cursorDoc(100, "firstBatch"))),
	)
	recordPair(t, r, 20,
		wire.MustOpMsg(
			"getMore", int64(100),
			"collection", "coll",
			"batchSize", int64(100),
			"$db", "db",
		),
		must.NotFail(wire.NewOpMsg(cursorDoc(100, "nextBatch"))),
	)

	tr := finalize(t, r, EndReasonClientClosed)

	ft := &fakeTransport{}
	ft.fn = func(req *middleware.Request) (*middleware.Response, error) {
		switch req.Document().Command() {
		case "find":
			require.Equal(t, int64(100), req.Document().Get("batchSize"))
			return respondDoc(req, cursorDoc(200, "firstBatch")), nil

		case "getMore":
			require.Equal(t, int64(200), req.Document().Get("getMore"), "handle remapped")
			require.Equal(t, int64(100), req.Document().Get("batchSize"), "non-handle integer preserved")
			return respondDoc(req, cursorDoc(200, "nextBatch")), nil
		}

		t.Fatal("unexpected command")
		return nil, nil
	}

	report, err := Replay(context.Background(), tr, &ReplayOpts{Transport: ft.handle()})
	require.NoError(t, err)
	assert.Equal(t, 2, ft.calls)

	for seq, status := range statuses(report) {
		assert.Equal(t, StatusMatched, status, "frame %d", seq)
	}
}

func TestReplayMismatchReportsDiff(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)

	recordPair(t, r, 10,
		wire.MustOpMsg("ping", int32(1), "$db", "admin"),
		wire.MustOpMsg("ok", float64(1)),
	)

	tr := finalize(t, r, EndReasonClientClosed)

	ft := &fakeTransport{}
	ft.fn = func(req *middleware.Request) (*middleware.Response, error) {
		return respond(req, "ok", float64(0), "errmsg", "live is different"), nil
	}

	report, err := Replay(context.Background(), tr, &ReplayOpts{Transport: ft.handle()})
	require.Error(t, err)
	assert.Equal(t, 1, ft.calls)

	got := statuses(report)
	assert.Equal(t, StatusMismatch, got[1])

	var diff string

	for _, res := range report.Results {
		if res.Status == StatusMismatch {
			diff = res.Diff
		}
	}

	assert.Contains(t, diff, "recorded")
	assert.Contains(t, diff, "live")
}

func TestReplayErrorResponse(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)

	errDoc := wirebson.MustDocument(
		"ok", float64(0), "errmsg", "boom",
		"code", int32(42), "codeName", "Boom",
	)
	recordPair(t, r, 10,
		wire.MustOpMsg("distinct", "c", "$db", "db"),
		must.NotFail(wire.NewOpMsg(errDoc)),
	)

	tr := finalize(t, r, EndReasonClientClosed)

	ft := &fakeTransport{}
	ft.fn = func(req *middleware.Request) (*middleware.Response, error) {
		return respond(req,
			"ok", float64(0), "errmsg", "boom",
			"code", int32(42), "codeName", "Boom",
		), nil
	}

	report, err := Replay(context.Background(), tr, &ReplayOpts{Transport: ft.handle()})
	require.NoError(t, err)
	assert.Equal(t, StatusMatched, statuses(report)[1])
}

func TestReplayAuthModes(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T) *Transcript {
		t.Helper()

		r := newTestRecorder(t, nil)

		sasl := wire.MustOpMsg(
			"saslStart", int32(1), "mechanism", "SCRAM-SHA-256",
			"payload", wirebson.Binary{B: []byte("secret")}, "$db", "admin",
		)
		r.RecordRequest(opMsgHeader(1, 0, sasl), sasl)
		r.RecordResponse(
			opMsgHeader(2, 1, wire.MustOpMsg("ok", float64(1))),
			wire.MustOpMsg("ok", float64(1), "done", true),
		)

		recordPair(t, r, 3,
			wire.MustOpMsg("ping", int32(1), "$db", "admin"),
			wire.MustOpMsg("ok", float64(1)),
		)

		return finalize(t, r, EndReasonClientClosed)
	}

	t.Run("BlockedWithoutPolicy", func(t *testing.T) {
		t.Parallel()

		tr := build(t)

		ft := &fakeTransport{}
		ft.fn = func(req *middleware.Request) (*middleware.Response, error) {
			t.Fatal("handler must not be called")
			return nil, nil
		}

		report, err := Replay(context.Background(), tr, &ReplayOpts{Transport: ft.handle()})
		require.ErrorIs(t, err, ErrAuthPlaceholder)
		assert.Equal(t, 0, ft.calls)
		assert.Equal(t, StatusAuthBlocked, statuses(report)[0])
	})

	t.Run("SafeSubsequence", func(t *testing.T) {
		t.Parallel()

		tr := build(t)

		ft := &fakeTransport{}
		ft.fn = func(req *middleware.Request) (*middleware.Response, error) {
			return respond(req, "ok", float64(1)), nil
		}

		report, err := Replay(context.Background(), tr, &ReplayOpts{
			Transport: ft.handle(),
			SkipAuth:  true,
		})
		require.NoError(t, err)
		assert.Equal(t, 1, ft.calls, "only the post-auth request reaches the handler")

		got := statuses(report)
		assert.Equal(t, StatusAuthSkipped, got[0])
		assert.Equal(t, StatusAuthSkipped, got[1])
		assert.Equal(t, StatusMatched, got[3])
	})

	t.Run("InjectedSession", func(t *testing.T) {
		t.Parallel()

		tr := build(t)

		injected := false

		ft := &fakeTransport{}
		ft.fn = func(req *middleware.Request) (*middleware.Response, error) {
			return respond(req, "ok", float64(1)), nil
		}

		report, err := Replay(context.Background(), tr, &ReplayOpts{
			Transport: ft.handle(),
			AuthSession: func(context.Context) error {
				injected = true
				return nil
			},
		})
		require.NoError(t, err)
		assert.True(t, injected)
		assert.Equal(t, 1, ft.calls)
		assert.Contains(t, report.MaskedComparisons, "payload:saslStart")
	})
}

func TestReplayIncompleteTail(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)

	recordPair(t, r, 10,
		wire.MustOpMsg("ping", int32(1), "$db", "admin"),
		wire.MustOpMsg("ok", float64(1)),
	)
	require.NoError(t, r.Close(EndReasonClientClosed))

	b, err := os.ReadFile(r.Path())
	require.NoError(t, err)

	tornPath := filepath.Join(t.TempDir(), "torn.wt")
	require.NoError(t, os.WriteFile(tornPath, b[:len(b)-footerLen], 0o666))

	tr, err := Open(tornPath)
	require.ErrorIs(t, err, ErrIncomplete)

	ft := &fakeTransport{}
	ft.fn = func(req *middleware.Request) (*middleware.Response, error) {
		return respond(req, "ok", float64(1)), nil
	}

	report, err := Replay(context.Background(), tr, &ReplayOpts{Transport: ft.handle()})
	require.ErrorIs(t, err, ErrIncomplete)
	assert.Equal(t, 0, ft.calls, "the incompletely recorded exchange must not be replayed")
	assert.Equal(t, StatusIncomplete, statuses(report)[1])
}

func TestReplayMaskedComparison(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)

	// Recorded response declares a masked pwd field and stores the placeholder.
	recResp := wire.MustOpMsg("ok", float64(1), "pwd", redactionToken)
	respHeader := opMsgHeader(2, 1, recResp)

	r.RecordRequest(
		opMsgHeader(1, 0, wire.MustOpMsg("createUser", int32(1), "$db", "admin")),
		wire.MustOpMsg("createUser", int32(1), "$db", "admin"),
	)
	r.recordFrame(DirectionResponse, respHeader, must.NotFail(marshalWire(respHeader, recResp)),
		frameFlagRedacted, []string{"pwd"})

	tr := finalize(t, r, EndReasonClientClosed)

	ft := &fakeTransport{}
	ft.fn = func(req *middleware.Request) (*middleware.Response, error) {
		// The live response still contains the real credential value.
		return respond(req, "ok", float64(1), "pwd", "real-secret"), nil
	}

	report, err := Replay(context.Background(), tr, &ReplayOpts{Transport: ft.handle()})
	require.NoError(t, err)
	assert.Equal(t, StatusMasked, statuses(report)[1])
	assert.Contains(t, report.MaskedComparisons, "pwd")
}
