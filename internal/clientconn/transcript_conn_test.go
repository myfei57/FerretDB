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

package clientconn

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/FerretDB/wire"
	"github.com/FerretDB/wire/wirebson"
	"github.com/FerretDB/wire/wireclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/FerretDB/FerretDB/v2/internal/handler/middleware"
	"github.com/FerretDB/FerretDB/v2/internal/util/testutil"
	"github.com/FerretDB/FerretDB/v2/internal/wiretranscript"
)

// fakeHandler is a scripted middleware.Handler counting real invocations.
type fakeHandler struct {
	calls atomic.Int32
}

func (h *fakeHandler) Run(context.Context) {}

func (h *fakeHandler) Handle(_ context.Context, req *middleware.Request) (*middleware.Response, error) {
	h.calls.Add(1)

	doc := wirebson.MustDocument(
		"ok", float64(1),
		"command", req.Document().Command(),
	)

	return middleware.ResponseDoc(req, doc)
}

func (h *fakeHandler) Describe(chan<- *prometheus.Desc) {}

func (h *fakeHandler) Collect(chan<- prometheus.Metric) {}

// pipeTCPConn makes a net.Pipe connection look like a TCP one for peer parsing.
type pipeTCPConn struct {
	net.Conn
}

func (pipeTCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func TestTranscriptRecording(t *testing.T) {
	t.Parallel()

	logger := testutil.Logger(t)

	h := new(fakeHandler)
	m := middleware.New(&middleware.NewOpts{
		Mode:    middleware.NormalMode,
		DocDB:   h,
		Metrics: middleware.NewMetrics(),
		L:       logger,
	})

	rawDir := t.TempDir()
	transcriptDir := t.TempDir()

	client, server := net.Pipe()

	c := &conn{
		netConn:            pipeTCPConn{Conn: server},
		l:                  logger,
		m:                  m,
		testRecordsDir:     rawDir,
		transcriptDir:      transcriptDir,
		transcriptMaxBytes: 0,
	}

	// context.Background is used instead of testutil.Ctx because the latter relies
	// on file locking, which is not implemented on Windows.
	done := make(chan error, 1)

	go func() {
		done <- c.run(context.Background())
	}()

	wc := wireclient.New(client, logger)

	ctx := context.Background()

	_, _, err := wc.Request(ctx, wire.MustOpMsg("ping", int32(1), "$db", "admin"))
	require.NoError(t, err)

	_, _, err = wc.Request(ctx, wire.MustOpMsg("insert", "coll", "$db", "testdb"))
	require.NoError(t, err)

	require.NoError(t, client.Close())

	runErr := <-done
	require.ErrorIs(t, runErr, wire.ErrZeroRead)

	// The legacy raw request byte recording stays compatible and enabled at the same time.
	rawFiles, err := filepath.Glob(filepath.Join(rawDir, "*", "*.bin"))
	require.NoError(t, err)
	require.Len(t, rawFiles, 1)

	transcriptFiles, err := filepath.Glob(filepath.Join(transcriptDir, "*"+wiretranscript.FileExt))
	require.NoError(t, err)
	require.Len(t, transcriptFiles, 1)

	tr, err := wiretranscript.Open(transcriptFiles[0])
	require.NoError(t, err)

	require.True(t, tr.Complete)
	assert.Equal(t, wiretranscript.EndReasonClientClosed, tr.EndReason)
	require.Len(t, tr.Frames, 4)

	for i, f := range tr.Frames {
		assert.Equal(t, uint64(i), f.Seq)
		assert.Equal(t, wire.OpCodeMsg, f.OpCode)
	}

	assert.Equal(t, wiretranscript.DirectionRequest, tr.Frames[0].Direction)
	assert.Equal(t, wiretranscript.DirectionResponse, tr.Frames[1].Direction)
	assert.Equal(t, int32(1), tr.Frames[1].ResponseTo)

	// Every request really went through the middleware handler exactly once.
	assert.Equal(t, int32(2), h.calls.Load())
}
