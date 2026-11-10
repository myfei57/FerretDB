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
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/FerretDB/wire"
	"github.com/FerretDB/wire/wirebson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/FerretDB/FerretDB/v2/internal/util/testutil"
)

// opMsgHeader builds a wire header for an OP_MSG body.
func opMsgHeader(id, responseTo int32, body *wire.OpMsg) *wire.MsgHeader {
	return &wire.MsgHeader{
		MessageLength: int32(wire.MsgHeaderLen + body.Size()),
		RequestID:     id,
		ResponseTo:    responseTo,
		OpCode:        wire.OpCodeMsg,
	}
}

// recordPair records one request/response pair with correlated identifiers.
func recordPair(t *testing.T, r *Recorder, id int32, req, resp *wire.OpMsg) {
	t.Helper()

	r.RecordRequest(opMsgHeader(id, 0, req), req)
	r.RecordResponse(opMsgHeader(id+10_000, id, resp), resp)
}

// newTestRecorder creates a file-backed recorder for the test.
func newTestRecorder(t *testing.T, opts *RecorderOpts) *Recorder {
	t.Helper()

	r, err := NewRecorder(t.TempDir(), opts)
	require.NoError(t, err)

	return r
}

// finalize closes the recorder and opens the produced transcript.
func finalize(t *testing.T, r *Recorder, reason EndReason) *Transcript {
	t.Helper()

	require.NoError(t, r.Close(reason))
	require.NotEmpty(t, r.Path())

	tr, err := Open(r.Path())
	require.NoError(t, err)

	return tr
}

func TestRoundTripMultiRequests(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, &RecorderOpts{Logger: testutil.Logger(t)})

	ping := wire.MustOpMsg("ping", int32(1), "$db", "admin")
	pingResp := wire.MustOpMsg("ok", float64(1))

	// write against one shard/database.
	insert := wire.MustOpMsg(
		"insert", "events",
		"documents", wirebson.MustArray(wirebson.MustDocument("_id", int32(1), "v", "a")),
		"$db", "shardA",
	)
	insertResp := wire.MustOpMsg("ok", float64(1), "n", int32(1))

	// read from another shard/database.
	find := wire.MustOpMsg("find", "items", "filter", wirebson.MustDocument(), "$db", "shardB")
	findResp := wire.MustOpMsg(
		"cursor", wirebson.MustDocument(
			"id", int64(0), "ns", "shardB.items",
			"firstBatch", wirebson.MustArray(),
		),
		"ok", float64(1),
	)

	// error response.
	bad := wire.MustOpMsg("distinct", "items", "$db", "shardB")
	badResp := wire.MustOpMsg(
		"ok", float64(0), "errmsg", "boom",
		"code", int32(42), "codeName", "Boom",
	)

	recordPair(t, r, 1, ping, pingResp)
	recordPair(t, r, 2, insert, insertResp)
	recordPair(t, r, 3, find, findResp)
	recordPair(t, r, 4, bad, badResp)

	tr := finalize(t, r, EndReasonClientClosed)

	require.True(t, tr.Complete)
	require.Equal(t, EndReasonClientClosed, tr.EndReason)
	require.Len(t, tr.Frames, 8)

	for i, f := range tr.Frames {
		require.Equal(t, uint64(i), f.Seq)
		require.NotZero(t, f.Offset)

		expectedDirection := DirectionRequest
		if i%2 == 1 {
			expectedDirection = DirectionResponse
		}

		require.Equal(t, expectedDirection, f.Direction)
		require.Equal(t, wire.OpCodeMsg, f.OpCode)
		require.NotEmpty(t, f.Payload)
	}

	// Payloads are stored as the exact marshaled wire bytes.
	raw, err := marshalWire(opMsgHeader(1, 0, ping), ping)
	require.NoError(t, err)
	assert.Equal(t, raw, tr.Frames[0].Payload)
}

func TestPreservesBSONTypesAndOrder(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)

	doc := wirebson.MustDocument(
		"z", int64(-7),
		"a", "text",
		"b", true,
		"c", float64(1.5),
		"d", wirebson.MustArray(int32(1), int32(2)),
	)
	req := wire.MustOpMsg("find", "c", "filter", doc, "$db", "db")
	resp := wire.MustOpMsg("ok", float64(1))

	recordPair(t, r, 7, req, resp)

	tr := finalize(t, r, EndReasonClientClosed)

	_, body, err := wire.ReadMessage(bufio.NewReader(bytes.NewReader(tr.Frames[0].Payload)))
	require.NoError(t, err)

	decoded, err := body.(*wire.OpMsg).DocumentDeep()
	require.NoError(t, err)
	assert.Equal(t, []string{"find", "filter", "$db"}, decoded.FieldNames())

	filter := decoded.Get("filter").(*wirebson.Document)
	assert.Equal(t, []string{"z", "a", "b", "c", "d"}, filter.FieldNames())
	assert.True(t, wirebson.Equal(doc, filter))
}

func TestTruncatedFrameReportsPosition(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)
	recordPair(t, r, 1, wire.MustOpMsg("ping", int32(1), "$db", "admin"), wire.MustOpMsg("ok", float64(1)))
	recordPair(t, r, 2, wire.MustOpMsg("ping", int32(1), "$db", "admin"), wire.MustOpMsg("ok", float64(1)))
	require.NoError(t, r.Close(EndReasonClientClosed))

	b, err := os.ReadFile(r.Path())
	require.NoError(t, err)

	tr, err := Open(r.Path())
	require.NoError(t, err)

	// cut inside the second request frame.
	cut := tr.Frames[2].Offset + 12
	torn := append(append([]byte(nil), b[:cut]...), 0)
	tornPath := filepath.Join(t.TempDir(), "torn.wt")
	require.NoError(t, os.WriteFile(tornPath, torn, 0o666))

	_, err = Open(tornPath)
	require.ErrorIs(t, err, ErrTruncated)
	assert.Contains(t, err.Error(), "offset")
}

func TestMissingFooterIsIncomplete(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)
	recordPair(t, r, 1, wire.MustOpMsg("ping", int32(1), "$db", "admin"), wire.MustOpMsg("ok", float64(1)))
	require.NoError(t, r.Close(EndReasonClientClosed))

	b, err := os.ReadFile(r.Path())
	require.NoError(t, err)

	footerOff := int64(len(b)) - footerLen
	tornPath := filepath.Join(t.TempDir(), "no-footer.wt")
	require.NoError(t, os.WriteFile(tornPath, b[:footerOff], 0o666))

	tr, err := Open(tornPath)
	require.ErrorIs(t, err, ErrIncomplete)
	require.False(t, tr.Complete)

	last := tr.Frames[len(tr.Frames)-1]
	require.Equal(t, DirectionResponse, last.Direction)
	assert.True(t, last.Incomplete, "incomplete last response must not be treated as success")
}

func TestUnknownOpcodeReportsPosition(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)
	recordPair(t, r, 1, wire.MustOpMsg("ping", int32(1), "$db", "admin"), wire.MustOpMsg("ok", float64(1)))
	require.NoError(t, r.Close(EndReasonClientClosed))

	b, err := os.ReadFile(r.Path())
	require.NoError(t, err)

	tr, err := Open(r.Path())
	require.NoError(t, err)

	off := tr.Frames[0].Offset
	binary.LittleEndian.PutUint32(b[off+18:], 9999)
	patchFrameChecksum(t, b, off)

	path := filepath.Join(t.TempDir(), "opcode.wt")
	require.NoError(t, os.WriteFile(path, b, 0o666))

	_, err = Open(path)
	require.ErrorIs(t, err, ErrUnknownOpcode)
	assert.Contains(t, err.Error(), "offset")
}

func TestFrameChecksumMismatch(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)
	recordPair(t, r, 1, wire.MustOpMsg("ping", int32(1), "$db", "admin"), wire.MustOpMsg("ok", float64(1)))
	require.NoError(t, r.Close(EndReasonClientClosed))

	b, err := os.ReadFile(r.Path())
	require.NoError(t, err)

	tr, err := Open(r.Path())
	require.NoError(t, err)

	off := tr.Frames[0].Offset
	b[off+frameFixedLen] ^= 0xff

	path := filepath.Join(t.TempDir(), "crc.wt")
	require.NoError(t, os.WriteFile(path, b, 0o666))

	_, err = Open(path)
	require.ErrorIs(t, err, ErrChecksum)
}

func TestCorrelationBroken(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)
	recordPair(t, r, 1, wire.MustOpMsg("ping", int32(1), "$db", "admin"), wire.MustOpMsg("ok", float64(1)))
	require.NoError(t, r.Close(EndReasonClientClosed))

	b, err := os.ReadFile(r.Path())
	require.NoError(t, err)

	tr, err := Open(r.Path())
	require.NoError(t, err)

	off := tr.Frames[1].Offset
	binary.LittleEndian.PutUint32(b[off+26:], 4242) // responseTo no longer references any request
	patchFrameChecksum(t, b, off)

	path := filepath.Join(t.TempDir(), "corr.wt")
	require.NoError(t, os.WriteFile(path, b, 0o666))

	_, err = Open(path)
	require.ErrorIs(t, err, ErrCorrelation)
}

func TestBudgetExhaustion(t *testing.T) {
	t.Parallel()

	// Budget covers the header and roughly one frame only.
	r := newTestRecorder(t, &RecorderOpts{MaxBytes: int64(headerLen) + 120, Logger: testutil.Logger(t)})

	for range 5 {
		recordPair(t, r, 1, wire.MustOpMsg("ping", int32(1), "$db", "admin"), wire.MustOpMsg("ok", float64(1)))
	}

	assert.True(t, r.budgetExhausted)

	tr := finalize(t, r, EndReasonClientClosed)
	require.True(t, tr.Complete)
	assert.True(t, tr.BudgetExhausted)
	assert.Less(t, len(tr.Frames), 10)
}

// failWriter fails after a number of bytes and never buffers failures itself.
type failWriter struct {
	remaining int
}

func (f *failWriter) Write(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, io.ErrClosedPipe
	}

	n := min(len(p), f.remaining)
	f.remaining -= n

	if n < len(p) {
		return n, io.ErrClosedPipe
	}

	return n, nil
}

func (f *failWriter) Close() error { return nil }

func TestRecorderWriteFailureIsIsolated(t *testing.T) {
	t.Parallel()

	r := newRecorder(&failWriter{remaining: headerLen + 5}, "", &RecorderOpts{Logger: testutil.Logger(t)})

	// Production path must not panic or receive errors from recording.
	assert.NotPanics(t, func() {
		for range 3 {
			r.RecordRequest(
				opMsgHeader(1, 0, wire.MustOpMsg("ping", int32(1), "$db", "admin")),
				wire.MustOpMsg("ping", int32(1), "$db", "admin"),
			)
		}
	})

	assert.True(t, r.dead)
	assert.Error(t, r.Close(EndReasonRecorderFailure))
}

func TestAuthRedactionKeepsSecretsOut(t *testing.T) {
	t.Parallel()

	r := newTestRecorder(t, nil)

	const secret = "super-secret-password"
	const password = "hunter2"

	saslStart := wire.MustOpMsg(
		"saslStart", int32(1),
		"mechanism", "SCRAM-SHA-256",
		"payload", wirebson.Binary{B: []byte("n,,n=user,r=" + secret)},
		"$db", "admin",
	)
	saslResp := wire.MustOpMsg("ok", float64(1), "done", true, "conversationId", int32(1))

	createUser := wire.MustOpMsg(
		"createUser", "user1",
		"pwd", password,
		"roles", wirebson.MustArray(),
		"$db", "admin",
	)
	createUserResp := wire.MustOpMsg("ok", float64(1))

	r.RecordRequest(opMsgHeader(1, 0, saslStart), saslStart)
	r.RecordResponse(opMsgHeader(2, 1, saslResp), saslResp)
	recordPair(t, r, 3, createUser, createUserResp)

	tr := finalize(t, r, EndReasonClientClosed)

	raw, err := os.ReadFile(r.Path())
	require.NoError(t, err)
	assert.NotContains(t, raw, []byte(secret))
	assert.NotContains(t, raw, []byte(password))

	authReq := tr.Frames[0]
	assert.True(t, authReq.AuthPlaceholder)
	assert.Nil(t, authReq.Payload)
	assert.Equal(t, []string{"payload:saslStart"}, authReq.MaskedFields)

	authResp := tr.Frames[1]
	assert.True(t, authResp.AuthPlaceholder)
	assert.Nil(t, authResp.Payload)

	redactedFrame := tr.Frames[2]
	assert.True(t, redactedFrame.Redacted)
	assert.Equal(t, []string{"pwd"}, redactedFrame.MaskedFields)

	// Redacted payload remains a legal wire message with legal BSON.
	_, body, err := wire.ReadMessage(bufio.NewReader(bytes.NewReader(redactedFrame.Payload)))
	require.NoError(t, err)

	doc, err := body.(*wire.OpMsg).DocumentDeep()
	require.NoError(t, err)
	assert.Equal(t, redactionToken, doc.Get("pwd"))
	assert.Equal(t, "user1", doc.Get("createUser"))
}

func TestFindFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.wt"), nil, 0o666))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.wt"), nil, 0o666))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ignore.bin"), nil, 0o666))

	files, err := FindFiles(dir)
	require.NoError(t, err)
	assert.Len(t, files, 2)

	single, err := FindFiles(filepath.Join(dir, "a.wt"))
	require.NoError(t, err)
	assert.Len(t, single, 1)
}

// patchFrameChecksum recalculates the frame CRC after an in-place mutation.
func patchFrameChecksum(t *testing.T, b []byte, off int64) {
	t.Helper()

	frameLen := int64(binary.LittleEndian.Uint32(b[off+4:]))
	end := off + frameLen

	crc := crc32.Checksum(b[off:end-4], crc32.MakeTable(crc32.Castagnoli))
	binary.LittleEndian.PutUint32(b[end-4:], crc)
}
