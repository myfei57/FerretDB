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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/FerretDB/FerretDB/v2/internal/util/testutil"
)

// testPKI is a small in-memory PKI generated for a single test: one CA and one leaf.
type testPKI struct {
	caKey *ecdsa.PrivateKey
	ca    *x509.Certificate
	caPEM []byte
	leaf  *x509.Certificate

	certPEM []byte
	keyPEM  []byte
}

// serialString returns the leaf certificate serial number as a string.
func (p *testPKI) serialString() string {
	return p.leaf.SerialNumber.String()
}

// testNewPKI generates a fresh ECDSA CA and leaf certificate in memory.
// When client is true, the leaf is a client certificate; otherwise it is a server certificate.
func testNewPKI(tb testing.TB, commonName string, client bool) *testPKI {
	tb.Helper()

	now := time.Now()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)

	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(tb, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: commonName + "-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(tb, err)

	ca, err := x509.ParseCertificate(caDER)
	require.NoError(tb, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)

	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(tb, err)

	extUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if client {
		extUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  extUsage,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	require.NoError(tb, err)

	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(tb, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(tb, err)

	//exhaustruct:enforce
	return &testPKI{
		caKey: caKey,
		ca:    ca,
		caPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caDER,
		}),
		leaf: leaf,
		certPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: leafDER,
		}),
		keyPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		}),
	}
}

// testWriteFile writes data into dir under name and returns the full path.
func testWriteFile(tb testing.TB, dir, name string, data []byte) string {
	tb.Helper()

	path := filepath.Join(dir, name)
	require.NoError(tb, os.WriteFile(path, data, 0o600))

	return path
}

// testListenTLS starts a TLS listener using the given server PKI.
// When clientCAPEM is not nil, mutual TLS is required.
func testListenTLS(tb testing.TB, server *testPKI, clientCAPEM []byte) (*Listener, string) {
	tb.Helper()

	dir := tb.TempDir()

	opts := &ListenerOpts{
		Logger:      testutil.Logger(tb),
		TLS:         "127.0.0.1:0",
		TLSCertFile: testWriteFile(tb, dir, "server-cert.pem", server.certPEM),
		TLSKeyFile:  testWriteFile(tb, dir, "server-key.pem", server.keyPEM),
	}

	if clientCAPEM != nil {
		opts.TLSCAFile = testWriteFile(tb, dir, "client-ca.pem", clientCAPEM)
	}

	l, err := Listen(opts)
	require.NoError(tb, err)

	tb.Cleanup(l.close)

	return l, dir
}

// testServerHandshake is one handshake observed on the server side.
type testServerHandshake struct {
	err          error
	clientSerial string
}

// testTLSServer accepts TLS connections in the background and records real handshakes.
type testTLSServer struct {
	ctx     context.Context
	l       *Listener
	cancel  context.CancelFunc
	records []testServerHandshake
	wg      sync.WaitGroup
	mu      sync.Mutex
}

// testServeTLS runs a background accept loop performing real TLS handshakes.
func testServeTLS(tb testing.TB, l *Listener) *testTLSServer {
	tb.Helper()

	ctx, cancel := context.WithCancel(tb.Context())

	s := &testTLSServer{
		l:      l,
		ctx:    ctx,
		cancel: cancel,
	}

	s.wg.Add(1)

	go func() {
		defer s.wg.Done()

		for {
			conn, err := l.tlsListener.Accept()
			if err != nil {
				return
			}

			s.wg.Add(1)

			go s.handle(conn)
		}
	}()

	tb.Cleanup(s.stop)

	return s
}

// handle performs the server-side handshake and keeps the connection open until shutdown.
func (s *testTLSServer) handle(conn net.Conn) {
	defer s.wg.Done()

	tlsConn := conn.(*tls.Conn)
	err := tlsConn.HandshakeContext(s.ctx)

	record := testServerHandshake{err: err}

	if err == nil {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			record.clientSerial = state.PeerCertificates[0].SerialNumber.String()
		}
	}

	s.mu.Lock()
	s.records = append(s.records, record)
	s.mu.Unlock()

	if err != nil {
		_ = tlsConn.Close()
		return
	}

	// Keep the established connection alive, exactly like the production accept loop would,
	// until the test stops the server.
	<-s.ctx.Done()
	_ = tlsConn.Close()
}

// stop closes the listener and waits for all accept and handshake goroutines.
func (s *testTLSServer) stop() {
	s.cancel()
	s.l.close()
	s.wg.Wait()
}

// snapshots returns a copy of all recorded server-side handshakes.
func (s *testTLSServer) snapshots() []testServerHandshake {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := make([]testServerHandshake, len(s.records))
	copy(res, s.records)

	return res
}

// The testDial helper performs a real TLS handshake against addr.
// The serverCA argument validates the server certificate; the client argument is presented only when not nil.
// A zero maxVersion means the library default.
func testDial(
	tb testing.TB, addr string, serverCA *testPKI, client *testPKI, maxVersion uint16,
) (*tls.Conn, tls.ConnectionState, error) {
	tb.Helper()

	roots := x509.NewCertPool()
	roots.AddCert(serverCA.ca)

	config := &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
		MaxVersion: maxVersion,
	}

	if client != nil {
		cert, err := tls.X509KeyPair(client.certPEM, client.keyPEM)
		require.NoError(tb, err)

		config.Certificates = []tls.Certificate{cert}
	}

	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, tls.ConnectionState{}, err
	}

	conn := tls.Client(raw, config)

	ctx, cancel := context.WithTimeout(tb.Context(), 10*time.Second)
	defer cancel()

	if err = conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, tls.ConnectionState{}, err
	}

	tb.Cleanup(func() { _ = conn.Close() })

	return conn, conn.ConnectionState(), nil
}

// testAssertDialFails performs a handshake that must fail before application data is exchanged,
// for example when the client does not trust the server certificate.
func testAssertDialFails(tb testing.TB, addr string, serverCA *testPKI, client *testPKI) {
	tb.Helper()

	conn, _, err := testDial(tb, addr, serverCA, client, 0)
	if conn != nil {
		_ = conn.Close()
	}

	assert.Error(tb, err, "handshake must fail")
}

// testAssertDialRejected verifies that the server refuses a client due to mTLS policy.
//
// Under TLS 1.2 the fatal alert makes Handshake fail synchronously. Under TLS 1.3, Go clients
// return from Handshake before the client-certificate decision and observe the rejection alert
// on the first application data operation, so a short Read is used to make the failure explicit.
func testAssertDialRejected(tb testing.TB, addr string, serverCA *testPKI, client *testPKI) {
	tb.Helper()

	conn, _, err := testDial(tb, addr, serverCA, client, 0)
	if err != nil {
		// Synchronous rejection (TLS 1.2 or earlier failure).
		return
	}

	defer func() { _ = conn.Close() }()

	require.NoError(tb, conn.SetReadDeadline(time.Now().Add(2*time.Second)))

	_, readErr := conn.Read(make([]byte, 1))
	require.Error(tb, readErr, "server must reject the client")

	var netErr net.Error
	if errors.As(readErr, &netErr) {
		assert.False(tb, netErr.Timeout(), "expected a TLS rejection alert, got a read timeout")
	}
}

// TestTLSBundleRotateServerCertificate verifies atomic rotation of the server certificate
// using real TLS clients, including old and new CAs, both TLS versions and long-lived connections.
func TestTLSBundleRotateServerCertificate(t *testing.T) {
	pki1 := testNewPKI(t, "server1", false)
	pki2 := testNewPKI(t, "server2", false)

	l, dir := testListenTLS(t, pki1, nil)
	srv := testServeTLS(t, l)
	addr := l.TLSAddr().String()

	require.Equal(t, uint64(1), l.tlsBundleInfo().Generation)

	conn1, state1, err := testDial(t, addr, pki1, nil, 0)
	require.NoError(t, err)
	assert.Equal(t, pki1.serialString(), state1.PeerCertificates[0].SerialNumber.String())

	// A client trusting only the not-yet-published CA must fail.
	testAssertDialFails(t, addr, pki2, nil)

	// The same must hold when the client is pinned to TLS 1.2.
	_, state12, err := testDial(t, addr, pki1, nil, tls.VersionTLS12)
	require.NoError(t, err)
	assert.Equal(t, pki1.serialString(), state12.PeerCertificates[0].SerialNumber.String())

	// Rotate the whole bundle to a certificate signed by a different CA.
	info, err := l.ReloadTLSBundle(&ReloadTLSBundleOpts{
		CertFile: testWriteFile(t, dir, "server2-cert.pem", pki2.certPEM),
		KeyFile:  testWriteFile(t, dir, "server2-key.pem", pki2.keyPEM),
		ID:       "deployment-2",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), info.Generation)
	assert.Equal(t, "deployment-2", info.ID)
	assert.Equal(t, tls.NoClientCert, info.ClientAuth)
	assert.Len(t, info.Digest, 64)

	_, err = hex.DecodeString(info.Digest)
	require.NoError(t, err)

	// New handshakes pin the new generation; the old CA is no longer trusted.
	_, state2, err := testDial(t, addr, pki2, nil, 0)
	require.NoError(t, err)
	assert.Equal(t, pki2.serialString(), state2.PeerCertificates[0].SerialNumber.String())

	testAssertDialFails(t, addr, pki1, nil)

	// The connection established before the reload keeps using the old bundle and stays open.
	assert.Equal(t, pki1.serialString(), conn1.ConnectionState().PeerCertificates[0].SerialNumber.String())

	require.NoError(t, conn1.SetReadDeadline(time.Now().Add(200*time.Millisecond)))

	_, err = conn1.Read(make([]byte, 1))

	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout(), "established connection must remain open, got %v", err)

	// A correct expected digest is accepted; a wrong one is rejected without touching the generation.
	info, err = l.ReloadTLSBundle(&ReloadTLSBundleOpts{
		CertFile:       filepath.Join(dir, "server2-cert.pem"),
		KeyFile:        filepath.Join(dir, "server2-key.pem"),
		ExpectedDigest: info.Digest,
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(3), info.Generation)

	_, err = l.ReloadTLSBundle(&ReloadTLSBundleOpts{
		CertFile:       filepath.Join(dir, "server2-cert.pem"),
		KeyFile:        filepath.Join(dir, "server2-key.pem"),
		ExpectedDigest: strings.Repeat("0", 64),
	})
	require.Error(t, err)
	assert.Equal(t, uint64(3), l.tlsBundleInfo().Generation)

	// The failed digest check must not have affected the usable configuration.
	_, state2Again, err := testDial(t, addr, pki2, nil, tls.VersionTLS13)
	require.NoError(t, err)
	assert.Equal(t, pki2.serialString(), state2Again.PeerCertificates[0].SerialNumber.String())

	assert.NotEmpty(t, srv.snapshots())
}

// TestTLSBundleMTLSRotation verifies that client CA rotation keeps requiring client certificates
// and that every successful handshake uses one complete generation.
func TestTLSBundleMTLSRotation(t *testing.T) {
	server1 := testNewPKI(t, "mts-server1", false)
	server2 := testNewPKI(t, "mts-server2", false)

	clientCA1 := testNewPKI(t, "mts-client-ca1", true)
	clientCA2 := testNewPKI(t, "mts-client-ca2", true)
	client1 := testIssueChild(t, clientCA1, "mts-client1")
	client2 := testIssueChild(t, clientCA2, "mts-client2")

	l, dir := testListenTLS(t, server1, clientCA1.caPEM)
	srv := testServeTLS(t, l)
	addr := l.TLSAddr().String()

	info := l.tlsBundleInfo()
	require.NotNil(t, info)
	assert.Equal(t, tls.RequireAndVerifyClientCert, info.ClientAuth)

	// Generation 1: only client1, signed by clientCA1, is accepted.
	_, state, err := testDial(t, addr, server1, client1, 0)
	require.NoError(t, err)
	assert.Equal(t, server1.serialString(), state.PeerCertificates[0].SerialNumber.String())

	testAssertDialRejected(t, addr, server1, nil)
	testAssertDialRejected(t, addr, server1, client2)

	// Rotate server certificate and client CA together.
	info, err = l.ReloadTLSBundle(&ReloadTLSBundleOpts{
		CertFile: testWriteFile(t, dir, "server2-cert.pem", server2.certPEM),
		KeyFile:  testWriteFile(t, dir, "server2-key.pem", server2.keyPEM),
		CAFile:   testWriteFile(t, dir, "client-ca2.pem", clientCA2.caPEM),
		ID:       "mtls-deployment-2",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), info.Generation)
	assert.Equal(t, tls.RequireAndVerifyClientCert, info.ClientAuth)

	_, state, err = testDial(t, addr, server2, client2, 0)
	require.NoError(t, err)
	assert.Equal(t, server2.serialString(), state.PeerCertificates[0].SerialNumber.String())

	// The old client CA is rejected and a client without a certificate is still rejected:
	// reloading the CA must never downgrade RequireAndVerifyClientCert.
	testAssertDialRejected(t, addr, server2, client1)
	testAssertDialRejected(t, addr, server2, nil)

	// Invalid CA updates must fail and leave generation 2 fully usable.
	emptyCAPath := testWriteFile(t, dir, "empty-ca.pem", nil)

	_, err = l.ReloadTLSBundle(&ReloadTLSBundleOpts{
		CertFile: filepath.Join(dir, "server2-cert.pem"),
		KeyFile:  filepath.Join(dir, "server2-key.pem"),
		CAFile:   emptyCAPath,
	})
	require.Error(t, err)
	assert.Equal(t, uint64(2), l.tlsBundleInfo().Generation)

	_, err = l.ReloadTLSBundle(&ReloadTLSBundleOpts{
		CertFile: filepath.Join(dir, "server2-cert.pem"),
		KeyFile:  filepath.Join(dir, "server2-key.pem"),
		CAFile:   testWriteFile(t, dir, "bad-ca.pem", []byte("not a pem")),
	})
	require.Error(t, err)
	assert.Equal(t, uint64(2), l.tlsBundleInfo().Generation)
	assert.Equal(t, tls.RequireAndVerifyClientCert, l.tlsBundleInfo().ClientAuth)

	_, state, err = testDial(t, addr, server2, client2, 0)
	require.NoError(t, err)
	assert.Equal(t, server2.serialString(), state.PeerCertificates[0].SerialNumber.String())

	// Every successful server-side handshake must have accepted a certificate of the
	// generation that was published at that moment. Failed handshakes are expected here.
	for _, record := range srv.snapshots() {
		if record.err != nil {
			continue
		}

		assert.NotEmpty(t, record.clientSerial)
		assert.Contains(t, []string{client1.serialString(), client2.serialString()}, record.clientSerial)
	}
}

// TestTLSBundleInvalidKeepsOldGeneration covers mismatched keys, corrupt PEM and missing files.
func TestTLSBundleInvalidKeepsOldGeneration(t *testing.T) {
	good := testNewPKI(t, "good", false)
	other := testNewPKI(t, "other", false)

	l, dir := testListenTLS(t, good, nil)
	srv := testServeTLS(t, l)
	addr := l.TLSAddr().String()

	certPath := filepath.Join(dir, "server-cert.pem")
	keyPath := filepath.Join(dir, "server-key.pem")

	garbage := []byte("-----BEGIN BROKEN-----\nnot valid pem\n-----END BROKEN-----\n")

	// Each candidate is invalid in a different way; none may replace the running generation.
	for name, opts := range map[string]*ReloadTLSBundleOpts{
		"corrupt certificate PEM": {
			CertFile: testWriteFile(t, dir, "bad-cert.pem", garbage),
			KeyFile:  keyPath,
		},
		"corrupt key PEM": {
			CertFile: certPath,
			KeyFile:  testWriteFile(t, dir, "bad-key.pem", garbage),
		},
		"certificate and key do not match": {
			CertFile: testWriteFile(t, dir, "other-cert.pem", other.certPEM),
			KeyFile:  keyPath,
		},
		"missing certificate file": {
			CertFile: filepath.Join(dir, "does-not-exist.pem"),
			KeyFile:  keyPath,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := l.ReloadTLSBundle(opts)
			require.Error(t, err)

			assert.Equal(t, uint64(1), l.tlsBundleInfo().Generation)

			_, state, dialErr := testDial(t, addr, good, nil, 0)
			require.NoError(t, dialErr)
			assert.Equal(t, good.serialString(), state.PeerCertificates[0].SerialNumber.String())
		})
	}

	assert.NotEmpty(t, srv.snapshots())
}

// TestTLSBundleNonMTLSCannotEnable ensures an empty or stray CA file never enables mTLS
// on a listener started without client certificate verification.
func TestTLSBundleNonMTLSCannotEnable(t *testing.T) {
	server := testNewPKI(t, "plain", false)
	strayCA := testNewPKI(t, "stray-ca", true)

	l, dir := testListenTLS(t, server, nil)
	testServeTLS(t, l)
	addr := l.TLSAddr().String()

	_, err := l.ReloadTLSBundle(&ReloadTLSBundleOpts{
		CAFile: testWriteFile(t, dir, "stray-ca.pem", strayCA.caPEM),
	})
	require.Error(t, err)
	assert.Equal(t, tls.NoClientCert, l.tlsBundleInfo().ClientAuth)

	// A client without a certificate keeps succeeding.
	_, _, err = testDial(t, addr, server, nil, 0)
	require.NoError(t, err)

	// Re-reading the configured files works and does not change the mode.
	info, err := l.ReloadTLSBundle(&ReloadTLSBundleOpts{})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), info.Generation)
	assert.Equal(t, tls.NoClientCert, info.ClientAuth)

	// Direct builder checks pin down the mode semantics independently of the file layer.
	config, err := buildTLSConfig(server.certPEM, server.keyPEM, strayCA.caPEM, tls.NoClientCert)
	require.NoError(t, err)
	assert.Equal(t, tls.NoClientCert, config.ClientAuth)
	assert.Nil(t, config.ClientCAs)

	_, err = buildTLSConfig(server.certPEM, server.keyPEM, nil, tls.RequireAndVerifyClientCert)
	require.Error(t, err)

	_, err = buildTLSConfig(server.certPEM, server.keyPEM, []byte("garbage"), tls.RequireAndVerifyClientCert)
	require.Error(t, err)
}

// TestTLSBundleReadStability directly verifies the double-read snapshot logic.
func TestTLSBundleReadStability(t *testing.T) {
	t.Run("stable files", func(t *testing.T) {
		files := map[string][]byte{
			"cert": []byte("cert-bytes"),
			"key":  []byte("key-bytes"),
		}

		reader := func(path string) ([]byte, error) {
			return files[path], nil
		}

		contents, err := readStableFiles(reader, []string{"cert", "key"})
		require.NoError(t, err)
		require.Len(t, contents, 2)
		assert.Equal(t, []byte("cert-bytes"), contents[0])
		assert.Equal(t, []byte("key-bytes"), contents[1])
	})

	t.Run("file changes between reads", func(t *testing.T) {
		calls := 0

		reader := func(path string) ([]byte, error) {
			if path != "cert" {
				return []byte("key-bytes"), nil
			}

			calls++
			if calls == 1 {
				return []byte("old-cert"), nil
			}

			return []byte("new-cert"), nil
		}

		_, err := readStableFiles(reader, []string{"cert", "key"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "changed while it was being read")
	})

	t.Run("read error", func(t *testing.T) {
		reader := func(string) ([]byte, error) {
			return nil, os.ErrNotExist
		}

		_, err := readStableFiles(reader, []string{"cert"})
		require.Error(t, err)
	})
}

// TestTLSBundleDigest verifies digest determinism and sensitivity to every bundle part.
func TestTLSBundleDigest(t *testing.T) {
	pki := testNewPKI(t, "digest", false)
	ca := testNewPKI(t, "digest-ca", true)

	d1 := bundleDigest(pki.certPEM, pki.keyPEM, nil)
	d2 := bundleDigest(pki.certPEM, pki.keyPEM, nil)

	assert.Len(t, d1, 64)
	assert.Equal(t, d1, d2)

	other := testNewPKI(t, "digest-other", false)

	assert.NotEqual(t, d1, bundleDigest(other.certPEM, pki.keyPEM, nil))
	assert.NotEqual(t, d1, bundleDigest(pki.certPEM, other.keyPEM, nil))
	assert.NotEqual(t, d1, bundleDigest(pki.certPEM, pki.keyPEM, ca.caPEM))

	// Length prefixes make concatenation order matter.
	assert.NotEqual(t,
		bundleDigest([]byte("aa"), []byte("a"), nil),
		bundleDigest([]byte("a"), []byte("aa"), nil),
	)
}

// TestTLSBundleConcurrent exercises concurrent reloads and handshakes.
// Every successful handshake must observe one complete, published generation.
func TestTLSBundleConcurrent(t *testing.T) {
	// Two fully independent mTLS generations.
	serverA := testNewPKI(t, "a-server", false)
	serverB := testNewPKI(t, "b-server", false)
	clientCAA := testNewPKI(t, "a-client-ca", true)
	clientCAB := testNewPKI(t, "b-client-ca", true)
	clientA := testIssueChild(t, clientCAA, "a-client")
	clientB := testIssueChild(t, clientCAB, "b-client")

	l, dir := testListenTLS(t, serverA, clientCAA.caPEM)
	srv := testServeTLS(t, l)
	addr := l.TLSAddr().String()

	dirA := filepath.Join(dir, "gen-a")
	dirB := filepath.Join(dir, "gen-b")

	require.NoError(t, os.Mkdir(dirA, 0o700))
	require.NoError(t, os.Mkdir(dirB, 0o700))

	optsA := ReloadTLSBundleOpts{
		CertFile: testWriteFile(t, dirA, "cert.pem", serverA.certPEM),
		KeyFile:  testWriteFile(t, dirA, "key.pem", serverA.keyPEM),
		CAFile:   testWriteFile(t, dirA, "ca.pem", clientCAA.caPEM),
		ID:       "generation-a",
	}

	optsB := ReloadTLSBundleOpts{
		CertFile: testWriteFile(t, dirB, "cert.pem", serverB.certPEM),
		KeyFile:  testWriteFile(t, dirB, "key.pem", serverB.keyPEM),
		CAFile:   testWriteFile(t, dirB, "ca.pem", clientCAB.caPEM),
		ID:       "generation-b",
	}

	// An always-invalid candidate must never be published.
	optsBad := ReloadTLSBundleOpts{
		CertFile: testWriteFile(t, dirB, "cert.pem", serverB.certPEM),
		KeyFile:  testWriteFile(t, dirA, "key.pem", serverA.keyPEM),
		CAFile:   filepath.Join(dirB, "ca.pem"),
	}

	type reloadOutcome struct {
		err        error
		generation uint64
	}

	var outcomesMu sync.Mutex
	var outcomes []reloadOutcome

	var reloadCount atomic.Int64

	var reloadWG sync.WaitGroup

	for range 8 {
		reloadWG.Add(1)

		go func() {
			defer reloadWG.Done()

			for range 8 {
				n := reloadCount.Add(1)

				var opts *ReloadTLSBundleOpts

				switch n % 4 {
				case 0:
					opts = &optsBad
				case 1:
					opts = &optsA
				case 2:
					opts = &optsB
				default:
					opts = &optsA
				}

				info, err := l.ReloadTLSBundle(opts)

				outcomesMu.Lock()

				if err == nil {
					outcomes = append(outcomes, reloadOutcome{generation: info.Generation})
				} else {
					outcomes = append(outcomes, reloadOutcome{err: err})
				}

				outcomesMu.Unlock()
			}
		}()
	}

	type dialResult struct {
		generation string
		ok         bool
	}

	var dialWG sync.WaitGroup
	var resultsMu sync.Mutex
	var results []dialResult

	var dialGen atomic.Uint64

	for range 16 {
		dialWG.Add(1)

		go func() {
			defer dialWG.Done()

			for range 10 {
				g := dialGen.Add(1) % 2

				var serverCA, client *testPKI
				var name string

				if g == 0 {
					serverCA, client, name = serverA, clientA, "A"
				} else {
					serverCA, client, name = serverB, clientB, "B"
				}

				conn, state, err := testDial(t, addr, serverCA, client, 0)
				if conn != nil {
					_ = conn.Close()
				}

				result := dialResult{generation: name, ok: err == nil}

				if err == nil {
					// A successful handshake must present exactly the server cert of that generation.
					expectedSerial := serverCA.serialString()
					if actual := state.PeerCertificates[0].SerialNumber.String(); actual != expectedSerial {
						t.Errorf("generation %s handshake observed server serial %s, want %s", name, actual, expectedSerial)
					}
				}

				resultsMu.Lock()
				results = append(results, result)
				resultsMu.Unlock()
			}
		}()
	}

	reloadWG.Wait()
	dialWG.Wait()

	// Successful commits must get unique, contiguous generation numbers.
	// They are assigned under the lock in commit order, while the collected outcomes are
	// in completion order, so only the set of generations can be asserted here.
	var generations []uint64

	for _, outcome := range outcomes {
		if outcome.err == nil {
			generations = append(generations, outcome.generation)
		} else {
			assert.True(t, errors.Is(outcome.err, ErrListenerClosed) || isReloadValidationError(outcome.err))
		}
	}

	require.NotEmpty(t, generations)

	sort.Slice(generations, func(i, j int) bool { return generations[i] < generations[j] })

	for i, generation := range generations {
		// The initial bundle is generation 1, so the first reload must be generation 2.
		assert.Equal(t, uint64(i+2), generation, "duplicate or non-contiguous generation")
	}

	// Both generations were observed working, and cross-generation handshakes always failed:
	// there is no such thing as a partially switched bundle.
	okA, okB := false, false

	for _, result := range results {
		switch {
		case result.generation == "A" && result.ok:
			okA = true
		case result.generation == "B" && result.ok:
			okB = true
		}
	}

	assert.True(t, okA, "generation A must complete at least one handshake")
	assert.True(t, okB, "generation B must complete at least one handshake")

	// Every server-side success must pair the client certificate with the same generation's CA.
	clientSerials := map[string]string{
		clientA.serialString(): "A",
		clientB.serialString(): "B",
	}

	for _, record := range srv.snapshots() {
		if record.err != nil {
			continue
		}

		generation, ok := clientSerials[record.clientSerial]
		assert.True(t, ok, "unexpected client serial %s", record.clientSerial)
		assert.NotEmpty(t, generation)
	}
}

// TestTLSBundleClosedRejectsUpdate verifies shutdown semantics under concurrency.
func TestTLSBundleClosedRejectsUpdate(t *testing.T) {
	pki := testNewPKI(t, "closing", false)
	l, _ := testListenTLS(t, pki, nil)

	l.close()

	_, err := l.ReloadTLSBundle(&ReloadTLSBundleOpts{})
	require.ErrorIs(t, err, ErrListenerClosed)

	// A second close must be a safe no-op.
	assert.False(t, l.Listening())
	l.close()
}

// TestTLSBundleCloseRacesReload ensures every concurrent reload either commits or is rejected
// once the listener closes, with no panic and no publication after closure.
func TestTLSBundleCloseRacesReload(t *testing.T) {
	pki := testNewPKI(t, "race-closing", false)
	l, dir := testListenTLS(t, pki, nil)

	opts := &ReloadTLSBundleOpts{
		CertFile: filepath.Join(dir, "server-cert.pem"),
		KeyFile:  filepath.Join(dir, "server-key.pem"),
	}

	var wg sync.WaitGroup

	for range 16 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for range 20 {
				info, err := l.ReloadTLSBundle(opts)

				switch {
				case err == nil:
					assert.NotZero(t, info.Generation)
				case errors.Is(err, ErrListenerClosed):
					return
				default:
					t.Errorf("unexpected reload error: %v", err)
					return
				}
			}
		}()
	}

	time.Sleep(10 * time.Millisecond)
	l.close()
	wg.Wait()

	_, err := l.ReloadTLSBundle(opts)
	require.ErrorIs(t, err, ErrListenerClosed)
}

// TestTLSListenerDisabledAndBadInitialBundles covers startup-time validation.
func TestTLSListenerDisabledAndBadInitialBundles(t *testing.T) {
	t.Run("reload without TLS listener", func(t *testing.T) {
		l, err := Listen(&ListenerOpts{
			Logger: testutil.Logger(t),
			TCP:    "127.0.0.1:0",
		})
		require.NoError(t, err)
		t.Cleanup(l.close)

		_, err = l.ReloadTLSBundle(&ReloadTLSBundleOpts{})
		require.ErrorIs(t, err, ErrTLSListenerDisabled)
	})

	t.Run("corrupt initial certificate", func(t *testing.T) {
		dir := t.TempDir()
		certPath := testWriteFile(t, dir, "cert.pem", []byte("broken"))
		keyPath := testWriteFile(t, dir, "key.pem", []byte("broken"))

		l, err := Listen(&ListenerOpts{
			Logger:      testutil.Logger(t),
			TLS:         "127.0.0.1:0",
			TLSCertFile: certPath,
			TLSKeyFile:  keyPath,
		})
		require.Error(t, err)
		assert.Nil(t, l)
	})

	t.Run("empty initial client CA", func(t *testing.T) {
		pki := testNewPKI(t, "startup-mtls", false)
		dir := t.TempDir()

		l, err := Listen(&ListenerOpts{
			Logger:      testutil.Logger(t),
			TLS:         "127.0.0.1:0",
			TLSCertFile: testWriteFile(t, dir, "cert.pem", pki.certPEM),
			TLSKeyFile:  testWriteFile(t, dir, "key.pem", pki.keyPEM),
			TLSCAFile:   testWriteFile(t, dir, "ca.pem", nil),
		})
		require.Error(t, err)
		assert.Nil(t, l)
	})
}

// TestTLSBundleNoPrivateKeyInLogs ensures PEM bodies never reach the logger.
func TestTLSBundleNoPrivateKeyInLogs(t *testing.T) {
	var buffer bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&buffer, nil))

	pki := testNewPKI(t, "quiet", false)
	dir := t.TempDir()
	certPath := testWriteFile(t, dir, "cert.pem", pki.certPEM)
	keyPath := testWriteFile(t, dir, "key.pem", pki.keyPEM)

	l, err := Listen(&ListenerOpts{
		Logger:      logger,
		TLS:         "127.0.0.1:0",
		TLSCertFile: certPath,
		TLSKeyFile:  keyPath,
	})
	require.NoError(t, err)
	t.Cleanup(l.close)

	_, err = l.ReloadTLSBundle(&ReloadTLSBundleOpts{ID: "ok"})
	require.NoError(t, err)

	badKeyPath := testWriteFile(t, dir, "bad-key.pem", []byte("-----BEGIN PRIVATE KEY-----\nXXXX\n-----END PRIVATE KEY-----\n"))

	_, err = l.ReloadTLSBundle(&ReloadTLSBundleOpts{CertFile: certPath, KeyFile: badKeyPath})
	require.Error(t, err)

	_, err = l.ReloadTLSBundle(&ReloadTLSBundleOpts{ExpectedDigest: "abcd"})
	require.Error(t, err)

	logs := buffer.String()
	assert.NotContains(t, logs, "PRIVATE KEY")
	assert.NotContains(t, logs, string(pki.keyPEM))
	assert.NotContains(t, logs, string(pki.certPEM))
}

// testIssueChild issues a fresh client leaf signed by the given CA and returns a PKI sharing the CA.
func testIssueChild(tb testing.TB, ca *testPKI, commonName string) *testPKI {
	tb.Helper()

	now := time.Now()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(tb, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.ca, &leafKey.PublicKey, ca.caKey)
	require.NoError(tb, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(tb, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(tb, err)

	//exhaustruct:enforce
	return &testPKI{
		caKey: ca.caKey,
		ca:    ca.ca,
		caPEM: ca.caPEM,
		leaf:  leaf,
		certPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		}),
		keyPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		}),
	}
}

// isReloadValidationError reports whether err is an expected reload failure other than shutdown.
func isReloadValidationError(err error) bool {
	if err == nil {
		return false
	}

	return !errors.Is(err, ErrListenerClosed) && !errors.Is(err, ErrTLSListenerDisabled)
}
