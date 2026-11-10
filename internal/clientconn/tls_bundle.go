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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/AlekSi/lazyerrors"

	"github.com/FerretDB/FerretDB/v2/internal/util/logging"
)

// Sentinel errors returned by [Listener.ReloadTLSBundle].
var (
	// ErrTLSListenerDisabled is returned when the listener was started without a TLS socket.
	ErrTLSListenerDisabled = errors.New("TLS listener is disabled")

	// ErrListenerClosed is returned when the listener is closed and can no longer accept bundle updates.
	ErrListenerClosed = errors.New("listener is closed")
)

// ReloadTLSBundleOpts represents options for [Listener.ReloadTLSBundle].
//
// All file paths are optional: an empty value makes the listener reuse the corresponding
// file path configured when it was started. The client certificate verification mode
// can not be changed after the listener has started, so the effective CA file must be
// empty if, and only if, mTLS was not enabled at startup.
type ReloadTLSBundleOpts struct {
	// CertFile is the path to the PEM-encoded server certificate.
	CertFile string

	// KeyFile is the path to the PEM-encoded server private key.
	KeyFile string

	// CAFile is the path to the PEM-encoded bundle of trusted client CA certificates.
	CAFile string

	// ID is an optional opaque identifier assigned by the administrator.
	// It is never interpreted as a path or as PEM data; it is only logged and returned
	// in [TLSBundleInfo], allowing operators to correlate a reload with a deployment.
	ID string

	// ExpectedDigest is an optional lowercase hex-encoded SHA-256 digest of the complete
	// validated bundle. When set, the reload fails unless it matches the digest computed
	// from the files that were actually read, which prevents deploying a mixed or stale bundle.
	ExpectedDigest string
}

// TLSBundleInfo describes a published TLS bundle generation.
type TLSBundleInfo struct {
	PublishedAt time.Time
	ID          string
	Digest      string
	Generation  uint64
	ClientAuth  tls.ClientAuthType
}

// tlsBundle is one immutable, fully validated TLS configuration generation.
//
// A bundle is published as a whole: every new TLS handshake pins exactly one generation
// through [tls.Config.GetConfigForClient], so a handshake can never observe a server
// certificate from one deployment and a client CA pool from another.
// Instances must never be modified after they are stored in [Listener.tlsBundle].
type tlsBundle struct {
	publishedAt time.Time
	config      *tls.Config
	id          string
	digest      string
	generation  uint64
	clientAuth  tls.ClientAuthType
}

// readStableFiles reads every given file twice using readFile and returns their contents
// only when both reads of every file return identical bytes.
//
// It guarantees that the returned snapshot does not mix bytes written before and after a
// concurrent file replacement. All disk I/O happens here, without any listener lock held.
func readStableFiles(readFile func(string) ([]byte, error), paths []string) ([][]byte, error) {
	contents := make([][]byte, len(paths))

	for i, path := range paths {
		b, err := readFile(path)
		if err != nil {
			return nil, lazyerrors.Errorf("read TLS bundle file %q: %w", path, err)
		}

		contents[i] = b
	}

	// Re-read everything: a changed file means another deployment touched the directory
	// while we were reading it, so the candidate bundle is not trustworthy.
	for i, path := range paths {
		b, err := readFile(path)
		if err != nil {
			return nil, lazyerrors.Errorf("re-read TLS bundle file %q: %w", path, err)
		}

		if !bytes.Equal(b, contents[i]) {
			return nil, lazyerrors.Errorf("TLS bundle file %q changed while it was being read", path)
		}
	}

	return contents, nil
}

// buildTLSConfig validates the complete, already read bundle and builds an immutable
// server TLS configuration from in-memory PEM data.
//
// The client authentication mode is decided by the listener, not by the bundle contents:
// an empty CA file can neither enable client certificate verification nor downgrade
// a listener that requires it.
func buildTLSConfig(certPEM, keyPEM, caPEM []byte, clientAuth tls.ClientAuthType) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, lazyerrors.Errorf("TLS certificate/key pair: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if clientAuth == tls.RequireAndVerifyClientCert {
		if len(caPEM) == 0 {
			return nil, lazyerrors.New(
				"TLS client CA file is required because the listener requires client certificates",
			)
		}

		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caPEM); !ok {
			return nil, lazyerrors.New("TLS client CA file contains no valid PEM certificates")
		}

		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = pool
	} else if clientAuth != tls.NoClientCert {
		return nil, lazyerrors.Errorf("unsupported TLS client authentication mode %d", clientAuth)
	}

	return config, nil
}

// bundleDigest returns a lowercase hex-encoded SHA-256 fingerprint of the complete bundle.
//
// Every PEM block is length-prefixed, so two bundles with the same bytes in a different
// split still get different digests. The result is safe to log: it is a one-way fingerprint,
// not the private key or any other PEM content.
func bundleDigest(certPEM, keyPEM, caPEM []byte) string {
	h := sha256.New()

	for _, b := range [][]byte{certPEM, keyPEM, caPEM} {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(b)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(b)
	}

	return hex.EncodeToString(h.Sum(nil))
}

// newTLSBundle validates the given PEM data and assembles one immutable bundle generation.
// The generation number is assigned by the caller at publication time.
func newTLSBundle(
	generation uint64, id string, certPEM, keyPEM, caPEM []byte, clientAuth tls.ClientAuthType,
) (*tlsBundle, error) {
	config, err := buildTLSConfig(certPEM, keyPEM, caPEM, clientAuth)
	if err != nil {
		return nil, err
	}

	//exhaustruct:enforce
	return &tlsBundle{
		generation:  generation,
		id:          id,
		digest:      bundleDigest(certPEM, keyPEM, caPEM),
		clientAuth:  clientAuth,
		config:      config,
		publishedAt: time.Now(),
	}, nil
}

// info returns the public description of a published bundle.
func (b *tlsBundle) info() *TLSBundleInfo {
	//exhaustruct:enforce
	return &TLSBundleInfo{
		Generation:  b.generation,
		ID:          b.id,
		Digest:      b.digest,
		ClientAuth:  b.clientAuth,
		PublishedAt: b.publishedAt,
	}
}

// ReloadTLSBundle atomically replaces the TLS bundle of a running listener without closing
// or re-binding its listening socket.
//
// The candidate bundle is read from disk and fully validated before a new immutable
// [tls.Config] generation is published. If any file changes while it is read, if any PEM
// block is invalid, if the certificate and key do not match, or if the optional expected
// digest does not match, the currently published generation stays in use and an error is
// returned.
//
// Every new TLS handshake pins one complete published generation through
// [tls.Config.GetConfigForClient]: a certificate can never be switched together with a
// stale client CA pool. Already established connections keep using the bundle they
// handshaked with until they disconnect; rotating a client CA therefore does not revoke
// existing connections.
//
// Concurrent reloads are committed one at a time in an unspecified but total order, with
// strictly increasing generation numbers. Reloads after the listener is closed fail with
// [ErrListenerClosed] and never block. Private key contents are never written to logs
// or metrics.
//
// Only the inbound TLS listener is affected. Proxy and backend database connections
// keep their own TLS configuration.
func (l *Listener) ReloadTLSBundle(opts *ReloadTLSBundleOpts) (*TLSBundleInfo, error) {
	if l.tlsListener == nil {
		l.lm.recordTLSReload(tlsReloadResultFailure, tlsReloadReasonDisabled)
		return nil, ErrTLSListenerDisabled
	}

	if opts == nil {
		l.lm.recordTLSReload(tlsReloadResultFailure, tlsReloadReasonConfig)
		return nil, lazyerrors.New("TLS bundle reload options are not set")
	}

	// Empty paths mean "re-read the files configured at startup".
	certFile := opts.CertFile
	if certFile == "" {
		certFile = l.TLSCertFile
	}

	keyFile := opts.KeyFile
	if keyFile == "" {
		keyFile = l.TLSKeyFile
	}

	caFile := opts.CAFile
	if caFile == "" {
		caFile = l.TLSCAFile
	}

	if certFile == "" || keyFile == "" {
		l.lm.recordTLSReload(tlsReloadResultFailure, tlsReloadReasonConfig)
		return nil, lazyerrors.New("TLS certificate and key files are required to reload a bundle")
	}

	// mTLS mode is fixed for the lifetime of the listener: a reload must neither enable
	// client verification that was not configured nor silently downgrade it.
	if l.tlsClientAuth == tls.RequireAndVerifyClientCert {
		if caFile == "" {
			l.lm.recordTLSReload(tlsReloadResultFailure, tlsReloadReasonConfig)

			return nil, lazyerrors.New(
				"TLS client CA file is required: client certificate verification can not be disabled by a bundle reload",
			)
		}
	} else if l.tlsClientAuth == tls.NoClientCert {
		if caFile != "" {
			l.lm.recordTLSReload(tlsReloadResultFailure, tlsReloadReasonConfig)

			return nil, lazyerrors.New(
				"TLS client CA file must be empty: client certificate verification was not enabled when the listener started",
			)
		}
	} else {
		l.lm.recordTLSReload(tlsReloadResultFailure, tlsReloadReasonConfig)

		return nil, lazyerrors.Errorf("unsupported TLS client authentication mode %d", l.tlsClientAuth)
	}

	paths := []string{certFile, keyFile}
	if caFile != "" {
		paths = append(paths, caFile)
	}

	// All disk I/O and CPU-bound PEM validation happen without holding the bundle lock,
	// so a slow filesystem never blocks handshakes using the current generation.
	contents, err := readStableFiles(os.ReadFile, paths)
	if err != nil {
		l.lm.recordTLSReload(tlsReloadResultFailure, tlsReloadReasonRead)
		l.ll.WarnContext(context.Background(), "Failed to read TLS bundle", logging.Error(err))

		return nil, err
	}

	certPEM, keyPEM := contents[0], contents[1]

	var caPEM []byte

	if caFile != "" {
		caPEM = contents[2]
	}

	candidate, err := newTLSBundle(0, opts.ID, certPEM, keyPEM, caPEM, l.tlsClientAuth)
	if err != nil {
		l.lm.recordTLSReload(tlsReloadResultFailure, tlsReloadReasonValidate)
		l.ll.WarnContext(context.Background(), "Failed to validate TLS bundle", logging.Error(err))

		return nil, err
	}

	if expected := strings.ToLower(opts.ExpectedDigest); expected != "" && expected != candidate.digest {
		err = lazyerrors.Errorf(
			"TLS bundle digest %q does not match the expected digest %q",
			candidate.digest, expected,
		)

		l.lm.recordTLSReload(tlsReloadResultFailure, tlsReloadReasonDigest)
		l.ll.WarnContext(context.Background(), "Rejected TLS bundle with unexpected digest", logging.Error(err))

		return nil, err
	}

	// Publication is a single pointer swap under the lock. There is no I/O in this section.
	l.tlsMu.Lock()
	defer l.tlsMu.Unlock()

	if !l.Listening() || l.tlsBundle == nil {
		l.lm.recordTLSReload(tlsReloadResultFailure, tlsReloadReasonClosed)
		return nil, ErrListenerClosed
	}

	candidate.generation = l.tlsBundle.generation + 1
	candidate.publishedAt = time.Now()
	l.tlsBundle = candidate

	l.lm.tlsBundleGeneration.Set(float64(candidate.generation))
	l.lm.recordTLSReload(tlsReloadResultSuccess, tlsReloadReasonNone)

	l.ll.InfoContext(
		context.Background(),
		"TLS bundle reloaded",
		slog.Uint64("generation", candidate.generation),
		slog.String("id", candidate.id),
		slog.String("digest", candidate.digest),
	)

	return candidate.info(), nil
}

// currentTLSConfig returns the immutable configuration of the currently published bundle.
// It is called by the TLS stack on every handshake.
func (l *Listener) currentTLSConfig() (*tls.Config, error) {
	l.tlsMu.RLock()
	bundle := l.tlsBundle
	l.tlsMu.RUnlock()

	if bundle == nil {
		return nil, ErrListenerClosed
	}

	return bundle.config, nil
}

// tlsBundleInfo returns the public description of the currently published bundle, or nil
// when the TLS listener is disabled.
func (l *Listener) tlsBundleInfo() *TLSBundleInfo {
	l.tlsMu.RLock()
	defer l.tlsMu.RUnlock()

	if l.tlsBundle == nil {
		return nil
	}

	return l.tlsBundle.info()
}

// check interfaces
var (
	_ fmt.Stringer = (*TLSBundleInfo)(nil)
)

// String implements [fmt.Stringer].
// It never contains PEM data or private key material.
func (i *TLSBundleInfo) String() string {
	return fmt.Sprintf(
		"TLS bundle generation %d (id %q, digest %s, client auth %v)",
		i.Generation, i.ID, i.Digest, i.ClientAuth,
	)
}
