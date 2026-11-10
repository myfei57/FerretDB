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
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Parts of Prometheus metric names.
const (
	// TODO https://github.com/FerretDB/FerretDB/issues/3420
	namespace = "ferretdb"
	subsystem = "client"
)

// TLS bundle reload metric label values. They contain neither file paths nor any PEM data.
const (
	tlsReloadResultSuccess = "success"
	tlsReloadResultFailure = "failure"

	tlsReloadReasonNone     = ""
	tlsReloadReasonRead     = "read"
	tlsReloadReasonValidate = "validate"
	tlsReloadReasonDigest   = "digest"
	tlsReloadReasonConfig   = "config"
	tlsReloadReasonClosed   = "closed"
	tlsReloadReasonDisabled = "disabled"
)

// listenerMetrics represents listener metrics.
type listenerMetrics struct {
	accepts   *prometheus.CounterVec
	durations *prometheus.HistogramVec

	tlsReloads          *prometheus.CounterVec
	tlsBundleGeneration prometheus.Gauge
}

// NewListenerMetrics creates new listener metrics.
func NewListenerMetrics() *listenerMetrics {
	lm := &listenerMetrics{
		accepts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "accepts_total",
				Help:      "Total number of accepted client connections.",
			},
			[]string{"error"},
		),
		durations: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "duration_seconds",
				Help:      "Client connection lifetime in seconds.",
				Buckets: []float64{
					1,
					5,
					10,
					30,
					(1 * time.Minute).Seconds(),
					(5 * time.Minute).Seconds(),
					(10 * time.Minute).Seconds(),
					(30 * time.Minute).Seconds(),
				},
			},
			[]string{"error"},
		),
		tlsReloads: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "tls_bundle_reloads_total",
				Help:      "Total number of inbound TLS bundle reload attempts, labeled by result and failure reason.",
			},
			[]string{"result", "reason"},
		),
		tlsBundleGeneration: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "tls_bundle_generation",
				Help: "Generation number of the inbound TLS bundle currently used by new handshakes;" +
					" zero when TLS is disabled.",
			},
		),
	}

	lm.accepts.WithLabelValues("0")
	lm.durations.WithLabelValues("0")

	lm.tlsReloads.WithLabelValues(tlsReloadResultSuccess, tlsReloadReasonNone)

	for _, reason := range []string{
		tlsReloadReasonRead,
		tlsReloadReasonValidate,
		tlsReloadReasonDigest,
		tlsReloadReasonConfig,
		tlsReloadReasonClosed,
		tlsReloadReasonDisabled,
	} {
		lm.tlsReloads.WithLabelValues(tlsReloadResultFailure, reason)
	}

	return lm
}

// recordTLSReload counts one TLS bundle reload attempt using fixed, non-sensitive labels.
func (lm *listenerMetrics) recordTLSReload(result, reason string) {
	lm.tlsReloads.WithLabelValues(result, reason).Inc()
}

// Describe implements [prometheus.Collector].
func (lm *listenerMetrics) Describe(ch chan<- *prometheus.Desc) {
	lm.accepts.Describe(ch)
	lm.durations.Describe(ch)
	lm.tlsReloads.Describe(ch)
	lm.tlsBundleGeneration.Describe(ch)
}

// Collect implements [prometheus.Collector].
func (lm *listenerMetrics) Collect(ch chan<- prometheus.Metric) {
	lm.accepts.Collect(ch)
	lm.durations.Collect(ch)
	lm.tlsReloads.Collect(ch)
	lm.tlsBundleGeneration.Collect(ch)
}

// check interfaces
var (
	_ prometheus.Collector = (*listenerMetrics)(nil)
)
