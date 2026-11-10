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

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/FerretDB/FerretDB/v2/internal/handler/middleware"
	"github.com/FerretDB/FerretDB/v2/internal/util/setup"
	"github.com/FerretDB/FerretDB/v2/internal/util/state"
	"github.com/FerretDB/FerretDB/v2/internal/wiretranscript"
)

// runReplay replays the configured transcript through a real handler instance.
// No network listener is started.
func runReplay() {
	logger := setupDefaultLogger(cli.Log.Format, "")
	checkFlags(logger)

	stateProvider, err := state.NewProviderDir(cli.StateDir)
	if err != nil {
		logger.Error("Failed to set up state provider", slog.String("error", err.Error()))
		os.Exit(1)
	}

	mm := middleware.NewMetrics()

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	//exhaustruct:enforce
	res := setup.Setup(ctx, &setup.SetupOpts{
		Logger:        logger,
		StateProvider: stateProvider,
		Metrics:       mm,

		PostgreSQLURL:          cli.PostgreSQLURL,
		Auth:                   cli.Auth,
		ReplSetName:            cli.Dev.ReplSetName,
		SessionCleanupInterval: 0,

		// Replay does not accept network connections.
		TCPAddr:  "",
		UnixAddr: "",
		TLSAddr:  "",

		Mode: middleware.NormalMode,

		DataAPIAddr: "",
		MCPAddr:     "",
	})
	if res == nil {
		os.Exit(1)
	}

	report, err := res.ReplayTranscript(ctx, cli.Replay.Path, &wiretranscript.ReplayOpts{
		SkipAuth: cli.Replay.SkipAuth,
		Logger:   logger,
	})
	if report != nil {
		printReport(report)
	}

	if err != nil {
		logger.Error("Transcript replay failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.Info("Transcript replay succeeded")
}

// printReport writes a human-readable replay report to stdout.
func printReport(report *wiretranscript.Report) {
	var b strings.Builder

	fmt.Fprintf(&b, "transcript: %s\n", report.Path)
	fmt.Fprintf(&b, "complete:   %t\n", report.Complete)
	fmt.Fprintf(&b, "end reason: %s\n", report.EndReason)
	fmt.Fprintf(&b, "handler calls: %d\n", report.HandlerCalls)

	if len(report.MaskedComparisons) > 0 {
		fmt.Fprintf(&b, "masked comparisons: %s\n", strings.Join(report.MaskedComparisons, ", "))
	}

	b.WriteString("frames:\n")

	for _, r := range report.Results {
		fmt.Fprintf(&b, "  %6d  %s\n", r.Seq, r.Status)

		if r.Detail != "" {
			fmt.Fprintf(&b, "          %s\n", r.Detail)
		}

		if r.Diff != "" {
			b.WriteString(indent(r.Diff, "          "))
			b.WriteByte('\n')
		}
	}

	fmt.Fprint(os.Stdout, b.String())
}

// indent prefixes every line of s with the given prefix.
func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}

	return strings.Join(lines, "\n")
}
