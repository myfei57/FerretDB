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

package setup

import (
	"context"
	"errors"
	"fmt"

	"github.com/FerretDB/FerretDB/v2/internal/handler/middleware"
	"github.com/FerretDB/FerretDB/v2/internal/wiretranscript"
)

// ReplayTranscript opens the given transcript file (or all transcript files found
// recursively in a directory) and replays them through the real middleware handler,
// never returning recorded answers. The transport in opts is always overridden.
func (sr *SetupResult) ReplayTranscript(
	ctx context.Context, path string, opts *wiretranscript.ReplayOpts,
) (*wiretranscript.Report, error) {
	files, err := wiretranscript.FindFiles(path)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no transcript files found in %q", path)
	}

	if opts == nil {
		opts = new(wiretranscript.ReplayOpts)
	}

	combined := &wiretranscript.Report{
		Path:     path,
		Complete: true,
	}

	var errs []error

	for _, file := range files {
		t, err := wiretranscript.Open(file)
		if err != nil && t == nil {
			errs = append(errs, fmt.Errorf("%s: %w", file, err))
			continue
		}

		fileOpts := *opts
		fileOpts.Transport = func(ctx context.Context, req *middleware.Request) (*middleware.Response, error) {
			return sr.m.Handle(ctx, req), nil
		}

		report, replayErr := wiretranscript.Replay(ctx, t, &fileOpts)

		if report != nil {
			combined.Results = append(combined.Results, report.Results...)
			combined.HandlerCalls += report.HandlerCalls
			combined.MaskedComparisons = append(combined.MaskedComparisons, report.MaskedComparisons...)
			combined.Complete = combined.Complete && report.Complete
			combined.EndReason = report.EndReason
		}

		if replayErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", file, replayErr))
		}
	}

	return combined, errors.Join(errs...)
}
