/*
 * Copyright 2025 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package logging

import (
	"fmt"
	"log/slog"
)

// LevelTrace is a custom slog level below Debug, following the convention of slog.Level(-8).
const LevelTrace = slog.Level(-8)

// ParseLevel converts a level name string to a slog.Level.
// Accepted values: trace, debug, info, warn, error.
func ParseLevel(s string) (slog.Level, error) {
	switch s {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q, accepted: trace, debug, info, warn, error", s)
	}
}
