package reporter

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// InitLogger configures the global slog logger with the requested level and format.
func InitLogger(level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(handler))
}

// Log emits a structured log entry with optional extra key-value pairs.
func Log(ctx context.Context, level slog.Level, component, action, resourceID, detail string, extras ...any) {
	args := []any{
		"component", component,
		"action", action,
		"resource_id", resourceID,
		"detail", detail,
	}
	args = append(args, extras...)
	slog.Log(ctx, level, action, args...)
}
