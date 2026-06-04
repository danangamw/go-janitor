package reporter

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// CleanTextHandler is a custom slog handler for pretty console formatting
type CleanTextHandler struct {
	level slog.Level
}

func (h *CleanTextHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *CleanTextHandler) Handle(_ context.Context, r slog.Record) error {
	timeStr := r.Time.Format("15:04:05")

	var levelStr string
	switch r.Level {
	case slog.LevelDebug:
		levelStr = "\033[1;30mDEBUG\033[0m" // Gray
	case slog.LevelInfo:
		levelStr = "\033[1;36mINFO \033[0m" // Cyan
	case slog.LevelWarn:
		levelStr = "\033[1;33mWARN \033[0m" // Yellow
	case slog.LevelError:
		levelStr = "\033[1;31mERROR\033[0m" // Red
	default:
		levelStr = r.Level.String()
	}

	msg := r.Message

	var attrs []string
	r.Attrs(func(a slog.Attr) bool {
		// Skip internal logging keys to keep progress log clean
		if a.Key == "component" || a.Key == "action" {
			return true
		}
		attrs = append(attrs, fmt.Sprintf("%s=%v", a.Key, a.Value.Any()))
		return true
	})

	attrStr := ""
	if len(attrs) > 0 {
		attrStr = " \033[3m(" + strings.Join(attrs, ", ") + ")\033[0m"
	}

	fmt.Fprintf(os.Stderr, "%s %s %s%s\n", timeStr, levelStr, msg, attrStr)
	return nil
}

func (h *CleanTextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *CleanTextHandler) WithGroup(name string) slog.Handler {
	return h
}

// InitLogger configures the global slog logger with the requested level and format.
func InitLogger(level string, format string) {
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

	var handler slog.Handler
	if strings.ToLower(format) == "json" {
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	} else {
		handler = &CleanTextHandler{level: lvl}
	}

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
