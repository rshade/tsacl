package main

import (
	"context"
	"io"
	"log/slog"

	"github.com/rs/zerolog"
	"github.com/rshade/ax-go"

	"github.com/rshade/tsacl/pkg/policycore/sanitize"
)

// axLogHandler forwards slog records to an ax-go logger, so every log line is
// zerolog JSON carrying trace correlation, while call sites keep using slog.
type axLogHandler struct {
	logger    ax.Logger
	level     slog.Level
	sanitizer *sanitize.Sanitizer
	prefix    string
	attrs     []slog.Attr
}

// newLogger builds a logger that writes ax-go JSON lines to w.
func newLogger(w io.Writer, verbose bool, sanitizer *sanitize.Sanitizer) *slog.Logger {
	return newLoggerOn(newAxLogger(context.Background(), w), verbose, sanitizer)
}

func newAxLogger(ctx context.Context, w io.Writer) ax.Logger {
	return ax.NewLogger(ctx, ax.WithLoggerWriter(w), ax.WithLoggerLevel(zerolog.DebugLevel))
}

func newLoggerOn(logger ax.Logger, verbose bool, sanitizer *sanitize.Sanitizer) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(&axLogHandler{logger: logger, level: level, sanitizer: sanitizer})
}

func (h *axLogHandler) Enabled(_ context.Context, level slog.Level) bool { return level >= h.level }

func (h *axLogHandler) Handle(ctx context.Context, record slog.Record) error {
	event := h.event(ctx, record.Level)
	if event == nil {
		return nil
	}
	for _, attr := range h.attrs {
		h.add(event, h.prefix, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		h.add(event, h.prefix, attr)
		return true
	})
	event.Msg(h.scrub(record.Message))
	return nil
}

func (h *axLogHandler) event(ctx context.Context, level slog.Level) *zerolog.Event {
	switch {
	case level >= slog.LevelError:
		return h.logger.Error(ctx)
	case level >= slog.LevelWarn:
		return h.logger.Warn(ctx)
	case level >= slog.LevelInfo:
		return h.logger.Info(ctx)
	default:
		return h.logger.Debug(ctx)
	}
}

func (h *axLogHandler) add(event *zerolog.Event, prefix string, attr slog.Attr) {
	value := attr.Value.Resolve()
	key := prefix + attr.Key
	switch value.Kind() {
	case slog.KindGroup:
		for _, nested := range value.Group() {
			h.add(event, key+".", nested)
		}
	case slog.KindString:
		event.Str(key, h.scrub(value.String()))
	case slog.KindInt64:
		event.Int64(key, value.Int64())
	case slog.KindUint64:
		event.Uint64(key, value.Uint64())
	case slog.KindBool:
		event.Bool(key, value.Bool())
	case slog.KindDuration:
		event.Dur(key, value.Duration())
	case slog.KindAny:
		if err, ok := value.Any().(error); ok {
			event.Str(key, h.scrub(err.Error()))
			return
		}
		event.Str(key, h.scrub(value.String()))
	case slog.KindFloat64, slog.KindTime, slog.KindLogValuer:
		event.Str(key, h.scrub(value.String()))
	}
}

func (h *axLogHandler) scrub(text string) string {
	if h.sanitizer == nil || h.sanitizer.Level() == sanitize.Off {
		return text
	}
	return scrubText(h.sanitizer, text)
}

func (h *axLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &clone
}

func (h *axLogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.prefix = h.prefix + name + "."
	return &clone
}
