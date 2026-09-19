// Package logging centralizes zerolog construction so every logger in the
// process — production and tests — renders identical JSON field names. The
// runtime log level lives in zerolog's package-global atomic level
// (SetGlobalLevel): only the config-reload goroutine writes it, and every
// event checks it at emit time, which is what makes log-level hot reload work
// without touching handler state.
package logging

import (
	"io"

	"github.com/rs/zerolog"
)

func init() {
	zerolog.MessageFieldName = "msg"
	zerolog.LevelFieldName = "level"
	zerolog.TimestampFieldName = "time"
}

// New returns a JSON logger writing one object per line to w. What it emits
// is gated by the process-global level.
func New(w io.Writer) zerolog.Logger {
	return zerolog.New(w).With().Timestamp().Logger()
}

// Nop returns a logger that discards every event.
func Nop() zerolog.Logger {
	return zerolog.Nop()
}
