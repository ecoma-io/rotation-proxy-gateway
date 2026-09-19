// Package sanitize provides shared safe-diagnostics helpers for pool
// snapshots, admin /status, and request logs. It redacts URL userinfo,
// neutralizes terminal controls and ANSI sequences, and bounds output.
// Zero dependencies beyond the standard library.
package sanitize

import (
	"strings"
	"unicode/utf8"
)

// MaxLength bounds sanitized diagnostic text in runes before the ellipsis.
const MaxLength = 512

const redacted = "[redacted]@"

// Sanitize returns bounded diagnostic text with URL userinfo redacted and
// terminal controls and ANSI sequences neutralized.
func Sanitize(s string) string {
	if !needsSanitizing(s) {
		return s
	}
	return bound(cleanControls(redactUserinfo(s)))
}

// needsSanitizing reports whether any stage of Sanitize would change s, so the
// clean common case skips every intermediate string copy. The control scan is
// byte-wise on purpose: multi-byte UTF-8 sequences never contain bytes below
// 0x20 or 0x7f, and every control rune encodes as one such byte.
func needsSanitizing(s string) bool {
	if len(s) > MaxLength {
		return true // bound() truncates
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return true // stripANSI consumes ESC; cleanControls rewrites controls
		}
	}
	if strings.Contains(s, "://") {
		return true // a scheme token may carry userinfo
	}
	// Bare userinfo: only the user:pass@ shape matters, approximated here by
	// any '@' with a ':' somewhere before it; redactUserinfo decides per token.
	at := strings.LastIndexByte(s, '@')
	return at >= 0 && strings.IndexByte(s[:at], ':') >= 0
}

// ErrorString sanitizes err.Error(), returning "" for nil.
func ErrorString(err error) string {
	if err == nil {
		return ""
	}
	return Sanitize(err.Error())
}

// redactUserinfo replaces scheme://userinfo@ and bare user:pass@ with
// [redacted]@, preserving the host:port identity after the final '@' so
// synthetic passwords containing '/', '?', or '@' are still fully redacted.
// Bare tokens redact only when the segment before their '@' carries ':', the
// user:pass shape accepted in configuration, leaving mentions like an email
// address untouched.
func redactUserinfo(value string) string {
	if !strings.Contains(value, "://") {
		if at := strings.LastIndexByte(value, '@'); at < 0 || strings.IndexByte(value[:at], ':') < 0 {
			return value
		}
	}
	var b strings.Builder
	b.Grow(len(value))
	for i := 0; i < len(value); {
		if isTokenBoundary(value[i]) {
			b.WriteByte(value[i])
			i++
			continue
		}
		start := i
		for i < len(value) && !isTokenBoundary(value[i]) {
			i++
		}
		b.WriteString(redactToken(value[start:i]))
	}
	return b.String()
}

// redactToken redacts the userinfo of one boundary-delimited token, if any.
func redactToken(token string) string {
	if scheme := strings.Index(token, "://"); scheme >= 0 {
		rest := token[scheme+len("://"):]
		if at := strings.LastIndexByte(rest, '@'); at >= 0 {
			return token[:scheme+len("://")] + redacted + rest[at+1:]
		}
		return token
	}
	if at := strings.LastIndexByte(token, '@'); at > 0 && strings.IndexByte(token[:at], ':') >= 0 {
		return redacted + token[at+1:]
	}
	return token
}

// isTokenBoundary reports whether c ends a diagnostic token: whitespace,
// controls, quotes, angle brackets, or backtick.
func isTokenBoundary(c byte) bool {
	return c <= 0x20 || c == 0x7f || c == '"' || c == '\'' || c == '<' || c == '>' || c == '`'
}

// cleanControls strips ANSI escape sequences and neutralizes remaining
// terminal controls. Newlines, carriage returns, and tabs become a single
// space so diagnostics stay single-line; other C0 controls, DEL, and ESC
// remnants are removed.
func cleanControls(value string) string {
	// Strip common ANSI sequences first so "[31m" remnants do not survive.
	value = stripANSI(value)
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r == 0x1b:
			// Drop any surviving ESC.
			continue
		case r < 0x20 || r == 0x7f:
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != 0x1b {
			b.WriteByte(s[i])
			i++
			continue
		}
		// ESC found: consume sequence.
		i++ // skip ESC
		if i >= len(s) {
			break
		}
		switch s[i] {
		case '[':
			// CSI: ESC [ params intermediates final(@-~).
			i++
			for i < len(s) {
				c := s[i]
				i++
				if c >= 0x40 && c <= 0x7e {
					break
				}
			}
		case ']':
			// OSC: ESC ] ... BEL or ESC \.
			i++
			for i < len(s) {
				if s[i] == 0x07 {
					i++
					break
				}
				if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
					i += 2
					break
				}
				i++
			}
		case '(', ')', '#':
			// Two-byte sequences.
			i++
			if i < len(s) {
				i++
			}
		default:
			// Single-char sequence: drop the designator.
			i++
		}
	}
	return b.String()
}

func bound(value string) string {
	if utf8.RuneCountInString(value) <= MaxLength {
		return value
	}
	return string([]rune(value)[:MaxLength]) + "…"
}
