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
	return bound(cleanControls(redactUserinfo(s)))
}

// ErrorString sanitizes err.Error(), returning "" for nil.
func ErrorString(err error) string {
	if err == nil {
		return ""
	}
	return Sanitize(err.Error())
}

// redactUserinfo replaces scheme://userinfo@ with scheme://[redacted]@.
// It uses the last '@' within the URL token so synthetic passwords
// containing '/', '?', or '@' are still fully redacted while the
// host:port identity after the final '@' is preserved.
func redactUserinfo(value string) string {
	for searchFrom := 0; ; {
		idx := strings.Index(value[searchFrom:], "://")
		if idx < 0 {
			return value
		}
		schemeAt := searchFrom + idx
		userinfoStart := schemeAt + len("://")
		tokenEnd := tokenEndIndex(value, userinfoStart)
		token := value[userinfoStart:tokenEnd]
		at := strings.LastIndexByte(token, '@')
		if at < 0 {
			searchFrom = tokenEnd
			if searchFrom >= len(value) {
				return value
			}
			continue
		}
		at += userinfoStart
		value = value[:userinfoStart] + redacted + value[at+1:]
		searchFrom = userinfoStart + len(redacted)
	}
}

func tokenEndIndex(s string, from int) int {
	for i := from; i < len(s); {
		c := s[i]
		// End tokens on whitespace, controls, quotes, angle brackets, backtick.
		if c <= 0x20 || c == 0x7f || c == '"' || c == '\'' || c == '<' || c == '>' || c == '`' || c == 0x1b {
			return i
		}
		i++
	}
	return len(s)
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
