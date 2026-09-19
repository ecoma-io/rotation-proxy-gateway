package sanitize

import "testing"

// sinkString keeps benchmark results alive so the compiler cannot fold the
// calls away.
var sinkString string

func BenchmarkSanitizeClean(b *testing.B) {
	const clean = "dial socks endpoint proxy.test:1080: connect: connection refused"
	b.ReportAllocs()
	for b.Loop() {
		sinkString = Sanitize(clean)
	}
}

// An '@' without the user:pass shape before it (an email address) must stay
// on the zero-allocation clean path.
func BenchmarkSanitizeEmailClean(b *testing.B) {
	const clean = "owner contact alice@example.com for socks endpoint proxy.test:1080"
	b.ReportAllocs()
	for b.Loop() {
		sinkString = Sanitize(clean)
	}
}

func BenchmarkSanitizeBareRedact(b *testing.B) {
	// Credentials here are fake TEST fixtures.
	const dirty = "invalid proxy user:pass@proxy.test:1080: connect: refused"
	b.ReportAllocs()
	for b.Loop() {
		sinkString = Sanitize(dirty)
	}
}

func BenchmarkSanitizeRedact(b *testing.B) {
	// Credentials here are fake TEST fixtures.
	const dirty = "dial socks5://user:pass@proxy.test:1080: connect: refused"
	b.ReportAllocs()
	for b.Loop() {
		sinkString = Sanitize(dirty)
	}
}
