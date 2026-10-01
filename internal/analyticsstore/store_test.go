package analyticsstore

import (
	"testing"
	"time"
)

func TestCanonicalizeIPUnmapsIPv4MappedIPv6(t *testing.T) {
	v, err := canonicalizeIP("::ffff:1.2.3.4")
	if err != nil {
		t.Fatalf("canonicalizeIP: %v", err)
	}
	if v != "1.2.3.4" {
		t.Fatalf("got %q, want 1.2.3.4", v)
	}
}

func TestCanonicalizeIPRejectsNonAddress(t *testing.T) {
	_, err := canonicalizeIP("not-an-ip")
	if err == nil {
		t.Fatalf("expected an error for a non-address literal")
	}
}

func TestOptionalIPEmpty(t *testing.T) {
	v, err := optionalIP("")
	if err != nil {
		t.Fatalf("optionalIP empty: %v", err)
	}
	if v != "" {
		t.Fatalf("expected empty string, got %q", v)
	}
}

func TestOptionalIPCanonicalizes(t *testing.T) {
	v, err := optionalIP("::ffff:10.0.0.1")
	if err != nil {
		t.Fatalf("optionalIP: %v", err)
	}
	if v != "10.0.0.1" {
		t.Fatalf("got %q, want 10.0.0.1", v)
	}
}

func TestBucketOf(t *testing.T) {
	mid := time.Date(2026, 10, 1, 0, 1, 37, 123456789, time.UTC)
	b := bucketOf(mid, time.Minute)
	want := time.Date(2026, 10, 1, 0, 1, 0, 0, time.UTC)
	if !b.Equal(want) {
		t.Fatalf("bucketOf(%s,1m) = %s, want %s", mid, b, want)
	}
	if b := bucketOf(mid, 0); !b.Equal(mid) {
		t.Fatalf("bucketOf with zero width should return the input")
	}
}

func TestRouteKeyForHostOnly(t *testing.T) {
	k := RouteKeyFor("proxy.example:1080", "v4", "manual")
	if k.Host != "proxy.example:1080" {
		t.Fatalf("host = %q", k.Host)
	}
	if k.Kind != "v4" {
		t.Fatalf("kind = %q", k.Kind)
	}
	if k.Origin != "manual" {
		t.Fatalf("origin = %q", k.Origin)
	}
}

func TestEventIDIsZero(t *testing.T) {
	var id EventID
	if !id.IsZero() {
		t.Fatalf("zero EventID must be zero")
	}
	id = EventID("a-test-id")
	if id.IsZero() {
		t.Fatalf("non-zero EventID must not be zero")
	}
	if id.String() != "a-test-id" {
		t.Fatalf("String mismatch")
	}
}

func TestRotationAttemptDurationClamped(t *testing.T) {
	start := time.Now()
	a := RotationAttempt{StartedAt: start, EndedAt: start.Add(-time.Millisecond)}
	if d := a.Duration(); d != 0 {
		t.Fatalf("duration = %s, want 0", d)
	}
	a.EndedAt = start.Add(1500 * time.Millisecond)
	if d := a.Duration(); d != 1500*time.Millisecond {
		t.Fatalf("duration = %s, want 1500ms", d)
	}
}
