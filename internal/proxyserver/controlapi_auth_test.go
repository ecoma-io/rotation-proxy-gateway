package proxyserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testControlToken = "control-token-for-tests"

// withBearer builds a request presenting exactly one well-formed bearer header.
func withBearer(token string) *http.Request {
	return withBearerRaw("Bearer " + token)
}

// withBearerRaw builds a request presenting exactly one Authorization header
// with the given value, so a test can present a header this package's parser
// must refuse.
func withBearerRaw(value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/control/proxies", nil)
	r.Header.Set("Authorization", value)
	return r
}

// Every refusal answers 401 with the same challenge and the same body. A caller
// that can tell "malformed" from "wrong" can probe the token one spelling at a
// time, so the table below asserts the responses are indistinguishable and not
// merely unsuccessful.
func TestControlAuthenticatorRefusals(t *testing.T) {
	auth := NewControlAuthenticator(testControlToken)

	repeat := httptest.NewRequest(http.MethodGet, "/control/proxies", nil)
	repeat.Header.Add("Authorization", "Bearer "+testControlToken)
	repeat.Header.Add("Authorization", "Bearer "+testControlToken)

	overlong := httptest.NewRequest(http.MethodGet, "/control/proxies", nil)
	overlong.Header.Set("Authorization", "Bearer "+strings.Repeat("a", maxPresentedTokenBytes+1))

	whitespace := httptest.NewRequest(http.MethodGet, "/control/proxies", nil)
	whitespace.Header.Set("Authorization", "Bearer "+testControlToken+" extra")

	for name, r := range map[string]*http.Request{
		"no Authorization header":     httptest.NewRequest(http.MethodGet, "/control/proxies", nil),
		"empty header value":          withBearer(""),
		"no scheme":                   withBearerRaw(testControlToken),
		"wrong scheme":                withBearerRaw("Basic " + testControlToken),
		"empty bearer value":          withBearerRaw("Bearer "),
		"trailing whitespace":         whitespace,
		"repeated header":             repeat,
		"over-long token":             overlong,
		"wrong token":                 withBearer("not-the-token"),
		"token differing in one byte": withBearer("control-token-for-tesu"),
		"token differing in length":   withBearer(testControlToken + "x"),
		"token case-shifted":          withBearer(strings.ToUpper(testControlToken)),
	} {
		if auth.Authorized(r) {
			t.Errorf("%s: Authorized = true, want false", name)
		}
	}
}

// A nil authenticator — what a control surface mounted with no configured token
// gets — must refuse. This is the second lock on the fail-closed door, and it is
// the one that holds if a future mount site forgets the startup check.
func TestNilControlAuthenticatorRefusesEverything(t *testing.T) {
	var auth *ControlAuthenticator
	if auth.Authorized(withBearer(testControlToken)) {
		t.Error("a nil authenticator authorized a request")
	}
	if got := NewControlAuthenticator(""); got != nil {
		t.Error("an empty token produced an authenticator rather than nil")
	}
}

func TestControlAuthenticatorAcceptsTheConfiguredToken(t *testing.T) {
	auth := NewControlAuthenticator(testControlToken)
	for name, r := range map[string]*http.Request{
		"exact token":  withBearer(testControlToken),
		"lowercase b":  withBearerRaw("bearer " + testControlToken),
		"uppercase b":  withBearerRaw("BEARER " + testControlToken),
		"mixed scheme": withBearerRaw("BeArEr " + testControlToken),
	} {
		if !auth.Authorized(r) {
			t.Errorf("%s: Authorized = false, want true", name)
		}
	}
}

// The over-long token must be refused before it is hashed.
//
// The digest is fixed-length, so hashing an unbounded attacker-chosen string
// would let one unauthenticated request make this process hash arbitrary
// megabytes; the bound is what keeps the work a fixed cost. The bound is
// observable through the authenticator's own behavior only, so the test asserts
// the boundary itself: exactly at the limit is accepted, one byte over is not.
func TestOverLongTokenIsRefusedAtTheBoundary(t *testing.T) {
	// A token whose digest is known to this test, at exactly the limit.
	limit := strings.Repeat("z", maxPresentedTokenBytes)
	auth := NewControlAuthenticator(limit)

	if !auth.Authorized(withBearer(limit)) {
		t.Fatal("a token of exactly the maximum length was refused")
	}
	if auth.Authorized(withBearer(limit + "z")) {
		t.Error("a token one byte over the maximum length was accepted")
	}
}

// A repeated Authorization header is refused rather than resolved.
//
// With two headers this process could authenticate against one while another
// layer validated the other, so the ambiguity is a refusal. Both an identical
// pair and a correct/incorrect pair must fail: the second is the attack the
// first is a proxy for.
func TestRepeatedAuthorizationHeaderIsRefused(t *testing.T) {
	auth := NewControlAuthenticator(testControlToken)
	for name, values := range map[string][]string{
		"identical pair":  {"Bearer " + testControlToken, "Bearer " + testControlToken},
		"correct/garbage": {"Bearer " + testControlToken, "Bearer wrong"},
		"empty/correct":   {"", "Bearer " + testControlToken},
		"triple":          {"Bearer " + testControlToken, "Bearer " + testControlToken, "Bearer " + testControlToken},
	} {
		r := httptest.NewRequest(http.MethodGet, "/control/proxies", nil)
		// Add, never Set: an empty value still has to arrive as a second
		// occurrence for this to be the repeated-header case at all.
		for _, v := range values {
			r.Header.Add("Authorization", v)
		}
		if auth.Authorized(r) {
			t.Errorf("%s: Authorized = true, want false", name)
		}
	}
}

// The 401 must carry the bearer challenge, and it must be 401 rather than 407:
// 407 is the proxy listeners' Proxy-Authorization vocabulary, and a client that
// answers 407 by asking for a proxy password would look correct while never
// having reached the control API.
func TestControlChallengeIsBearer401NotProxyAuth(t *testing.T) {
	rec := httptest.NewRecorder()
	challenge := BearerChallenge
	if challenge != `Bearer realm="rotation-proxy-gateway"` {
		t.Fatalf("BearerChallenge = %q", challenge)
	}
	if http.StatusUnauthorized != 401 || http.StatusProxyAuthRequired != 407 {
		t.Fatal("the status constants this test distinguishes are not the ones in use")
	}
	rec.Header().Set("WWW-Authenticate", challenge)
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="rotation-proxy-gateway"` {
		t.Errorf("WWW-Authenticate = %q", got)
	}
	// The proxy listeners keep their own challenge; the two must never be the
	// same string, or a client could not tell which credential it owes.
	if BearerChallenge == `Basic realm="rotation-proxy-gateway"` {
		t.Error("the bearer challenge collides with the proxy listeners' Basic realm")
	}
}

// AcceptedRequestID applies the proxy listeners' grammar without minting: an id
// this process will not echo is reported absent, not replaced, because the admin
// listener's own log already carries a usable id for the request.
func TestAcceptedRequestID(t *testing.T) {
	for name, tc := range map[string]struct {
		values []string
		want   string
		ok     bool
	}{
		"absent":         {nil, "", false},
		"accepted":       {[]string{"abc-123_x.y:z"}, "abc-123_x.y:z", true},
		"empty":          {[]string{""}, "", false},
		"repeated":       {[]string{"a", "b"}, "", false},
		"quoted":         {[]string{`"abc"`}, "", false},
		"control byte":   {[]string{"abc\ndef"}, "", false},
		"ansi":           {[]string{"abc\x1b[31m"}, "", false},
		"at the bound":   {[]string{strings.Repeat("a", maxInboundRequestIDLength)}, strings.Repeat("a", maxInboundRequestIDLength), true},
		"over the bound": {[]string{strings.Repeat("a", maxInboundRequestIDLength+1)}, "", false},
	} {
		h := http.Header{}
		for _, v := range tc.values {
			h.Add(headerRequestID, v)
		}
		got, ok := AcceptedRequestID(h)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: AcceptedRequestID = (%q, %t), want (%q, %t)", name, got, ok, tc.want, tc.ok)
		}
	}
}
