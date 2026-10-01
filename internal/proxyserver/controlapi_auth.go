package proxyserver

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// The control API's authentication boundary.
//
// The control surface can commit a cluster-wide configuration revision, so it
// is the one part of the admin listener an operator must be able to lock down.
// It authenticates with an opaque bearer token presented as
// `Authorization: Bearer <token>` and refuses everything else.
//
// Three deliberate properties:
//
//   - The token is compared as an HMAC-SHA256 digest under the same
//     process-wide random key the inbound Basic account uses (credentialDigest
//     in server.go). The token itself is never retained on the authenticator
//     and never logged, so a dump of the process's admin state says nothing
//     brute-forceable about it.
//   - A presented token longer than maxPresentedTokenBytes is rejected before
//     it is hashed. The digest is fixed-length, so hashing an unbounded
//     attacker-chosen string would let one unauthenticated request make this
//     process hash arbitrary megabytes; the bound keeps the work a fixed cost.
//   - Exactly one Authorization header is accepted. With two, an intermediary
//     or a confused client could get this process to authenticate against one
//     constraint while another layer validated the other, so the ambiguity is
//     refused rather than resolved by picking one.
//
// 401, not 407. 407 Proxy Authentication Required is reserved for the proxy
// listeners' `Proxy-Authorization` credential (RFC 9110 §11.7.1); reusing it
// here would make a client that answers 407 by asking for a proxy password
// look correct while never having reached the control API. The bearer realm
// names this product so a client knows which credential to present.

// maxPresentedTokenBytes bounds one presented bearer token before any hashing.
// It is well above any real operator token and far below the inbound 1 MiB
// header bound, so the digest a request can force this process to compute is
// bounded by the header a request can send.
const maxPresentedTokenBytes = 512

// BearerChallenge names the credential the control API challenges for. One
// fixed realm string, matching the proxy listeners' Basic realm, so an operator
// sees one product name in every challenge.
//
// It is exported because writing the challenge is the HTTP layer's job, not the
// authenticator's: this package owns the credential, and the surface that
// mounts it owns the response.
const BearerChallenge = `Bearer realm="rotation-proxy-gateway"`

// ControlAuthenticator verifies the bearer token required by the control API.
//
// A nil *ControlAuthenticator refuses every request. That is the fail-closed
// direction on purpose: a zero value cannot accidentally authenticate, and a
// control surface mounted with no token configured is refused at startup
// rather than served unauthenticated.
type ControlAuthenticator struct {
	tokenSum [credentialDigestSize]byte
}

// NewControlAuthenticator reduces an operator-configured token to its digest
// form. The configured string is not retained, so the caller may discard it
// (and the bootstrap configuration holding it) immediately.
//
// The token must be non-empty. A caller that has one returns nil rather than an
// error so the mount decision stays at the call site, where the fail-closed
// refusal is written.
func NewControlAuthenticator(token string) *ControlAuthenticator {
	if token == "" {
		return nil
	}
	return &ControlAuthenticator{tokenSum: credentialDigest([]byte(token))}
}

// Authorized reports whether r carries the configured bearer token.
//
// The presented value is digest-then-compare, never compare-then-digest, so the
// comparison is over two fixed-length digests and depends on neither the token's
// length nor on how many leading bytes happened to match.
func (a *ControlAuthenticator) Authorized(r *http.Request) bool {
	if a == nil {
		return false
	}
	presented, ok := bearerToken(r.Header)
	if !ok {
		return false
	}
	presentedSum := credentialDigest([]byte(presented))
	return subtle.ConstantTimeCompare(presentedSum[:], a.tokenSum[:]) == 1
}

// AcceptedRequestID returns a client-supplied correlation id that is safe to
// echo, or reports that there is none.
//
// It exists so the control API accepts `x-ecoma-request-id` under exactly the
// rules the proxy listeners apply — bounded, inside the token alphabet, single
// occurrence — without duplicating the grammar here. The proxy path mints a
// replacement rather than refusing a mismeasured id, because a request is still
// perfectly serviceable when only its diagnostic header is bad. That is right on
// the proxy path and wrong for an admin call: an operator who sent an id this
// process will not echo deserves to know, and the admin listener's own access
// log already carries the id for correlating. So this reports absence, and the
// caller decides. An invalid id is never echoed as-is.
//
// The header is consumed here, not forwarded: nothing in the admin surface
// proxies a request, but a control handler that later grew an outbound call must
// not inherit a client's control namespace by default.
func AcceptedRequestID(header http.Header) (string, bool) {
	values := header.Values(headerRequestID)
	if len(values) != 1 {
		return "", false
	}
	supplied := values[0]
	if len(supplied) == 0 || len(supplied) > maxInboundRequestIDLength || !isRequestIDToken(supplied) {
		return "", false
	}
	return supplied, true
}

// bearerToken extracts the one presented bearer token, or reports that the
// request does not present an acceptable one.
//
// Absent, repeated, non-Bearer, empty, whitespace-bearing, and over-long are
// all refusals, and none of them is distinguished in the response: every one
// answers the same 401 with the same challenge, so an unauthenticated caller
// cannot probe which spelling was "almost right".
func bearerToken(header http.Header) (string, bool) {
	values := header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, encoded, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || encoded == "" || strings.ContainsAny(encoded, " \t") {
		return "", false
	}
	// Bound before the digest: the hash is fixed-length, so its own cost says
	// nothing about the input's size. This check is what stops an
	// unauthenticated caller from making this process hash an arbitrarily large
	// string on a request that could never match.
	if len(encoded) > maxPresentedTokenBytes {
		return "", false
	}
	return encoded, true
}
