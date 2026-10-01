package proxyserver

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/pool"
)

var testAccount = newInboundAccount([]byte("gw-user"), []byte("gw-pass"))

// proxyAuthorization renders the Proxy-Authorization field an armed listener
// demands. The empty-value form is deliberately reachable: a client may present
// no field at all, which is the case a no-auth client exercises.
func proxyAuthorization(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// checkProxyAuthorization is the pure verdict behind the 407: it decodes before
// comparing, keeps the configured field bounds for untrusted input, and accepts
// exactly the one header value a conforming client sends.
func TestCheckProxyAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name    string
		account *inboundAccount // nil runs against testAccount
		// values is the exact Proxy-Authorization field list to present. More
		// than one value is ambiguous and must be refused even when one of them
		// is correct.
		values    []string
		wantAllow bool
	}{
		{name: "correct pair", values: []string{proxyAuthorization("gw-user", "gw-pass")}, wantAllow: true},
		{name: "wrong password", values: []string{proxyAuthorization("gw-user", "other")}},
		{name: "wrong username", values: []string{proxyAuthorization("other", "gw-pass")}},
		{name: "both wrong", values: []string{proxyAuthorization("other", "other")}},
		{name: "no header at all"},
		{name: "empty header value", values: []string{""}},
		{name: "lowercase scheme", values: []string{strings.Replace(proxyAuthorization("gw-user", "gw-pass"), "Basic", "basic", 1)}, wantAllow: true},
		{name: "mixed-case scheme", values: []string{strings.Replace(proxyAuthorization("gw-user", "gw-pass"), "Basic", "bAsIc", 1)}, wantAllow: true},
		{name: "wrong scheme", values: []string{"Bearer Z3ctdXNlcjpnd3ctcGFzcw=="}},
		{name: "scheme with no credentials", values: []string{"Basic"}},
		{name: "trailing space after scheme", values: []string{"Basic Z3ctdXNlcjpnd3ctcGFzcw== "}},
		{name: "credentials with an embedded space", values: []string{"Basic Z3ctdXNlcjpn dy"}},
		{name: "base64 without a colon", values: []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("gw-user"))}},
		{name: "empty username", values: []string{proxyAuthorization("", "gw-pass")}},
		{name: "empty password", values: []string{proxyAuthorization("gw-user", "")}},
		{name: "username above the field bound", values: []string{proxyAuthorization(strings.Repeat("u", 256), "gw-pass")}},
		{name: "password above the field bound", values: []string{proxyAuthorization("gw-user", strings.Repeat("p", 256))}},
		{name: "not base64", values: []string{"Basic !!!not-base64!!!"}},
		{name: "two header values, one correct", values: []string{
			proxyAuthorization("gw-user", "gw-pass"), proxyAuthorization("gw-user", "gw-pass")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodConnect, "http://example.test:443", nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range tc.values {
				req.Header.Add("Proxy-Authorization", value)
			}
			account := tc.account
			if account == nil {
				account = testAccount
			}
			if got := checkProxyAuthorization(req, account); got != tc.wantAllow {
				t.Fatalf("checkProxyAuthorization(%v) = %v, want %v", tc.values, got, tc.wantAllow)
			}
		})
	}
}

// An unarmed listener is a historical unauthenticated deployment: the ingress
// must accept any request, including one that presents a credential the gateway
// was never configured with.
func TestCheckProxyAuthorizationNilAccountAcceptsEverything(t *testing.T) {
	for _, values := range [][]string{
		nil,
		{""},
		{"Bearer whatever"},
		{proxyAuthorization("gw-user", "gw-pass")},
	} {
		req, err := http.NewRequest(http.MethodConnect, "http://example.test:443", nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range values {
			req.Header.Add("Proxy-Authorization", value)
		}
		if !checkProxyAuthorization(req, nil) {
			t.Fatalf("checkProxyAuthorization(%v) on an unarmed listener = false, want true", values)
		}
	}
}

// credentialsMatch is the pure comparison behind the Basic exchange: both
// presented fields are digested to a fixed length and both constant-time
// comparisons run before the combined result exists.
func TestCredentialsMatch(t *testing.T) {
	defaultAccount := newInboundAccount([]byte("gw-user"), []byte("gw-pass"))
	for _, tc := range []struct {
		name     string
		account  *inboundAccount // nil runs against the default account
		username string
		password string
		want     bool
	}{
		{name: "correct pair", username: "gw-user", password: "gw-pass", want: true},
		{name: "wrong username only", username: "gw-use", password: "gw-pass", want: false},
		{name: "wrong password only", username: "gw-user", password: "gw_pas", want: false},
		{name: "both wrong", username: "other", password: "other", want: false},
		{name: "username shorter", username: "gw", password: "gw-pass", want: false},
		{name: "username empty", username: "", password: "gw-pass", want: false},
		// The length-leak case: a 255-byte presented username must fail exactly
		// like any other mismatch, never along a different code path.
		{name: "username much longer", username: strings.Repeat("u", 255), password: "gw-pass", want: false},
		{name: "password shorter", username: "gw-user", password: "gw", want: false},
		{name: "password empty", username: "gw-user", password: "", want: false},
		{name: "password longer", username: "gw-user", password: strings.Repeat("p", 255), want: false},
		{
			// Basic splits on the first colon only, so colons in the password
			// survive the round trip while a truncated password does not.
			name:     "colons in the configured password, correct pair",
			account:  newInboundAccount([]byte("gw-user"), []byte("se:cr:et:pa:ss")),
			username: "gw-user",
			password: "se:cr:et:pa:ss",
			want:     true,
		},
		{
			name:     "colons in the configured password, truncated at a colon",
			account:  newInboundAccount([]byte("gw-user"), []byte("se:cr:et:pa:ss")),
			username: "gw-user",
			password: "se:cr:et",
			want:     false,
		},
		{
			name:     "unicode bytes, correct pair",
			account:  newInboundAccount([]byte("gw-usër"), []byte("pässwörd✓")),
			username: "gw-usër",
			password: "pässwörd✓",
			want:     true,
		},
		{
			// Ë and ✓/✗ are multi-byte: same byte lengths as the configured
			// fields, entirely different bytes.
			name:     "unicode bytes, same byte length different bytes",
			account:  newInboundAccount([]byte("gw-usër"), []byte("pässwörd✓")),
			username: "gw-usËr",
			password: "pässwörd✗",
			want:     false,
		},
		{
			// An empty password is a legal configured pair and must match only
			// its empty presentation.
			name:     "empty configured password, empty presented",
			account:  newInboundAccount([]byte("gw-user"), []byte("")),
			username: "gw-user",
			password: "",
			want:     true,
		},
		{
			name:     "empty configured password, nonempty presented",
			account:  newInboundAccount([]byte("gw-user"), []byte("")),
			username: "gw-user",
			password: "x",
			want:     false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acct := tc.account
			if acct == nil {
				acct = defaultAccount
			}
			if got := credentialsMatch(acct, []byte(tc.username), []byte(tc.password)); got != tc.want {
				t.Fatalf("credentialsMatch(%q, %q) = %v, want %v", tc.username, tc.password, got, tc.want)
			}
		})
	}
}

// credentialDigest must be a MAC under the process-wide random key, not an
// unkeyed hash: an unkeyed fast digest of a credential would hand a
// memory-disclosure reader an offline brute-force target. Recomputing the HMAC
// independently pins both the keying and the digest form.
func TestCredentialDigestIsKeyedMAC(t *testing.T) {
	key := credentialDigestKey()
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("probe value"))
	var want [credentialDigestSize]byte
	mac.Sum(want[:0])
	if got := credentialDigest([]byte("probe value")); got != want {
		t.Fatalf("credentialDigest = %x, want the HMAC-SHA256 digest %x", got, want)
	}
}

// The comparison must stay unconditional across the pair: credentialsMatch
// digests both presented fields and runs both constant-time comparisons before
// any branch exists, so the only quantity the exchange can observe is the
// combined result. This table pins that combined result for every mismatch
// combination against independently computed per-field digest comparisons; a
// regression that swaps a field's digest, inverts the combination, or drops a
// comparison's contribution from the result fails here.
func TestCredentialsMatchCombinedResult(t *testing.T) {
	account := newInboundAccount([]byte("gw-user"), []byte("gw-pass"))
	usernames := []string{
		"gw-user",                // correct
		"gw-User",                // wrong, same length
		"gw",                     // wrong, shorter
		"",                       // wrong, empty
		strings.Repeat("u", 255), // wrong, much longer
	}
	passwords := []string{
		"gw-pass",                // correct
		"gw-Pass",                // wrong, same length
		"gw",                     // wrong, shorter
		"",                       // wrong, empty
		strings.Repeat("p", 255), // wrong, longer
	}
	for _, username := range usernames {
		for _, password := range passwords {
			userSum := credentialDigest([]byte(username))
			passSum := credentialDigest([]byte(password))
			userOK := subtle.ConstantTimeCompare(userSum[:], account.usernameSum[:]) == 1
			passOK := subtle.ConstantTimeCompare(passSum[:], account.passwordSum[:]) == 1
			if want := userOK && passOK; want != credentialsMatch(account, []byte(username), []byte(password)) {
				t.Errorf("credentialsMatch(%q, %q): want the combined result %v", username, password, want)
			}
		}
	}
}

// The 407 is the one protocol answer that names the accepted scheme, so it
// must carry the challenge — and it must stay bodyless, because the only useful
// information to a client is where to present a credential next.
func TestRequireProxyAuthorizationShape(t *testing.T) {
	var wire strings.Builder
	requireProxyAuthorization(&wire)
	// Connection: close is set inside WriteHeader and the header block is
	// written through http.Header.Write, so fields come out in canonical
	// (alphabetical) order.
	want := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Connection: close\r\n" +
		"Content-Length: 0\r\n" +
		`Proxy-Authenticate: Basic realm="rotation-proxy-gateway"` + "\r\n\r\n"
	if wire.String() != want {
		t.Fatalf("requireProxyAuthorization wrote %q, want %q", wire.String(), want)
	}
}

// authConnectStatus performs a full account-gated request against a live server
// and returns the status the client saw. A nil credential presents no
// Proxy-Authorization field at all, which is the no-auth client.
func authConnectStatus(t *testing.T, gatewayAddr string, credential *string, target string) int {
	t.Helper()
	conn := dialGateway(t, gatewayAddr)
	headers := []string{"Host: " + target}
	if credential != nil {
		headers = append(headers, "Proxy-Authorization: "+*credential)
	}
	if _, err := conn.Write(connectRequestWithHeaders(target, headers...)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	return readIngressResponse(t, bufio.NewReader(conn), http.MethodConnect).StatusCode
}

// connectRequestWithHeaders renders a CONNECT request with exactly the headers
// the test supplies, so a test can omit Host or add a credential.
func connectRequestWithHeaders(target string, headers ...string) []byte {
	var frame strings.Builder
	frame.WriteString("CONNECT " + target + " HTTP/1.1\r\n")
	for _, header := range headers {
		frame.WriteString(header + "\r\n")
	}
	frame.WriteString("\r\n")
	return []byte(frame.String())
}

// The account gates the whole server: valid credentials reach an established
// tunnel through the real route pool, wrong credentials and no-auth clients
// never reach route selection, and no credential byte reaches the logs.
func TestInboundAccountGatesServing(t *testing.T) {
	route := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(route.URL), 30*time.Second, time.Minute)
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	s.UseInboundAccount([]byte("gw-user"), []byte("gw-pass"))
	addr := startServer(t, s)
	target := startRawEchoTarget(t)

	correct := proxyAuthorization("gw-user", "gw-pass")
	wrong := proxyAuthorization("gw-user", "wrong")
	conn := dialGateway(t, addr)
	if _, err := conn.Write(connectRequestWithHeaders(target, "Host: "+target, "Proxy-Authorization: "+correct)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	tunnel := bufio.NewReader(conn)
	if status := readIngressResponse(t, tunnel, http.MethodConnect).StatusCode; status != http.StatusOK {
		t.Fatalf("authenticated CONNECT = %d, want 200", status)
	}
	if banner := readBanner(t, tunnel); banner != "banner\n" {
		t.Fatalf("banner = %q", banner)
	}
	_ = conn.Close()

	// Wrong credentials are answered 407 and the connection closes, before any
	// route selection: the listener request counter must not move.
	if status := authConnectStatus(t, addr, &wrong, target); status != http.StatusProxyAuthRequired {
		t.Fatalf("wrong credentials = %d, want 407", status)
	}

	// A client that presents no credential at all is refused the same way.
	if status := authConnectStatus(t, addr, nil, target); status != http.StatusProxyAuthRequired {
		t.Fatalf("no credential = %d, want 407", status)
	}

	output := waitForRecord(t, &logs, map[string]string{
		"msg": "HTTP proxy authentication rejected", "level": "warn", "error_kind": "auth_rejected",
	})
	if status := s.ListenerStatus(); status.Requests != 1 || status.Failovers != 0 {
		t.Fatalf("listener status = %+v, want exactly the one authenticated request", status)
	}
	snap := pl.Snapshot()
	if len(snap) != 1 || snap[0].Successes != 1 || snap[0].Failures != 0 || !snap[0].Available {
		t.Fatalf("route state = %+v, want one success and a healthy route", snap)
	}
	// A 407 must never echo the presented credential back, and neither may any
	// log line: the reject is pre-selection and post-secret-consumption.
	for _, secret := range []string{"gw-user", "gw-pass", "wrong"} {
		if strings.Contains(output, secret) {
			t.Errorf("logs leaked %q:\n%s", secret, output)
		}
	}
}

// An armed account applies to the absolute-form shape too: the credential
// boundary is the ingress, not one request shape, and a rejected forward
// request must not reach its origin or advance the request counter.
func TestInboundAccountGatesForwardRequests(t *testing.T) {
	var reached bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		_, _ = io.WriteString(w, "origin")
	}))
	t.Cleanup(origin.Close)
	originHost := strings.TrimPrefix(origin.URL, "http://")

	route := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(route.URL), 30*time.Second, time.Minute)
	s := newRuntimeServer(pl, defaultRuntime(), testLogger())
	s.UseInboundAccount([]byte("gw-user"), []byte("gw-pass"))
	addr := startServer(t, s)

	correct := proxyAuthorization("gw-user", "gw-pass")
	resp := httpForward(t, addr, httpForwardRequest(http.MethodGet, "http://"+originHost+"/thing",
		"Host: "+originHost, "Proxy-Authorization: "+correct), http.MethodGet)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated forward request = %d, want the origin's own 200", resp.StatusCode)
	}
	if !reached {
		t.Fatal("the authenticated forward request never reached the origin")
	}

	resp = httpForward(t, addr, httpForwardRequest(http.MethodGet, "http://"+originHost+"/thing",
		"Host: "+originHost), http.MethodGet)
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated forward request = %d, want 407", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got == "" {
		t.Error("the forward-shape 407 did not name the accepted scheme")
	}
	// Only the authenticated request counted.
	if status := s.ListenerStatus(); status.Requests != 1 {
		t.Fatalf("listener status = %+v, want exactly the one authenticated request", status)
	}
}

// The consumed credential is removed from the outbound request before either
// accepted shape reaches its target, and the reserved control namespace gets
// the same explicit treatment. stripEcomaControlHeaders is case-insensitive
// because HTTP field names are.
func TestStripEcomaControlHeadersIsCaseInsensitive(t *testing.T) {
	header := http.Header{
		"X-Ecoma-Probe":       []string{"one"},
		"x-ecoma-other":       []string{"two"},
		"X-ECOMA-Third":       []string{"three"},
		"X-Ecomable":          []string{"kept"},
		"Proxy-Authorization": []string{"kept"},
		"Accept":              []string{"kept"},
	}
	stripEcomaControlHeaders(header)
	for _, name := range []string{"X-Ecoma-Probe", "x-ecoma-other", "X-ECOMA-Third"} {
		if len(header.Values(name)) != 0 {
			t.Errorf("stripEcomaControlHeaders kept %q", name)
		}
	}
	// The namespace boundary is the whole x-ecoma- prefix, not an exact list.
	for _, name := range []string{"X-Ecomable", "Proxy-Authorization", "Accept"} {
		if len(header.Values(name)) != 1 {
			t.Errorf("stripEcomaControlHeaders dropped %q, which is outside the reserved namespace", name)
		}
	}
}

// A tunnel is established without any handshake reply the client must consume
// beyond the 200: the credential is a header, so nothing about the tunnel
// depends on how the client framed the exchange before it.
func TestAuthenticatedTunnelCarriesBytesAfterThe200(t *testing.T) {
	route := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(route.URL), 30*time.Second, time.Minute)
	s := newRuntimeServer(pl, defaultRuntime(), testLogger())
	s.UseInboundAccount([]byte("gw-user"), []byte("gw-pass"))
	addr := startServer(t, s)
	target := startRawEchoTarget(t)

	conn := dialGateway(t, addr)
	payload := []byte("authenticated-payload")
	frame := connectRequestWithHeaders(target, "Host: "+target,
		"Proxy-Authorization: "+proxyAuthorization("gw-user", "gw-pass"))
	if _, err := conn.Write(append(frame, payload...)); err != nil {
		t.Fatalf("write burst: %v", err)
	}
	br := bufio.NewReader(conn)
	if status := readIngressResponse(t, br, http.MethodConnect).StatusCode; status != http.StatusOK {
		t.Fatalf("authenticated CONNECT = %d, want 200", status)
	}
	if got := readBanner(t, br); got != "banner\n" {
		t.Fatalf("banner = %q", got)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}
	_ = conn.Close()
}
