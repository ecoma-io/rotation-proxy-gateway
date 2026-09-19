// Probe and rotate-API plumbing. Everything here treats the rotate API's
// headers and body as credentials: they are sent, never logged, and never
// returned in errors.
package rotation

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/sanitize"
)

// errProbe describes one failed egress-IP probe. Only fixed labels and
// sanitized transport text survive into it.
type errProbe struct{ msg string }

func (e *errProbe) Error() string { return e.msg }

// probeIP observes the route's current public egress IP: it dials the route's
// SOCKS endpoint, tunnels to the ip-check URL, TLS-verifies the endpoint
// regardless of the gateway's target-tls-insecure setting, fetches it, and
// parses the ip= entry from the response body.
func (e *Engine) probeIP(ctx context.Context, gen *pool.Generation, spec config.ManualRouteSpec, timeout time.Duration) (string, error) {
	checkURL, err := url.Parse(gen.Config.Rotation.IPCheckURL)
	if err != nil || checkURL.Host == "" {
		return "", &errProbe{"ip-check-url is not parseable"}
	}
	hostPort := checkURL.Host
	if checkURL.Port() == "" {
		hostPort = net.JoinHostPort(checkURL.Hostname(), "443")
	}

	// The probe budget bounds the whole attempt — dial through body — and is
	// measured from entry, not from whenever the dial happens to finish: the
	// caller's verify loop hands over the remaining slice of its own
	// deadline, and a slow dial must eat into that slice rather than extend
	// the attempt. The context's deadline still wins when it is sooner.
	start := time.Now()
	deadline := start.Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	conn, err := e.dial(ctx, spec.URL, hostPort, timeout)
	if err != nil {
		return "", err // socksdial errors are already host-only and sanitized
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(deadline); err != nil {
		return "", &errProbe{"setting ip-check deadline failed"}
	}

	tlsConn := tls.Client(conn, e.probeTLS(checkURL.Hostname()))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", &errProbe{"TLS handshake with ip-check endpoint failed"}
	}

	req := "GET " + checkURL.RequestURI() + " HTTP/1.1\r\n" +
		"Host: " + checkURL.Host + "\r\n" +
		"User-Agent: rotation-proxy-gateway\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(tlsConn, req); err != nil {
		return "", &errProbe{"sending ip-check request failed"}
	}

	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return "", &errProbe{"reading ip-check response failed"}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", &errProbe{"reading ip-check body failed"}
	}
	if resp.StatusCode != http.StatusOK {
		return "", &errProbe{fmt.Sprintf("ip-check endpoint returned status %d", resp.StatusCode)}
	}
	ip := parseIPLine(string(body))
	if ip == "" {
		return "", &errProbe{"ip-check response has no usable ip= entry"}
	}
	return ip, nil
}

// parseIPLine extracts the value of the first ip= line (key=value format, as
// served by the cloudflare trace endpoint and compatible services). The value
// must parse as an address literal: a broken or hostile endpoint serving
// junk must fail the probe, not flow into rotation state where it would
// defeat collision checks by never matching a real address.
func parseIPLine(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(line, "ip="); ok {
			value = strings.TrimSpace(value)
			if net.ParseIP(value) == nil {
				return ""
			}
			return value
		}
	}
	return ""
}

// baselineProbe tries to learn the route's egress IP before rotating. After
// baselineAttempts failures the rotation proceeds unverified: the first
// observed non-colliding IP after the rotate API call counts as the new IP.
func (e *Engine) baselineProbe(ctx context.Context, gen *pool.Generation, spec config.ManualRouteSpec, timeout time.Duration) (string, bool) {
	for attempt := range baselineAttempts {
		if ctx.Err() != nil {
			return "", false
		}
		ip, err := e.probeIP(ctx, gen, spec, timeout)
		if err == nil {
			return ip, true
		}
		if attempt < baselineAttempts-1 {
			if !sleepCtx(ctx, probeRetryPause) {
				return "", false
			}
		}
	}
	return "", false
}

// rotateAPITransport performs provider rotate calls directly. A nil Proxy
// func on a Transport means "no proxy, ever" — deliberately not
// ProxyFromEnvironment, because the rotate API's headers and body are
// credentials and an ambient HTTP(S)_PROXY would receive them. The client
// below sets this Transport explicitly: leaving it unset would fall back to
// http.DefaultTransport, which honors the environment.
var rotateAPITransport = &http.Transport{
	ForceAttemptHTTP2: true,
	TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
}

// rotateClient builds the one-shot client for a provider rotate call.
func rotateClient(api config.RotateAPI) *http.Client {
	return &http.Client{
		Transport: rotateAPITransport,
		Timeout:   api.Timeout,
		// Never follow redirects: a 3xx would replay the rotate API's
		// headers (and body on 307/308) to whatever host it names. The
		// first response is final, so a redirect fails the call like any
		// other non-2xx status.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// callRotateAPI performs the provider call that swaps the route's egress IP.
// It returns a Retry-After hint when the provider rate-limits the call.
func (e *Engine) callRotateAPI(ctx context.Context, api config.RotateAPI) (time.Duration, error) {
	var body io.Reader
	if api.Body != "" {
		body = strings.NewReader(api.Body)
	}
	req, err := http.NewRequestWithContext(ctx, api.Method, api.URL.String(), body)
	if err != nil {
		return 0, errors.New("building the rotate API request failed")
	}
	for name, value := range api.Headers {
		req.Header.Set(name, value)
	}

	client := rotateClient(api)
	resp, err := client.Do(req)
	if err != nil {
		// url.Error embeds the full URL, which may carry credentials in its
		// query. Keep only the transport-level cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			return 0, fmt.Errorf("rotate API %s failed: %v", strings.ToLower(ue.Op), sanitize.ErrorString(ue.Err))
		}
		return 0, errors.New("rotate API call failed")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10) // response body is intentionally discarded

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return 0, nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return parseRetryAfter(resp.Header.Get("Retry-After")), fmt.Errorf("rotate API returned status %d", resp.StatusCode)
	default:
		return 0, fmt.Errorf("rotate API returned status %d", resp.StatusCode)
	}
}

// parseRetryAfter understands the seconds form of Retry-After; the date form
// is ignored (providers use seconds).
func parseRetryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
