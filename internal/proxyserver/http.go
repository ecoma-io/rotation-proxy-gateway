package proxyserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/socksdial"

	"github.com/rs/zerolog"
)

// The data plane deliberately parses exactly one HTTP request from every client
// connection. A CONNECT turns that connection into the tunnel it requested;
// an absolute-form request is relayed as one HTTP exchange over one SOCKS
// tunnel. In both cases accepting a second request would decouple request
// lifetime from the selected route's in-flight hold, and leave a pipelined
// second request without a route-selection chain of its own.
const maxInboundHeaderBytes = 1 << 20

// errHTTPVersionNotSupported carries no untrusted version text: the response
// and log must state only the stable protocol outcome, never reflect a raw
// request line. It is recognized before net/http's parser folds an otherwise
// well-formed HTTP/1.0 or HTTP/2.0 start line into a generic parse failure.
var errHTTPVersionNotSupported = errors.New("HTTP version not supported")

// replier reports the outcome of one request's route-selection chain back to
// the client in whatever protocol the ingress speaks. It is intentionally
// smaller than the route-selection engine: the engine owns the retry, frozen
// generation, selection, health, and winning-hold invariants, while this seam
// owns only wire-visible success and terminal failure replies.
type replier interface {
	ok() error
	fail() error
}

// failureStatusReplier is private plumbing for HTTP's several terminal error
// statuses. The route engine sees only replier; HTTP implementations expose the
// one additional setter so an already-selected terminal class can choose its
// correct status without copying the attempt chain into every ingress shape.
type failureStatusReplier interface {
	replier
	setFailureStatus(int)
}

func replyFailure(reply replier, status int) error {
	if configurable, ok := reply.(failureStatusReplier); ok {
		configurable.setFailureStatus(status)
	}
	return reply.fail()
}

// httpResponseWriter writes one HTTP/1.1 response directly to a client socket.
// The data plane accepts one request per connection, so every response closes
// the connection rather than pretending an unknown-length body is reusable.
// That makes a streamed upstream body self-delimiting without buffering or a
// second transfer-encoding implementation, and is why Flush is safely a no-op:
// conn.Write has no user-space response buffer to drain.
type httpResponseWriter struct {
	conn        io.Writer
	header      http.Header
	close       bool
	wroteHeader bool
	// body counts the response body bytes this writer handed to the client. It is
	// an observable counter and nothing more: no control-flow decision reads it,
	// and only bytes that actually went to the socket are counted.
	body int64
	// failed records that the gateway — not the target — terminated the
	// response. It is set only by forwardHTTP's ErrorHandler, and read only
	// after ServeHTTP has returned, so it needs no synchronization.
	failed bool
}

func newHTTPResponseWriter(conn io.Writer) *httpResponseWriter {
	return &httpResponseWriter{conn: conn, header: make(http.Header), close: true}
}

// newTunnelResponseWriter leaves Connection unmodified: CONNECT's successful
// response is immediately followed by arbitrary tunnel bytes on this same
// socket, so advertising close there would contradict the established tunnel.
func newTunnelResponseWriter(conn io.Writer) *httpResponseWriter {
	return &httpResponseWriter{conn: conn, header: make(http.Header)}
}

func (w *httpResponseWriter) Header() http.Header { return w.header }

func (w *httpResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if w.close {
		w.header.Set("Connection", "close")
	}
	_, _ = fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	_ = w.header.Write(w.conn)
	_, _ = io.WriteString(w.conn, "\r\n")
}

func (w *httpResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.conn.Write(p)
	w.body += int64(n)
	return n, err
}

func (*httpResponseWriter) Flush() {}

// writeHTTPError emits a deliberately bodyless protocol response. The status is
// the useful information to a proxy client; echoing parser, credential, target,
// or upstream details in a response is both unhelpful for retry and a possible
// disclosure of data the client supplied.
func writeHTTPError(conn io.Writer, status int) error {
	response := newHTTPResponseWriter(conn)
	response.Header().Set("Content-Length", "0")
	response.WriteHeader(status)
	return nil
}

// connectReplier writes the one success reply that has a meaning before bytes
// cross the established tunnel. Its failure status is supplied by serveTunnel:
// an upstream problem is not exposed until the complete fallback chain ended.
type connectReplier struct {
	conn          io.Writer
	failureStatus int
}

func (r *connectReplier) ok() error {
	response := newTunnelResponseWriter(r.conn)
	response.Header().Set("Content-Length", "0")
	response.WriteHeader(http.StatusOK)
	return nil
}

func (r *connectReplier) fail() error { return writeHTTPError(r.conn, r.failureStatus) }

func (r *connectReplier) setFailureStatus(status int) { r.failureStatus = status }

// forwardReplier deliberately writes nothing for a successful route pick. The
// ReverseProxy starts the sole client response only after it receives the target
// response over the just-established SOCKS tunnel; an invented 200 here would
// turn one HTTP request into two responses. Terminal route-chain failures still
// use the shared replier seam.
type forwardReplier struct {
	conn          io.Writer
	failureStatus int
}

func (*forwardReplier) ok() error { return nil }

func (r *forwardReplier) fail() error { return writeHTTPError(r.conn, r.failureStatus) }

func (r *forwardReplier) setFailureStatus(status int) { r.failureStatus = status }

// readInboundRequest reads and preserves one header block before asking net/http
// to build the streaming Request. net/http intentionally removes Host from
// Request.Header after assigning Request.Host, which is normally correct but
// would hide an absolute-form target whose explicit Host header disagreed. The
// small capture exists only to enforce forward-proxy authority integrity; the
// body remains on the socket reader and is never buffered by this layer.
//
// It returns the socket's own framing reader, not the parser's. net/http parses
// the header block out of a view that replays the captured bytes and then
// drains it, so whatever that view buffered beyond the header block is gone by
// the time parsing returns; a client that pipelines bytes behind its CONNECT
// headers — which every TLS client does — would have its first tunnel payload
// discarded. The framing reader is the only place those bytes still live, and
// CONNECT hands it straight to the relay. The absolute-form path does not need
// it, because that path consumes the body through req.Body.
func readInboundRequest(conn net.Conn) (*http.Request, *bufio.Reader, string, error) {
	framing := bufio.NewReaderSize(conn, inboundBufSize)
	header, err := readHTTPHeader(framing)
	if err != nil {
		return nil, nil, "", err
	}
	parsed := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(header), framing), inboundBufSize)
	req, err := http.ReadRequest(parsed)
	if err != nil {
		if headerRequestsUnsupportedHTTPVersion(header) {
			return nil, nil, "", errHTTPVersionNotSupported
		}
		return nil, nil, "", err
	}
	host, err := headerHost(header)
	if err != nil {
		return nil, nil, "", err
	}
	return req, framing, host, nil
}

// readHTTPHeader returns exactly the bytes through the empty line. ReadSlice
// lets bufio keep body bytes it happened to pull from the socket, while the
// explicit bound rejects a peer that attempts to turn a listener goroutine into
// unbounded header storage before net/http's parser gets a chance to reject it.
func readHTTPHeader(br *bufio.Reader) ([]byte, error) {
	header := make([]byte, 0, inboundBufSize)
	for {
		line, err := br.ReadSlice('\n')
		header = append(header, line...)
		if len(header) > maxInboundHeaderBytes {
			return nil, errors.New("HTTP request header exceeds the inbound limit")
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
		if bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			return header, nil
		}
	}
}

// headerRequestsUnsupportedHTTPVersion reports whether a header block began
// with a syntactically well-formed request line naming an HTTP major version
// this ingress does not speak. net/http accepts and rejects HTTP/1.0 and
// HTTP/1.1 start lines, so distinguishing them here is the only way a
// well-formed `GET / HTTP/1.0` still receives 505 instead of 400. The check is
// deliberately narrow: nothing outside the first line is consulted, so a
// malformed request still fails as 400.
func headerRequestsUnsupportedHTTPVersion(header []byte) bool {
	lineEnd := bytes.Index(header, []byte("\r\n"))
	if lineEnd < 0 {
		return false
	}
	fields := bytes.Split(header[:lineEnd], []byte(" "))
	if len(fields) < 3 || len(fields[0]) == 0 || len(fields[1]) == 0 {
		return false
	}
	version := fields[2]
	major, minor, ok := http.ParseHTTPVersion(string(version))
	return !ok || major != 1 || minor != 1
}

// headerHost returns the one explicit Host field from a syntactically-valid
// header block. ReadRequest catches malformed field syntax and duplicate Host
// fields; this pass only makes the field available after ReadRequest intentionally
// erased it. The HTTP authority in an absolute-form target is authoritative even
// without Host; a CONNECT may likewise omit Host, but if it supplies one, it
// must agree with the tunnel authority.
func headerHost(header []byte) (string, error) {
	for len(header) > 0 {
		lineEnd := bytes.Index(header, []byte("\r\n"))
		if lineEnd < 0 {
			return "", errors.New("HTTP header lacks CRLF framing")
		}
		line := header[:lineEnd]
		header = header[lineEnd+2:]
		if len(line) == 0 {
			return "", nil
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue // request line; ReadRequest validates it separately.
		}
		if !strings.EqualFold(string(line[:colon]), "Host") {
			continue
		}
		return strings.TrimSpace(string(line[colon+1:])), nil
	}
	return "", errors.New("HTTP request lacks complete headers")
}

// validateHTTPProxyRequest separates the only two accepted forward-proxy
// shapes from HTTP's broader request-target grammar, and turns their authority
// into the target passed unchanged to the SOCKS5H dialer. No target is resolved
// locally: a hostname remains AddrDomain, and IP literals remain their literal
// address type, preserving target routing's source-of-truth rule.
func validateHTTPProxyRequest(req *http.Request, suppliedHost string) (socksdial.Target, bool, int, error) {
	if req.ProtoMajor != 1 || req.ProtoMinor != 1 {
		return socksdial.Target{}, false, http.StatusHTTPVersionNotSupported, errHTTPVersionNotSupported
	}
	if req.Method == http.MethodConnect {
		if req.URL.Scheme != "" || req.URL.Host == "" || req.URL.Path != "" || req.URL.RawQuery != "" {
			return socksdial.Target{}, false, http.StatusBadRequest, errors.New("CONNECT request target is not an authority")
		}
		if suppliedHost != "" && !sameHTTPAuthority(req.URL.Host, suppliedHost) {
			return socksdial.Target{}, false, http.StatusBadRequest, errors.New("CONNECT Host does not match request target")
		}
		target, err := targetFromAuthority(req.URL.Host, true)
		if err != nil {
			return socksdial.Target{}, false, http.StatusBadRequest, err
		}
		return target, true, 0, nil
	}

	if req.URL.Scheme == "" || req.URL.Host == "" {
		// The asterisk form does not name a forward-proxy target. It is valid HTTP
		// but has no implemented proxy semantics, unlike a syntactically broken
		// origin-form request, so report the requested 501 distinction here.
		if req.RequestURI == "*" {
			return socksdial.Target{}, false, http.StatusNotImplemented, errors.New("asterisk-form proxy requests are not implemented")
		}
		return socksdial.Target{}, false, http.StatusBadRequest, errors.New("forward proxy requires an absolute-form request target")
	}
	if !strings.EqualFold(req.URL.Scheme, "http") {
		return socksdial.Target{}, false, http.StatusNotImplemented, errors.New("forward proxy supports only the http scheme")
	}
	// A forward proxy relays the request's method verbatim, but a method it
	// cannot interpret as proxying is a protocol error on this listener rather
	// than a route problem. CONNECT has its own branch above; everything else
	// here is the ordinary absolute-form shape, so one method is the only one
	// the proxy semantics are defined for.
	if req.Method != http.MethodGet && req.Method != http.MethodHead && req.Method != http.MethodPost {
		return socksdial.Target{}, false, http.StatusMethodNotAllowed, errors.New("forward proxy does not support this method")
	}
	if req.URL.User != nil || (suppliedHost != "" && !sameHTTPAuthority(req.URL.Host, suppliedHost)) {
		return socksdial.Target{}, false, http.StatusBadRequest, errors.New("host does not match absolute request target")
	}
	target, err := targetFromAuthority(req.URL.Host, false)
	if err != nil {
		return socksdial.Target{}, false, http.StatusBadRequest, err
	}
	return target, false, 0, nil
}

// sameHTTPAuthority makes the Host check semantic enough for case-insensitive
// DNS names, but does not silently make an explicit non-default port disappear.
// The client tells us both authority values; accepting a mismatch would let the
// ingress be used as a reverse proxy whose target differs from its request line.
func sameHTTPAuthority(target, supplied string) bool {
	targetHost, targetPort, targetHasPort, err := splitHTTPAuthority(target)
	if err != nil {
		return false
	}
	suppliedHost, suppliedPort, suppliedHasPort, err := splitHTTPAuthority(supplied)
	if err != nil || targetHasPort != suppliedHasPort || targetPort != suppliedPort {
		return false
	}
	return strings.EqualFold(targetHost, suppliedHost)
}

// targetFromAuthority validates an HTTP authority without resolving it. CONNECT
// must have a port because it names a TCP tunnel directly; HTTP absolute-form
// inherits the scheme's default port 80 when it omitted one. A zero port is
// never a target, even if a permissive URL parser happened to accept its text.
func targetFromAuthority(authority string, requirePort bool) (socksdial.Target, error) {
	host, port, hasPort, err := splitHTTPAuthority(authority)
	if err != nil {
		return socksdial.Target{}, err
	}
	if !hasPort {
		if requirePort {
			return socksdial.Target{}, errors.New("CONNECT target lacks a port")
		}
		port = "80"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return socksdial.Target{}, errors.New("target port is invalid")
	}
	target := socksdial.Target{Host: host, Port: uint16(n), Type: socksdial.AddrDomain}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			target.Type = socksdial.AddrIPv4
		} else {
			target.Type = socksdial.AddrIPv6
		}
	}
	return target, nil
}

// splitHTTPAuthority accepts precisely a host or host:port authority without
// userinfo, local DNS resolution, a zero port, or URL path/query fragments.
// url.Parse gives IPv6 bracket handling and rejects malformed host escaping;
// the explicit host/port results let the caller distinguish omitted HTTP's
// default from CONNECT's required port.
func splitHTTPAuthority(authority string) (host, port string, hasPort bool, err error) {
	if authority == "" || strings.ContainsAny(authority, "@/?# \t\r\n") {
		return "", "", false, errors.New("target authority is malformed")
	}
	parsed, err := url.Parse("http://" + authority)
	if err != nil || parsed.Host != authority || parsed.User != nil || parsed.Hostname() == "" {
		return "", "", false, errors.New("target authority is malformed")
	}
	host = parsed.Hostname()
	port = parsed.Port()
	if port != "" {
		return host, port, true, nil
	}
	// url.URL.Port returns an empty string for a host without a port, but a
	// malformed `host:` authority needs rejecting rather than treating it as the
	// HTTP default. A bracketed IPv6 literal contains colons only inside brackets.
	if strings.HasSuffix(authority, ":") {
		return "", "", false, errors.New("target authority has an empty port")
	}
	return host, "", false, nil
}

// checkProxyAuthorization verifies Basic proxy credentials without exposing the
// presented bytes to a log, error, response, or status field. Decode before the
// fixed-length digest comparison, retain the configuration's field bounds for
// untrusted input too, and compare both fields even when one mismatch is known.
func checkProxyAuthorization(req *http.Request, account *inboundAccount) bool {
	if account == nil {
		return true
	}
	values := req.Header.Values("Proxy-Authorization")
	if len(values) != 1 {
		return false
	}
	scheme, encoded, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Basic") || encoded == "" || strings.ContainsAny(encoded, " \t") {
		return false
	}
	presented, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	username, password, ok := bytes.Cut(presented, []byte(":"))
	if !ok || len(username) == 0 || len(username) > 255 || len(password) > 255 {
		return false
	}
	return credentialsMatch(account, username, password)
}

func requireProxyAuthorization(conn io.Writer) {
	response := newHTTPResponseWriter(conn)
	response.Header().Set("Content-Length", "0")
	response.Header().Set("Proxy-Authenticate", `Basic realm="rotation-proxy-gateway"`)
	response.WriteHeader(http.StatusProxyAuthRequired)
}

// The gateway-private control headers. Both are read on ingress, stripped
// before forwarding, and absent from route identity: nothing in the x-ecoma-
// prefix reaches an upstream, whatever it happens to carry.
const (
	headerProxyFamily = "X-Ecoma-Proxy-Family"
	headerRequestID   = "X-Ecoma-Request-Id"
)

// stripEcomaControlHeaders removes an entire case-insensitive header namespace
// from the outbound HTTP request. ReverseProxy already removes the RFC 7230
// hop-by-hop set itself (including values named by Connection), so duplicating
// that drift-prone list here would weaken rather than harden the forwarder.
//
// The key is canonicalized before the delete. http.Header.Del canonicalizes its
// argument, so it misses a lower-case key held directly in the map — which
// would hand the client's control material to the origin. Only x-ecoma-*
// keys are rewritten; a differently-cased header of any other prefix keeps the
// key the caller chose.
func stripEcomaControlHeaders(header http.Header) {
	for name := range header {
		if !strings.HasPrefix(strings.ToLower(name), "x-ecoma-") {
			continue
		}
		if canonical := http.CanonicalHeaderKey(name); canonical != name {
			header[canonical] = header[name]
			delete(header, name)
		}
		header.Del(name)
	}
}

// proxyFamily is the request-scoped egress-family constraint carried by
// x-ecoma-proxy-family. It narrows the eligible route set for one request
// exactly the way a listener's own kind filter and the routing policy do — a
// route of another kind is simply not eligible — and composes with both by
// intersection. It is not a socket binding: it never resolves a name, never
// changes the target that leaves in the outbound SOCKS5 CONNECT, and never
// enters route identity, so two requests for one target that differ only in
// this header hit the same pool.Proxy objects.
type proxyFamily int

const (
	// familyMixed is both an absent header and the literal "mixed" — the same
	// request, and the only value that constrains nothing.
	familyMixed proxyFamily = iota
	familyV4
	familyV6
)

// allows reports whether a route of this family may serve the request.
// familyMixed imposes no constraint at all, which is what keeps the
// absent-header path identical to a listener with no kind filter.
func (f proxyFamily) allows(p *pool.Proxy) bool {
	switch f {
	case familyV4:
		return p.Kind == config.EgressV4
	case familyV6:
		return p.Kind == config.EgressV6
	default:
		return true
	}
}

// narrow intersects the family constraint with an already-composed predicate
// and returns that predicate untouched for a mixed request. Handing back
// `allow` as it was — nil included — is what preserves the no-routing fast
// path, where a nil predicate still means "no filter at all".
func (f proxyFamily) narrow(allow func(*pool.Proxy) bool) func(*pool.Proxy) bool {
	if f == familyMixed {
		return allow
	}
	if allow == nil {
		return f.allows
	}
	return func(p *pool.Proxy) bool { return f.allows(p) && allow(p) }
}

// parseProxyFamily resolves the family constraint and refuses every spelling
// outside the closed set. Refusing beats a silent fall back to mixed on
// purpose: the stated egress family is a routing constraint, and quietly
// serving the request from the other family is an invisible correctness
// failure on the one property this gateway exists to provide — a client that
// asked for IPv6 egress has no way to see that it got IPv4. 400 is the same
// local pre-selection reject a malformed authority already gets, so a refused
// value never advances the listener `requests` counter and never touches route
// health. Two cases deserve their own words:
//
//   - An empty value is refused. It names no family, and reading it as absent
//     would make "present but meaningless" indistinguishable from "never
//     asked" — the silent fall back being refused here.
//   - A repeated header is refused. The gateway cannot know which of the two
//     constraints the client meant, and picking one would let an intermediary
//     choose the egress family.
//
// Leading and trailing whitespace is not a spelling at all: net/http trims
// optional field-value whitespace (RFC 9110 §5.5) before the value reaches
// here, so " v4 " is the same request as "v4". Interior whitespace, upper case,
// and every other spelling are outside the set.
func parseProxyFamily(header http.Header) (proxyFamily, error) {
	values := header.Values(headerProxyFamily)
	switch {
	case len(values) > 1:
		return familyMixed, errors.New("x-ecoma-proxy-family appears more than once")
	case len(values) == 0:
		return familyMixed, nil
	}
	switch values[0] {
	case "mixed":
		return familyMixed, nil
	case "v4":
		return familyV4, nil
	case "v6":
		return familyV6, nil
	}
	return familyMixed, errors.New("x-ecoma-proxy-family is not one of mixed, v4, v6")
}

// requestScope is the per-request state serveTunnel needs that a generation, a
// listener, or a connection cannot supply. It exists so the request's own
// narrowing travels as one value rather than as a growing parameter list:
// family is a request-scoped candidate constraint and has no correct home on
// the Server, whose allow filter is the same shape for every request on one
// listener. Only a real ingress request has one; a session that arrived without
// a family header is familyMixed.
type requestScope struct {
	family proxyFamily
	log    zerolog.Logger
}

// serveConn parses, authenticates, and validates one HTTP proxy request. Every
// protocol reject happens before the request counter and before pool selection,
// preserving the status metric's meaning: valid requests that reached route
// selection, not accepts or malformed frames.
func (s *Server) serveConn(conn net.Conn) {
	defer s.untrackConn(conn)
	defer conn.Close() //nolint:errcheck // every one-request session owns its client socket

	deadline := time.Now().Add(inboundHandshakeTimeout)
	_ = conn.SetDeadline(deadline)
	req, reader, suppliedHost, err := readInboundRequest(conn)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errHTTPVersionNotSupported) {
			status = http.StatusHTTPVersionNotSupported
		}
		_ = writeHTTPError(conn, status)
		s.log.Debug().Str("error_kind", "bad_request").Msg("HTTP proxy request rejected")
		return
	}
	defer req.Body.Close() //nolint:errcheck // input disappears with this one request either way

	if !checkProxyAuthorization(req, s.account) {
		requireProxyAuthorization(conn)
		s.log.Warn().Str("error_kind", "auth_rejected").Msg("HTTP proxy authentication rejected")
		return
	}
	// Both control headers are read here, before the namespace is stripped below:
	// they are the gateway's own, and they have to outlive this frame. A family
	// outside the closed set is a protocol reject on the same footing as a
	// malformed authority — answered locally, before route selection, without
	// advancing the request counter or touching route health.
	family, err := parseProxyFamily(req.Header)
	if err != nil {
		_ = writeHTTPError(conn, http.StatusBadRequest)
		s.log.Debug().Str("error_kind", "bad_request").Msg("HTTP proxy request rejected")
		return
	}
	// One correlation id per request, resolved once here and carried by every
	// line of this request's attempt chain however many routes it ends up
	// trying. It is deliberately not the request_id counter value: that one
	// must keep counting valid requests that reached selection, whatever a
	// client asked for, because it is what /status reports.
	correlationID := resolveRequestID(req.Header)
	// Authentication has consumed the client credential. Remove it explicitly
	// before either accepted shape reaches its target: ReverseProxy currently
	// strips it as a hop-by-hop field too, but this is a credential boundary, not
	// an implementation accident we may rely on. The reserved control namespace
	// gets the same explicit treatment; CONNECT has no later HTTP request, but
	// stripping it here makes both shapes safe by construction.
	req.Header.Del("Proxy-Authorization")
	stripEcomaControlHeaders(req.Header)
	target, isConnect, status, err := validateHTTPProxyRequest(req, suppliedHost)
	if err != nil {
		_ = writeHTTPError(conn, status)
		s.log.Debug().Str("error_kind", "bad_request").Msg("HTTP proxy request rejected")
		return
	}

	requestID := s.requests.Add(1)
	scope := requestScope{
		family: family,
		log: s.log.With().
			Int64("request_id", int64(requestID)).
			Str("correlation_id", correlationID).
			Logger(),
	}
	if isConnect {
		client := bufferedClientConn(conn, reader)
		s.serveTunnel(client, target, scope, deadline, &connectReplier{conn: client, failureStatus: http.StatusBadGateway},
			func(upstream net.Conn, chosen *pool.Proxy, start time.Time, logTarget string) {
				s.relayTunnel(client, upstream, chosen, start, logTarget, scope.log, family)
			})
		return
	}

	s.serveTunnel(conn, target, scope, deadline, &forwardReplier{conn: conn, failureStatus: http.StatusBadGateway},
		func(upstream net.Conn, chosen *pool.Proxy, start time.Time, logTarget string) {
			s.forwardHTTP(conn, req, upstream, scope.log, logTarget, chosen, start, family)
		})
}

// bufferedClientConn returns a net.Conn that serves request bytes net/http
// already read ahead before it falls through to the actual socket. That matters
// only for CONNECT: clients commonly pipeline TLS bytes immediately after their
// headers, and losing them would turn a successful proxy reply into a broken
// tunnel. Absolute-form bodies stay owned by req.Body and therefore the reader.
func bufferedClientConn(conn net.Conn, reader *bufio.Reader) net.Conn {
	if reader.Buffered() == 0 {
		return conn
	}
	prefix := make([]byte, reader.Buffered())
	_, _ = io.ReadFull(reader, prefix)
	return &prefixConn{Conn: conn, prefix: prefix}
}

// serveTunnel is the one route-selection and health-reporting engine for both
// accepted HTTP shapes. It fixes one generation for the attempt chain, routes
// only to narrow candidates, excludes every failed route, and holds the winning
// route until the shape-specific established-tunnel work has completed.
//
// The candidate predicate is composed, never branched: the routing policy, the
// listener's egress-kind view, and the request's own family constraint each
// narrow it, and the effective eligible set is their intersection. The pool
// stays the sole authority on health and order — a route the composed predicate
// excludes is simply never offered to it — so this remains one selection path,
// not a second one. Nothing here resolves a name or inspects tunnel bytes.
func (s *Server) serveTunnel(clientConn net.Conn, target socksdial.Target, scope requestScope, handshakeDeadline time.Time, reply replier, serveEstablished func(net.Conn, *pool.Proxy, time.Time, string)) {
	gen := s.generation()
	settings := generationSettings(gen)
	start := time.Now()
	log := scope.log
	targetAddr := target.Addr()
	logTarget := targetLogValue(targetAddr)
	log.Debug().Str("target", logTarget).Msg("tunnel start")

	candidates := gen.Pool.Scope(gen.Router.Match(target))
	allow := s.allow
	if candidates != nil {
		restricted, listenerAllow := candidates, s.allow
		allow = func(p *pool.Proxy) bool {
			_, ok := restricted[p]
			return ok && (listenerAllow == nil || listenerAllow(p))
		}
	}
	// The family constraint composes with what routing and the listener already
	// decided, so a v4-only route can never serve a v6 request even on the mixed
	// listener. For a mixed request this returns the composed predicate
	// untouched, leaving the no-routing path free of a second filter.
	allow = scope.family.narrow(allow)

	exclude := map[*pool.Proxy]bool{}
	var upstream net.Conn
	var chosen *pool.Proxy
	var attempts int
	exhausted := false
	for attempt := 0; ; attempt++ {
		if attempt > 0 && !time.Now().Before(handshakeDeadline) {
			_ = replyFailure(reply, http.StatusBadGateway)
			log.Warn().Str("target", logTarget).Int("attempts", attempts).
				Str("error_kind", errorKindSetup).Str("duration", logDuration(time.Since(start))).
				Msg("inbound handshake deadline expired before the next attempt")
			// Recorded at the same instant as the log line and the client
			// response, with the same error kind, so the analytics row and the
			// log always describe one event. chosen is nil here: the deadline
			// expired between attempts, so this request never had a route.
			s.observeFailure(chosen, s.listener, familyLabel(scope.family), errorKindSetup, logTarget, time.Now())
			return
		}
		if attempt >= settings.maxRetries {
			exhausted = true
			break
		}
		p := gen.Pool.PickFor(exclude, allow, targetAddr)
		if p == nil {
			break
		}
		attempts = attempt + 1
		if log.Debug().Enabled() {
			ev := log.Debug().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
				Int("attempt", attempts).Int("excluded", len(exclude))
			if candidates != nil {
				ev = ev.Str("route_id", p.RouteID())
			}
			if cd := gen.Pool.CoolingFor(p, targetAddr); cd > 0 {
				ev = ev.Str("cooldown_remaining", logDuration(cd))
			}
			ev.Msg("route selected")
		}
		up, dialErr := s.dialWarmFirst(s.baseCtx, p, target, settings.dialTimeout)
		if dialErr == nil {
			gen.Pool.ReportSuccess(p, targetAddr)
			upstream, chosen = up, p
			break
		}

		terminalStatus := http.StatusBadGateway
		switch {
		case isProxyDialError(dialErr):
			cooldown := gen.Pool.ReportFailure(p, dialErr)
			exclude[p] = true
			log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
				Int("attempt", attempts).Str("error_kind", errorKindProxyConnect).
				Str("error", logErrorValue(dialErr)).Str("cooldown", cooldown.String()).
				Msg("upstream dial failed")
		case isConnectTargetError(dialErr):
			cooldown := gen.Pool.ReportTargetFailure(p, targetAddr, dialErr)
			exclude[p] = true
			log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
				Int("attempt", attempts).Str("error_kind", errorKindConnectTarget).
				Str("error", logErrorValue(dialErr)).Str("cooldown", cooldown.String()).
				Msg("upstream refused connect target")
		case isSocksHandshakeError(dialErr):
			cooldown := gen.Pool.ReportFailure(p, dialErr)
			exclude[p] = true
			log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
				Int("attempt", attempts).Str("error_kind", errorKindSocksConnect).
				Str("error", logErrorValue(dialErr)).Str("cooldown", cooldown.String()).
				Msg("upstream handshake failed")
		case isProxyAuthError(dialErr):
			gen.Pool.ReportAuthBlocked(p, dialErr)
			exclude[p] = true
			log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
				Int("attempt", attempts).Str("error_kind", errorKindAuthRoute).
				Str("error", logErrorValue(dialErr)).
				Msg("upstream auth failed")
		default:
			// Setup is deliberately 502 here: this path has accepted a valid HTTP
			// proxy request and selected a route, so the client did not send a bad
			// frame. It is a gateway-side local construction failure (such as an
			// invalid configured route credential or target encoding), and no route
			// health changes or retry is justified.
			_ = replyFailure(reply, terminalStatus)
			log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
				Int("attempt", attempts).Str("error_kind", logErrorKind(dialErr)).Str("error", logErrorValue(dialErr)).
				Str("duration", logDuration(time.Since(start))).
				Msg("upstream setup failed")
			// The one failure with a route to attribute it to: this attempt did
			// pick p before the local construction failed, so the row carries it
			// and an operator can see which route produces gateway-side setup
			// errors rather than only that some route does.
			s.observeFailure(p, s.listener, familyLabel(scope.family), logErrorKind(dialErr), logTarget, time.Now())
			p.Release()
			return
		}
		p.Release()
		if attempt+1 < settings.maxRetries {
			s.failovers.Add(1)
		}
	}
	if upstream == nil {
		kind := errorKindNoRoute
		if exhausted {
			kind = errorKindRetryExhausted
		}
		_ = replyFailure(reply, http.StatusServiceUnavailable)
		ev := log.Warn().Str("target", logTarget).Int("attempts", attempts).
			Int("pool_size", gen.Pool.Size()).Int("kind_routes", gen.Pool.CountAllowed(allow)).
			Int("excluded", len(exclude)).
			Str("error_kind", kind).Str("duration", logDuration(time.Since(start)))
		if candidates != nil {
			ev = ev.Int("routing_candidates", len(candidates))
		}
		ev.Msg("tunnel failed")
		// chosen is nil on this path by construction — nothing was ever
		// selected — so the row carries no route. That is the honest shape: an
		// empty route key in failure_events means "the pool had nothing to
		// offer", which is exactly what an operator reading it needs to know and
		// something a per-route counter could not say.
		s.observeFailure(nil, s.listener, familyLabel(scope.family), kind, logTarget, time.Now())
		return
	}
	defer chosen.Release()
	_ = clientConn.SetDeadline(time.Now().Add(inboundHandshakeTimeout))
	if err := reply.ok(); err != nil {
		_ = upstream.Close()
		return
	}
	_ = clientConn.SetDeadline(time.Time{})
	log.Info().Str("target", logTarget).Str("upstream", upstreamLogValue(chosen)).
		Int("attempts", attempts).Str("duration", logDuration(time.Since(start))).
		Msg("tunnel")
	serveEstablished(upstream, chosen, start, logTarget)
}

// forwardHTTP lets ReverseProxy serialize the target request only after the
// SOCKS tunnel exists. Rewrite emits origin-form rather than forwarding the
// absolute request target; Transport's one-use DialContext hands that already
// established tunnel to net/http, and DisableKeepAlives binds this request's
// transport lifetime to the pool hold and tunnel close record.
func (s *Server) forwardHTTP(client net.Conn, req *http.Request, upstream net.Conn, log zerolog.Logger, logTarget string, chosen *pool.Proxy, start time.Time, family proxyFamily) {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if upstream == nil {
				return nil, errors.New("HTTP forward transport tried to reuse a tunnel")
			}
			conn := upstream
			upstream = nil
			return conn, nil
		},
	}
	writer := newHTTPResponseWriter(client)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.RequestURI = ""
			// ReverseProxy owns RFC 7230 hop-by-hop removal. These two explicit
			// boundaries name data it cannot safely retain: the already-consumed
			// client credential and the gateway-private namespace it cannot know.
			pr.Out.Header.Del("Proxy-Authorization")
			stripEcomaControlHeaders(pr.Out.Header)
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, forwardErr error) {
			status := http.StatusBadGateway
			if errors.Is(forwardErr, context.Canceled) || errors.Is(forwardErr, context.DeadlineExceeded) {
				status = http.StatusGatewayTimeout
			}
			if !writer.wroteHeader {
				_ = writeHTTPError(w, status)
			}
			// This error is post-tunnel: it cannot retroactively change the route
			// health already recorded as successful. The error string is omitted
			// because transport errors can quote client-controlled request material.
			log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(chosen)).
				Str("error_kind", errorKindSetup).Msg("HTTP forward failed after tunnel establishment")
			// Stamped here so the terminal sample forwardHTTP writes after
			// ServeHTTP returns knows the client got this gateway's error page
			// rather than the origin's response.
			writer.failed = true
		},
	}
	proxy.ServeHTTP(writer, req)
	if upstream != nil {
		_ = upstream.Close()
	}
	// One terminal sample for the forwarded request, recorded here because this
	// is the only point its outcome is known: the response is on the wire and
	// the body has been counted. ok is whether the client got the origin's
	// response rather than this gateway's error page — a status code is not read
	// as a failure here, because a 4xx or 5xx from the target is a successfully
	// proxied request and counting it as one would make the analytics failure
	// rate mean something different from /status's.
	s.observeRequest(chosen, s.listener, familyLabel(family), logTarget, !writer.failed, writer.body, 0, time.Now())
	if writer.failed {
		// The forward failed after the tunnel existed, so it is a post-tunnel
		// error: the route's health was already reported successful and nothing
		// is retried. It is still an operator-visible failure of this gateway,
		// so it gets its own bucketed row with the same error kind the log used.
		s.observeFailure(chosen, s.listener, familyLabel(family), errorKindSetup, logTarget, time.Now())
	}
}
