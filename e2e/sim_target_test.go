package e2e_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TargetSim is an HTTP(S) origin under test control: echo, fixed status,
// and header observation.
type TargetSim struct {
	Server *httptest.Server
	Host   string
	URL    string
}

// NewEchoTarget serves 200 with body "e2e-echo:<path>" for plain HTTP tests.
func NewEchoTarget(t testing.TB) *TargetSim {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "e2e-echo:%s", r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return fromServer(srv)
}

// NewStatusTarget serves a fixed status/body pair, including 407/429/5xx
// passthrough cases. It also sets a Proxy-Authorization response header that
// the gateway must strip before reaching the client.
func NewStatusTarget(t testing.TB, status int, body string) *TargetSim {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Proxy-Authorization", "must-not-reach-client")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return fromServer(srv)
}

// NewTLSEchoTarget serves an echo body over TLS for CONNECT-tunnel tests.
func NewTLSEchoTarget(t testing.TB) *TargetSim {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "e2e-tls-echo")
	}))
	t.Cleanup(srv.Close)
	return fromServer(srv)
}

// NewHeaderCaptureTarget records the headers the gateway forwards upstream.
func NewHeaderCaptureTarget(t testing.TB, seen chan<- http.Header) *TargetSim {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return fromServer(srv)
}

// ObservedRequest is one raw request-line and header observation at an origin.
// RequestLine comes from the wire before net/http normalizes the request target,
// so absolute-form forwarding tests can distinguish it from origin form.
type ObservedRequest struct {
	RequestLine string
	Host        string
	Header      http.Header
}

// NewRequestLineEchoTarget starts a raw HTTP origin that records the exact
// request line, parsed Host, and headers it receives. It writes a minimal
// HTTP/1.1 response itself instead of using net/http's server parser, which
// would discard the raw form this simulator needs to observe.
func NewRequestLineEchoTarget(t testing.TB) (*TargetSim, <-chan ObservedRequest) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan ObservedRequest, 32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
				head, err := textproto.NewReader(br).ReadMIMEHeader()
				if err != nil {
					return
				}
				parts := strings.SplitN(line, " ", 3)
				if len(parts) != 3 {
					return
				}
				select {
				case seen <- ObservedRequest{RequestLine: line, Host: head.Get("Host"), Header: http.Header(head)}:
				default:
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\norigin-ok")
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return &TargetSim{Host: ln.Addr().String(), URL: "http://" + ln.Addr().String()}, seen
}

// NewPipelinedEchoTarget starts a raw origin that echoes whatever bytes it
// receives. It exists for the CONNECT-pipelining regression: a client that
// writes its request head and its first payload in one syscall needs those
// payload bytes to survive the gateway's header parsing intact.
func NewPipelinedEchoTarget(t testing.TB) *TargetSim {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return &TargetSim{Host: ln.Addr().String(), URL: "http://" + ln.Addr().String()}
}

// ReadObservedRequest returns the next raw-origin observation, failing the
// test when no request arrives inside timeout.
func ReadObservedRequest(t testing.TB, seen <-chan ObservedRequest, timeout time.Duration) ObservedRequest {
	t.Helper()
	select {
	case obs := <-seen:
		return obs
	case <-time.After(timeout):
		t.Fatalf("origin recorded no request within %s", timeout)
		return ObservedRequest{}
	}
}

func fromServer(srv *httptest.Server) *TargetSim {
	u, _ := url.Parse(srv.URL)
	return &TargetSim{Server: srv, Host: u.Host, URL: srv.URL}
}

// BulkBodyTarget serves a fixed-size body for benchmark downloads.
func NewBulkBodyTarget(t testing.TB, size int) *TargetSim {
	t.Helper()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	s := fromServer(srv)
	return s
}

// NewSourceEchoTarget answers with the TCP source address it observes, so
// tests can tell which SOCKS route served a request.
func NewSourceEchoTarget(t testing.TB) *TargetSim {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		_, _ = io.WriteString(w, "source:"+host)
	}))
	t.Cleanup(srv.Close)
	return fromServer(srv)
}

// NewSlowBodyTarget streams half a body, holds the connection for hold, then
// completes it — a request that stays in flight while a rotation proceeds. The
// hold yields to teardown: closing stop (registered to run before srv.Close in
// the LIFO cleanup chain) wakes a parked handler, so a client that abandons
// the body unread never pins the test's cleanup for the remaining hold.
func NewSlowBodyTarget(t testing.TB, hold time.Duration) *TargetSim {
	t.Helper()
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "32")
		_, _ = io.WriteString(w, "0123456789abcdef")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-time.After(hold):
		case <-stop:
			return
		}
		_, _ = io.WriteString(w, "ghijklmnopqrstuv")
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(stop) })
	return fromServer(srv)
}

// NewEchoBodyTarget reads the whole request body and echoes it back; sized
// POST benchmarks use it to measure the full round trip.
func NewEchoBodyTarget(t testing.TB) *TargetSim {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return fromServer(srv)
}

// newHoldingTarget serves 200 with a small body only after the request context
// ends — which happens exactly when the gateway's client connection goes away.
// A request against it therefore models a tunnel that is genuinely long-lived:
// only the gateway can end it.
func newHoldingTarget(t testing.TB) *TargetSim {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return fromServer(srv)
}

// newDelayedTarget answers after a fixed delay, so a request in flight when a
// drain starts has something to complete.
func newDelayedTarget(t testing.TB, hold time.Duration) *TargetSim {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(hold)
		_, _ = fmt.Fprintf(w, "delayed:%s", hold)
	}))
	t.Cleanup(srv.Close)
	return fromServer(srv)
}
