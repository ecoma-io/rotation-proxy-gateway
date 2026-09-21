package e2e_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
