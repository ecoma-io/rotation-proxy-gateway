package e2e_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TargetSim is an HTTP(S) origin under test control: echo, fixed status,
// and header observation.
type TargetSim struct {
	Server *httptest.Server
	Host   string
	URL    string
}

// NewEchoTarget serves 200 with body "e2e-echo:<path>" for plain HTTP tests.
func NewEchoTarget(t *testing.T) *TargetSim {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "e2e-echo:%s", r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return fromServer(srv)
}

// NewStatusTarget serves a fixed status/body pair, including 407/429/5xx
// passthrough cases. It also sets a Proxy-Authorization response header that
// the gateway must strip before reaching the client.
func NewStatusTarget(t *testing.T, status int, body string) *TargetSim {
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
func NewTLSEchoTarget(t *testing.T) *TargetSim {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "e2e-tls-echo")
	}))
	t.Cleanup(srv.Close)
	return fromServer(srv)
}

// NewHeaderCaptureTarget records the headers the gateway forwards upstream.
func NewHeaderCaptureTarget(t *testing.T, seen chan<- http.Header) *TargetSim {
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
func NewBulkBodyTarget(t *testing.T, size int) *TargetSim {
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
