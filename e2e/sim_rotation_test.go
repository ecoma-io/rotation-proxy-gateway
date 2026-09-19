package e2e_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TraceSim plays the ip-check endpoint: an HTTPS server that answers trace
// bodies whose ip= line is under test control, per source address. The
// gateway's rotation probes always TLS-verify, so the sim mints its own CA,
// serves a leaf for 127.0.0.1 signed by it, and exposes the CA file — tests
// pass it to the gateway subprocess via SSL_CERT_FILE.
//
// Per-source state models different providers (one per SOCKS route): the sim
// keys the reported IP by the TCP source address it observes, and route sims
// bind distinct loopback addresses (127.0.2.x) for their tunnels.
type TraceSim struct {
	srv    *http.Server
	ln     net.Listener
	CAFile string
	URL    string

	mu     sync.Mutex
	byIP   map[string]string // source address -> reported egress IP
	calls  map[string]int    // source address -> probe count
	defalt string            // reported to unmarked sources

	Hits atomic.Uint64
}

// NewTraceSim starts the HTTPS trace endpoint on 127.0.0.1:0, reporting
// initial to every source until a test overrides it.
func NewTraceSim(t testing.TB, initial string) *TraceSim {
	t.Helper()
	caFile, caCert, caKey := mintCA(t)
	leaf := mintLeaf(t, caCert, caKey)
	cert := tls.Certificate{Certificate: leaf.der, PrivateKey: leaf.key, Leaf: leaf.cert}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &TraceSim{
		ln:     ln,
		CAFile: caFile,
		URL:    fmt.Sprintf("https://%s/trace", ln.Addr().String()),
		byIP:   map[string]string{},
		calls:  map[string]int{},
		defalt: initial,
	}
	s.srv = &http.Server{
		Handler: http.HandlerFunc(s.serve),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	go func() { _ = s.srv.Serve(tls.NewListener(ln, s.srv.TLSConfig)) }()
	t.Cleanup(func() { _ = s.srv.Close() })
	return s
}

// SetIP makes the endpoint report ip to the given loopback source (the
// Outbound address of the SOCKS route sim). An empty source sets the default.
func (s *TraceSim) SetIP(source, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if source == "" {
		s.defalt = ip
		return
	}
	s.byIP[source] = ip
}

// Calls reports how many probes a source (or "" for the default) has made.
func (s *TraceSim) Calls(source string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[source]
}

func (s *TraceSim) serve(w http.ResponseWriter, r *http.Request) {
	s.Hits.Add(1)
	source := ""
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		source = host
	}
	s.mu.Lock()
	s.calls[source]++
	ip, ok := s.byIP[source]
	if !ok {
		ip = s.defalt
	}
	s.mu.Unlock()
	_, _ = fmt.Fprintf(w, "loc=XX\nip=%s\ntls=1.3\n", ip)
}

type mintedKey struct {
	der  [][]byte
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// mintCA creates a self-signed CA and writes its PEM to the test temp dir.
func mintCA(t testing.TB) (string, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rpgw e2e test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "trace-ca.pem")
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(file, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return file, cert, key
}

// mintLeaf signs a server certificate for 127.0.0.1 and localhost.
func mintLeaf(t testing.TB, ca *x509.Certificate, caKey *ecdsa.PrivateKey) mintedKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return mintedKey{der: [][]byte{der, ca.Raw}, key: key, cert: cert}
}

// RotateAPISim plays a provider rotate endpoint: plain HTTP, scripted status,
// delay, and Retry-After, with per-call concurrency observation and an
// onCall hook where tests flip trace IPs (the provider rotates on request).
type RotateAPISim struct {
	srv *httptest.Server
	URL string

	Hits     atomic.Uint64
	maxFast  atomic.Int64
	inFlight atomic.Int64
	SawToken atomic.Bool // an expected X-Api-Token reached the sim

	// Status selects the response code; 0 means 200.
	Status atomic.Int64
	// Hang delays the response, modeling a slow provider API.
	Hang time.Duration
	// RetryAfter, when non-empty, is sent as a Retry-After header.
	RetryAfter atomic.Value // string
	// onCall runs when the request arrives, before the scripted response.
	onCall func()

	tmu   sync.Mutex
	times []time.Time
}

// NewRotateAPISim starts the rotate endpoint on 127.0.0.1:0.
func NewRotateAPISim(t testing.TB) *RotateAPISim {
	t.Helper()
	s := &RotateAPISim{}
	s.RetryAfter.Store("")
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Hits.Add(1)
		s.tmu.Lock()
		s.times = append(s.times, time.Now())
		s.tmu.Unlock()
		if r.Header.Get("X-Api-Token") != "" {
			s.SawToken.Store(true)
		}
		cur := s.inFlight.Add(1)
		defer s.inFlight.Add(-1)
		for {
			max := s.maxFast.Load()
			if cur <= max || s.maxFast.CompareAndSwap(max, cur) {
				break
			}
		}
		if s.onCall != nil {
			s.onCall()
		}
		if s.Hang > 0 {
			time.Sleep(s.Hang)
		}
		if ra, _ := s.RetryAfter.Load().(string); ra != "" {
			w.Header().Set("Retry-After", ra)
		}
		status := int(s.Status.Load())
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(s.srv.Close)
	s.URL = s.srv.URL
	return s
}

// MaxConcurrent reports the highest number of overlapping calls observed.
func (s *RotateAPISim) MaxConcurrent() int64 { return s.maxFast.Load() }

// OnCall registers a hook run at the arrival of each call.
func (s *RotateAPISim) OnCall(fn func()) { s.onCall = fn }

// ForceClose drops every live client connection so cleanup does not wait out
// a parked (hung) rotate call.
func (s *RotateAPISim) ForceClose() { s.srv.CloseClientConnections() }

// Times reports when each call arrived, for retry-cadence assertions.
func (s *RotateAPISim) Times() []time.Time {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	return append([]time.Time(nil), s.times...)
}
