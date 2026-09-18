package e2e_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// SocksMode selects how the simulator answers SOCKS5 requests.
type SocksMode int

const (
	// SocksOK tunnels to the requested target like a healthy provider.
	SocksOK SocksMode = iota
	// SocksAuthRequired demands username/password and rejects bad creds.
	SocksAuthRequired
	// SocksRejectTarget answers the CONNECT request with 0x05 (refused),
	// modeling a post-dial setup failure: no health change, no retry.
	SocksRejectTarget
)

// SocksSim is a minimal configurable SOCKS5 server for e2e. It speaks only
// enough RFC 1928/1929 to exercise the gateway's dial/auth/setup paths.
type SocksSim struct {
	ln   net.Listener
	User string
	Pass string
	Mode SocksMode

	Hits atomic.Uint64
	Addr string
}

// NewSocksSim starts the simulator on 127.0.0.1:0.
func NewSocksSim(t testing.TB, mode SocksMode, user, pass string) *SocksSim {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &SocksSim{ln: ln, User: user, Pass: pass, Mode: mode, Addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

// RouteValue renders the config proxy line for this simulator.
func (s *SocksSim) RouteValue() string {
	if s.User != "" {
		return fmt.Sprintf("socks5://%s:%s@%s", s.User, s.Pass, s.Addr)
	}
	return "socks5://" + s.Addr
}

func (s *SocksSim) handle(conn net.Conn) {
	defer conn.Close()
	s.Hits.Add(1)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if s.Mode == SocksAuthRequired {
		offersAuth := false
		for _, m := range methods {
			if m == 0x02 {
				offersAuth = true
			}
		}
		if !offersAuth {
			_, _ = conn.Write([]byte{0x05, 0xff})
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x01 {
			return
		}
		ub := make([]byte, hdr[1])
		if _, err := io.ReadFull(br, ub); err != nil {
			return
		}
		pb, err := br.ReadByte()
		if err != nil {
			return
		}
		pw := make([]byte, pb)
		if _, err := io.ReadFull(br, pw); err != nil {
			return
		}
		if string(ub) != s.User || string(pw) != s.Pass {
			_, _ = conn.Write([]byte{0x01, 0x01})
			return
		}
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 || req[1] != 0x01 {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		n, err := br.ReadByte()
		if err != nil {
			return
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, portBytes); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(portBytes[0])<<8|int(portBytes[1])))

	if s.Mode == SocksRejectTarget {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if n := br.Buffered(); n > 0 {
		b := make([]byte, n)
		_, _ = io.ReadFull(br, b)
		_, _ = up.Write(b)
	}
	go func() {
		_, _ = io.Copy(up, conn)
		_ = up.Close()
	}()
	_, _ = io.Copy(conn, up)
}
