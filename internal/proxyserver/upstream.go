package proxyserver

import (
	"context"
	"net"
	"net/url"
	"time"

	"rotation-proxy-gateway/internal/socksdial"
)

// The SOCKS dialer lives in internal/socksdial so the rotation engine can dial
// routes without importing the HTTP server. These aliases and helpers keep the
// proxyserver vocabulary intact.
type (
	ProxyDialError      = socksdial.ProxyDialError
	ProxyAuthError      = socksdial.ProxyAuthError
	SocksProtocolError  = socksdial.SocksProtocolError
	SocksHandshakeError = socksdial.SocksHandshakeError
	SocksReplyError     = socksdial.SocksReplyError
)

func isProxyDialError(err error) bool { return socksdial.IsDialError(err) }

func isProxyAuthError(err error) bool { return socksdial.IsAuthError(err) }

func isSocksHandshakeError(err error) bool { return socksdial.IsHandshakeError(err) }

// isConnectTargetError reports the target-scoped half of the handshake
// taxonomy: the endpoint answered CONNECT itself with a non-zero reply code,
// so the route works and only this (route, target) pair is refused.
func isConnectTargetError(err error) bool { return socksdial.IsConnectTargetError(err) }

// dialVia establishes a TCP connection to target through a SOCKS5 upstream,
// encoding target.Type as the CONNECT address type. The returned connection
// is ready for arbitrary byte transport.
func dialVia(ctx context.Context, pu *url.URL, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
	return socksdial.Dial(ctx, pu, target, timeout)
}

// dialTCP dials addr directly, wrapping endpoint failures as ProxyDialError.
func dialTCP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	return socksdial.DialTCP(ctx, addr, timeout)
}
