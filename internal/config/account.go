package config

import (
	"errors"
	"strings"
)

// InboundAccount is the validated RPGW_ACCOUNT pair: the username and
// password every proxy listener demands from clients as HTTP
// Proxy-Authorization: Basic credentials. A nil *InboundAccount keeps the
// documented no-authentication default. Bytes rather than strings so the
// comparison is constant-time without a per-request conversion.
type InboundAccount struct {
	Username []byte
	Password []byte
}

// parseAccount validates a raw RPGW_ACCOUNT value. The shape is
// "username:password" split at the first colon, so a password may itself
// contain colons; the username is 1-255 bytes and the password 0-255 bytes —
// the RFC 1929 field limits this configuration inherited. Errors are static
// on purpose: the offending value is a credential, and quoting it would leak
// into boot logs, the same discipline checkPort applies to route lines.
func parseAccount(raw string) (*InboundAccount, error) {
	user, pass, ok := strings.Cut(raw, ":")
	if !ok {
		return nil, errors.New("must be username:password (split at the first colon)")
	}
	if len(user) == 0 || len(user) > 255 {
		return nil, errors.New("username must be 1-255 bytes")
	}
	if len(pass) > 255 {
		return nil, errors.New("password must be 0-255 bytes")
	}
	return &InboundAccount{Username: []byte(user), Password: []byte(pass)}, nil
}
