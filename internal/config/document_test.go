package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The document tests assert one property above all: a durable document is
// validated by exactly the same rules a YAML config is. Every "must reject"
// case below is a shape the file config rejects today, so a configuration that
// could not be written to config.yaml must not be writable to the store either.
// That equivalence is what keeps a move to durable storage from weakening
// validation.

// validDocument is the smallest document that decodes: one route and the four
// required scalar settings. Cases mutate a copy of it through edit.
const validDocument = `{
  "version": 1,
  "log-level": "info",
  "max-retries": 3,
  "cooldown": {"base": "15s", "max": "10m"},
  "dial-timeout": "10s",
  "proxies": {"auto": [{"proxy": "provider.example:1080", "kind": "v4"}]}
}`

// edit replaces one substring of the document. Panicking on a missing needle is
// correct in a test: a case whose fixture no longer contains what it means to
// replace has silently stopped testing anything.
func edit(t *testing.T, document, from, to string) []byte {
	t.Helper()
	if !strings.Contains(document, from) {
		t.Fatalf("fixture does not contain %q", from)
	}
	return []byte(strings.Replace(document, from, to, 1))
}

// countedDocument quotes every bare JSON number in data. The file config's
// anti-coercion checks demand a whole int; the document path narrows a whole
// JSON number back to one (see normalizeDocumentCounts) and leaves a fractional
// value for those checks to reject. Quoting the numbers here exercises the
// unmarshal → narrow → existing-validator path that every real document takes,
// instead of letting a numberless fixture hide a break in it.
func countedDocument(data []byte) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		panic("document fixture is not valid JSON: " + err.Error())
	}
	var out bytes.Buffer
	insideString := false
	escaped := false
	for i := 0; i < buf.Len(); i++ {
		c := buf.Bytes()[i]
		if escaped {
			escaped = false
			out.WriteByte(c)
			continue
		}
		switch {
		case c == '\\' && insideString:
			escaped = true
			out.WriteByte(c)
		case c == '"':
			insideString = !insideString
			out.WriteByte(c)
		case insideString:
			out.WriteByte(c)
		case c == '-' || (c >= '0' && c <= '9'):
			end := i
			for end < buf.Len() {
				d := buf.Bytes()[end]
				if d == '-' || d == '.' || d == 'e' || d == 'E' || d == '+' || (d >= '0' && d <= '9') {
					end++
					continue
				}
				break
			}
			out.Write(buf.Bytes()[i:end])
			i = end - 1
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

func TestDecodeDocumentAcceptsAValidDocument(t *testing.T) {
	cfg, err := DecodeDocument([]byte(validDocument))
	if err != nil {
		t.Fatalf("DecodeDocument: %v", err)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", cfg.MaxRetries)
	}
	if cfg.CooldownBase != 15*time.Second || cfg.CooldownMax != 10*time.Minute {
		t.Errorf("cooldown = %s/%s, want 15s/10m", cfg.CooldownBase, cfg.CooldownMax)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("len(Routes) = %d, want 1", len(cfg.Routes))
	}
	route := cfg.Routes[0]
	if route.URL.Host != "provider.example:1080" {
		t.Errorf("route host = %q, want provider.example:1080", route.URL.Host)
	}
	if route.Kind != EgressV4 {
		t.Errorf("route kind = %q, want v4", route.Kind)
	}
	// No routing block in the document means the unrestricted policy, not an
	// empty one. This is the documented spelling of "no routing block" and the
	// distinction matters: an empty block fails closed.
	if cfg.Routing != nil {
		t.Error("Routing is non-nil for a document with no routing block; want the unrestricted policy")
	}
}

// A round trip must be lossless, or a document that is read and written back
// would drift from the configuration it represents.
func TestMarshalDecodeRoundTrip(t *testing.T) {
	original, err := DecodeDocument([]byte(`{
      "version": 1,
      "log-level": "debug",
      "max-retries": 5,
      "cooldown": {"base": "1s", "max": "2m"},
      "dial-timeout": "3s",
      "proxies": {
        "auto": [
          {"id": "egress-a", "proxy": "user:pass@provider.example:1080", "kind": "v4"},
          {"id": "egress-b", "proxy": "[2001:db8::1]:1080:bob:other-secret", "kind": "v6"}
        ],
        "manual": [
          {"id": "rotating", "proxy": "carol:manual-secret@m.example:1080", "kind": "v4", "rotate-interval": "90s",
           "api": {"url": "https://rotate.example/api", "method": "POST",
                   "headers": {"Content-Type": "application/json", "X-Api-Token": "rot-token"},
                   "body": "{\"proxy_id\": 7}", "timeout": "7s"}}
        ]
      },
      "routing": {
        "rules": [{"match": {"domains": ["api.example.com", "*.openai.com"]}, "routes": ["egress-a"]}],
        "default-routes": ["rotating"]
      },
      "warm-pool": {"enabled": true, "min-idle-per-proxy": 2, "max-idle-per-proxy": 4},
      "rotation": {"max-concurrent": "50%", "ip-check-url": "https://if.example/trace"}
    }`))
	if err != nil {
		t.Fatalf("DecodeDocument: %v", err)
	}
	encoded, err := MarshalDocument(original)
	if err != nil {
		t.Fatalf("MarshalDocument: %v", err)
	}
	again, err := DecodeDocument(encoded)
	if err != nil {
		t.Fatalf("DecodeDocument after round trip: %v", err)
	}
	// Comparing the re-encoded bytes is the strongest form of the assertion: it
	// says the document is a fixed point, so storing one and reading it back
	// cannot drift on the next write.
	reencoded, err := MarshalDocument(again)
	if err != nil {
		t.Fatalf("MarshalDocument after round trip: %v", err)
	}
	if string(reencoded) != string(encoded) {
		t.Errorf("document is not a round-trip fixed point:\n first: %s\nsecond: %s", encoded, reencoded)
	}
	// And the settings that must survive a round trip, checked directly.
	if again.Routing == nil {
		t.Fatal("routing policy lost across the round trip")
	}
	if len(again.ManualRoutes) != 1 || again.ManualRoutes[0].RotateInterval != 90*time.Second {
		t.Errorf("manual route rotation interval lost: %+v", again.ManualRoutes)
	}
	if again.WarmPool.MinIdlePerProxy != 2 || !again.WarmPool.Enabled {
		t.Errorf("warm-pool settings lost: %+v", again.WarmPool)
	}
	if again.Rotation.IPCheckURL != "https://if.example/trace" {
		t.Errorf("rotation ip-check-url lost: %q", again.Rotation.IPCheckURL)
	}
}

// The document version is its own axis. A version this build does not implement
// is refused rather than partially understood, because a reader that skipped
// fields it did not recognize would validate less than the writer did.
func TestDecodeDocumentRejectsUnknownVersion(t *testing.T) {
	for _, version := range []string{"2", "99"} {
		t.Run(version, func(t *testing.T) {
			_, err := DecodeDocument(edit(t, string(countedDocument([]byte(validDocument))), `"version":1`, `"version":`+version))
			if err == nil {
				t.Fatalf("document version %s decoded; want refusal", version)
			}
			if !strings.Contains(err.Error(), "newer than this build supports") {
				t.Errorf("error %q does not explain that the document is too new", err)
			}
		})
	}
}

// A zero or absent version is not "version 1 by default". An unversioned
// document predates the versioning scheme and may carry a shape this build
// cannot reason about, so it is refused rather than assumed compatible.
func TestDecodeDocumentRejectsAbsentOrZeroVersion(t *testing.T) {
	cases := map[string][]byte{
		"zero":     edit(t, validDocument, `"version": 1`, `"version": 0`),
		"negative": edit(t, validDocument, `"version": 1`, `"version": -1`),
		"absent":   edit(t, validDocument, `"version": 1,`, ``),
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDocument(document); err == nil {
				t.Fatalf("a document with %s version decoded; want refusal", name)
			}
		})
	}
}

// A version that is not a number at all is refused too, and the error names the
// field rather than quoting the value: the version is not secret material, but
// a decode error that echoes raw bytes is the habit that eventually leaks one.
func TestDecodeDocumentRejectsNonNumericVersion(t *testing.T) {
	_, err := DecodeDocument(edit(t, validDocument, `"version": 1`, `"version": "one"`))
	if err == nil {
		t.Fatal("document with a string version decoded; want refusal")
	}
	if !strings.Contains(err.Error(), "must be") {
		t.Errorf("error %q does not report a type mismatch", err)
	}
}

// Every shape the file config rejects must be rejected here too. Each case is
// a document an operator could not have written to config.yaml.
func TestDecodeDocumentRejectsWhatTheFileConfigRejects(t *testing.T) {
	cases := []struct {
		name     string
		document []byte
		want     string
	}{
		{
			name:     "route line carrying a scheme",
			document: edit(t, validDocument, `"provider.example:1080"`, `"socks5://provider.example:1080"`),
			want:     "carry no scheme",
		},
		{
			name:     "route line carrying an https scheme",
			document: edit(t, validDocument, `"provider.example:1080"`, `"https://provider.example:1080"`),
			want:     "carry no scheme",
		},
		{
			name:     "zero port",
			document: edit(t, validDocument, `"provider.example:1080"`, `"provider.example:0"`),
			want:     "invalid proxy port",
		},
		{
			name:     "port above the range",
			document: edit(t, validDocument, `"provider.example:1080"`, `"provider.example:70000"`),
			want:     "invalid proxy port",
		},
		{
			name:     "missing port",
			document: edit(t, validDocument, `"provider.example:1080"`, `"provider.example"`),
			want:     "invalid proxy format",
		},
		{
			name:     "kind outside v4 and v6",
			document: edit(t, validDocument, `"kind": "v4"`, `"kind": "v5"`),
			want:     "kind must be exactly v4 or v6",
		},
		{
			name:     "absent kind",
			document: edit(t, validDocument, `, "kind": "v4"`, ``),
			want:     "kind must be exactly v4 or v6",
		},
		{
			name:     "retired global block",
			document: []byte(`{"version":1,"global":{"target-tls-insecure":true},"log-level":"info","max-retries":3,` + `"cooldown":{"base":"15s","max":"10m"},"dial-timeout":"10s",` + `"proxies":{"auto":[{"proxy":"p.example:1080","kind":"v4"}]}}`),
			want:     "unknown fields",
		},
		{
			name:     "retired global target-tls-insecure",
			document: []byte(`{"version":1,"global":{"target-tls-insecure":true},"log-level":"info","max-retries":3,` + `"cooldown":{"base":"15s","max":"10m"},"dial-timeout":"10s",` + `"proxies":{"auto":[{"proxy":"p.example:1080","kind":"v4"}]}}`),
			want:     "removed HTTP-era global block",
		},
		{
			name:     "retired weight on a route",
			document: edit(t, validDocument, `"kind": "v4"`, `"kind": "v4", "weight": 5`),
			want:     "removed weighted-selection key",
		},
		{
			name: "retired balance block",
			document: []byte(`{"version":1,"balance":{"strategy":"weighted"},"log-level":"info","max-retries":3,` +
				`"cooldown":{"base":"15s","max":"10m"},"dial-timeout":"10s",` +
				`"proxies":{"auto":[{"proxy":"p.example:1080","kind":"v4"}]}}`),
			want: "removed weighted-selection block",
		},
		{
			name:     "no routes at all",
			document: edit(t, validDocument, `"proxies": {"auto": [{"proxy": "provider.example:1080", "kind": "v4"}]}`, `"proxies": {"auto": []}`),
			want:     "at least one route",
		},
		{
			name:     "duplicate route identity",
			document: edit(t, validDocument, `"auto": [{"proxy": "provider.example:1080", "kind": "v4"}]`, `"auto": [{"proxy": "provider.example:1080", "kind": "v4"},{"proxy": "provider.example:1080", "kind": "v4"}]`),
			want:     "duplicate route",
		},
		{
			name:     "empty log level",
			document: edit(t, validDocument, `"log-level": "info"`, `"log-level": ""`),
			want:     "log-level must be one of",
		},
		{
			name:     "zero max-retries",
			document: edit(t, validDocument, `"max-retries": 3`, `"max-retries": 0`),
			want:     "max-retries must be >= 1",
		},
		{
			name:     "fractional max-retries",
			document: edit(t, validDocument, `"max-retries": 3`, `"max-retries": 2.5`),
			want:     "must be a whole number",
		},
		{
			name:     "cooldown base above max",
			document: edit(t, validDocument, `"base": "15s", "max": "10m"`, `"base": "20m", "max": "10m"`),
			want:     "must not exceed cooldown.max",
		},
		{
			name:     "unparseable dial timeout",
			document: edit(t, validDocument, `"dial-timeout": "10s"`, `"dial-timeout": "ten seconds"`),
			want:     "must be a Go duration",
		},
		{
			name:     "explicitly empty route id",
			document: edit(t, validDocument, `"proxy": "provider.example:1080"`, `"id": "", "proxy": "provider.example:1080"`),
			want:     "route id must not be empty",
		},
		{
			name:     "duplicate route ids",
			document: edit(t, validDocument, `"auto": [{"proxy": "provider.example:1080", "kind": "v4"}]`, `"auto": [{"id":"a","proxy": "provider.example:1080", "kind": "v4"},{"id":"a","proxy":"other.example:1080","kind":"v4"}]`),
			want:     "already used by another route",
		},
		{
			name:     "fractional warm-pool bound",
			document: edit(t, validDocument, `"dial-timeout": "10s"`, `"dial-timeout": "10s", "warm-pool": {"min-idle-per-proxy": 1.5}`),
			want:     "must be a whole number",
		},
		{
			name:     "fractional rotation max-concurrent",
			document: edit(t, validDocument, `"dial-timeout": "10s"`, `"dial-timeout": "10s", "rotation": {"max-concurrent": 2.5}`),
			want:     "must be a count or a percent",
		},
		{
			name:     "routing rule on an unnamed route",
			document: edit(t, validDocument, `"dial-timeout": "10s"`, `"dial-timeout": "10s", "routing": {"rules": [{"match": {"domains": ["a.example.com"]}, "routes": ["a"]}]}`),
			want:     "every serving route to carry an id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeDocument(tc.document)
			if err == nil {
				t.Fatalf("document decoded; want rejection mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// Unknown keys are refused rather than ignored, at every depth. An ignored key
// is a silently dropped setting, which is how a retired key would survive a move
// into durable storage.
func TestDecodeDocumentRejectsUnknownKeysAtEveryDepth(t *testing.T) {
	cases := map[string][]byte{
		"top level":   edit(t, validDocument, `"version": 1,`, `"version": 1, "surprise": true,`),
		"route entry": edit(t, validDocument, `"kind": "v4"`, `"kind": "v4", "surprise": true`),
		"nested block": edit(t, validDocument, `"cooldown": {"base": "15s", "max": "10m"}`,
			`"cooldown": {"base": "15s", "max": "10m", "surprise": true}`),
		"inside a route list": edit(t, validDocument, `"auto": [`,
			`"auto": [{"surprise": true}, `),
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeDocument(document)
			if err == nil {
				t.Fatal("document with an unknown key decoded; want rejection")
			}
			if !strings.Contains(err.Error(), "unknown fields") || !strings.Contains(err.Error(), "surprise") {
				t.Errorf("error %q should name the unknown key", err)
			}
		})
	}
}

// A key that merely appears inside a value is not a key. The unknown-key walk
// decodes structure rather than scanning text, so a string value carrying
// "weight" must not be mistaken for the retired weighted-selection key.
func TestDecodeDocumentDoesNotTreatStringValuesAsKeys(t *testing.T) {
	document := edit(t, validDocument, `"log-level": "info"`, `"log-level": "weight balance global"`)
	if _, err := DecodeDocument(document); err == nil {
		t.Fatal("document decoded; log-level is not a valid level")
	} else if strings.Contains(err.Error(), "unknown fields") {
		t.Errorf("error %q reports an unknown field for a string value", err)
	}
}

// The document is a single object, not a stream. A truncated-then-appended
// document must not parse as valid.
func TestDecodeDocumentRejectsTrailingContent(t *testing.T) {
	_, err := DecodeDocument([]byte(validDocument + `{"version":1}`))
	if err == nil {
		t.Fatal("a document with trailing content decoded; want rejection")
	}
	if !strings.Contains(err.Error(), "exactly one JSON object") {
		t.Errorf("error %q does not explain the trailing content", err)
	}
}

// A rejected document must not echo its content. Documents carry route
// credentials and rotate-API headers, so an error that quotes the offending
// value would put a secret into a log.
func TestDecodeDocumentErrorsNeverQuoteContent(t *testing.T) {
	// A malformed document whose bytes contain a credential-shaped string.
	secret := "sup3rsecret"
	document := []byte(`{"version":1,"proxies":{"auto":[{"proxy":"user:` + secret + `@p.example:1080","kind":"v4"},]}}`)
	_, err := DecodeDocument(document)
	if err == nil {
		t.Fatal("malformed document decoded; want rejection")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error quotes document content: %q", err)
	}
}

// The same holds for an invalid route line: the error names the field and the
// index to fix, never the credential in it.
func TestDecodeDocumentDoesNotLeakRouteCredentials(t *testing.T) {
	secret := "hunter2"
	document := edit(t, validDocument, `"provider.example:1080"`, `"user:`+secret+`@provider.example:0"`)
	_, err := DecodeDocument(document)
	if err == nil {
		t.Fatal("document with a zero port decoded; want rejection")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error quotes the route credential: %q", err)
	}
}

// MarshalDocument refuses a nil configuration rather than encoding a document
// that could never serve.
func TestMarshalDocumentRejectsNil(t *testing.T) {
	if _, err := MarshalDocument(nil); err == nil {
		t.Fatal("MarshalDocument(nil) succeeded; want an error")
	}
}
