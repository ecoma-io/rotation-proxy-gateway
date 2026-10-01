package config

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// Strict unknown-key rejection for the durable configuration document.
//
// encoding/json ignores a field it does not recognize, which would let a
// retired key survive a move into durable storage in silence — the exact
// failure the YAML path prevents with viper's UnmarshalExact. The document gets
// the same treatment from the same rule, spelled once here as an allowlist of
// the document's own key names.
//
// The allowlist is a literal description of the document shape rather than a
// reflection of it: the nested jsonKey form is what makes it possible to walk
// to the depth a typo was written at, and a derived list could only check the
// top level. Keeping it here, next to the shape it describes, is what makes a
// new field a deliberate addition rather than an accident of a struct tag.
var documentKeyAllowlist = keySet{
	"version":      nil,
	"log-level":    nil,
	"max-retries":  nil,
	"dial-timeout": nil,
	"cooldown": {
		"base": nil,
		"max":  nil,
	},
	"rotation": {
		"max-concurrent":    nil,
		"drain-timeout":     nil,
		"rotate-on-start":   nil,
		"ip-check-url":      nil,
		"ip-check-timeout":  nil,
		"ip-check-interval": nil,
		"retry-backoff-max": nil,
	},
	"warm-pool": {
		"enabled":                   nil,
		"min-idle-per-proxy":        nil,
		"max-idle-per-proxy":        nil,
		"max-total-idle":            nil,
		"max-replenish-concurrency": nil,
		"max-replenish-per-route":   nil,
		"idle-ttl":                  nil,
	},
	"proxies": {
		"auto": {
			"id":    nil,
			"proxy": nil,
			"kind":  nil,
		},
		"manual": {
			"id":              nil,
			"proxy":           nil,
			"kind":            nil,
			"rotate-interval": nil,
			"api": {
				"url":     nil,
				"method":  nil,
				"headers": nil,
				"body":    nil,
				"timeout": nil,
			},
		},
	},
	"routing": {
		"default-routes": nil,
		"rules": {
			"match": {
				"domains": nil,
			},
			"routes": nil,
		},
	},
}

// keySet is an allowlist node: key name to the key set accepted below it. A nil
// entry means the key is a scalar or an array and is not walked further; a
// non-nil one is what an object at that key may contain.
type keySet map[string]keySet

// unknownJSONKeys returns the dotted paths of every key in data that the
// document shape does not define, sorted so the report is deterministic.
//
// It walks the decoded structure rather than scanning text, so a key that
// happens to appear inside a string value is not mistaken for a key. Values are
// never included in the output: a document holds route credentials and
// rotate-API tokens, and a rejected document must not echo any of them back.
func unknownJSONKeys(data []byte) []string {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		// The strict decode already reported the malformed document; this pass
		// adds nothing.
		return nil
	}
	var unknown []string
	collectUnknownKeys(root, "", documentKeyAllowlist, &unknown)
	sort.Strings(unknown)
	return unknown
}

// collectUnknownKeys walks one object against the key set allowed at its depth.
// path is the dotted prefix used to name a key precisely, because "weight" is
// ambiguous in an error without knowing which route list it was written under.
func collectUnknownKeys(node map[string]json.RawMessage, path string, allowed keySet, unknown *[]string) {
	for key, raw := range node {
		children, known := allowed[key]
		// A key that is not defined at this depth is reported and not walked:
		// its value is by definition an unknown shape, and descending into it
		// would produce a cascade of names the operator never wrote.
		if !known {
			*unknown = append(*unknown, join(path, key))
			continue
		}
		if len(children) == 0 {
			continue
		}
		childPath := join(path, key)
		// A key may hold either an object or an array of objects (routes,
		// rules); both shapes are walked against the same key set.
		for _, element := range objectsAt(raw) {
			collectUnknownKeys(element, childPath, children, unknown)
		}
	}
}

// objectsAt unwraps raw into the set of JSON objects it contains: the object
// itself, or the elements of an array of objects. Anything else — a scalar, a
// null, an array of scalars — yields nothing to walk, because a key set is
// meaningless for a value that is not an object and json.Unmarshal's own type
// errors already cover a shape mismatch.
func objectsAt(raw json.RawMessage) []map[string]json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '{':
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return nil
		}
		return []map[string]json.RawMessage{object}
	case '[':
		var array []json.RawMessage
		if err := json.Unmarshal(trimmed, &array); err != nil {
			return nil
		}
		var out []map[string]json.RawMessage
		for _, element := range array {
			out = append(out, objectsAt(element)...)
		}
		return out
	default:
		return nil
	}
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// retiredKeys names the configuration keys this project removed, so the
// document's unknown-key error says what happened rather than leaving the
// operator to guess which key is wrong. They are rejected by the allowlist
// above like any other unknown key; this only improves the message.
var retiredKeys = map[string]string{
	"global":              "the removed HTTP-era global block (target-tls-insecure, max-body-buffer)",
	"target-tls-insecure": "the removed HTTP-era global block (target-tls-insecure, max-body-buffer)",
	"max-body-buffer":     "the removed HTTP-era global block (target-tls-insecure, max-body-buffer)",
	"weight":              "the removed weighted-selection key; selection is round-robin over the eligible set",
	"balance":             "the removed weighted-selection block; selection is round-robin over the eligible set",
}

// describeUnknownKeys renders unknown key paths with, where one applies, the
// reason a key of that name was retired. The names come from the allowlist's
// complement — they are literal key names in the submitted document — so no
// document value is ever quoted.
func describeUnknownKeys(keys []string) string {
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		// A dotted path's leaf is the key an operator typed, so a retired key
		// under a route list is still recognized.
		name := key
		if idx := strings.LastIndex(name, "."); idx >= 0 {
			name = name[idx+1:]
		}
		if reason, retired := retiredKeys[name]; retired {
			parts = append(parts, key+" ("+reason+")")
			continue
		}
		parts = append(parts, key)
	}
	return strings.Join(parts, ", ")
}
