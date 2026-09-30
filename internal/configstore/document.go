package configstore

import (
	"errors"
	"fmt"

	"rotation-proxy-gateway/internal/config"
)

// ErrUnknownDocumentVersion reports a document whose shape version this build
// does not implement — either one it never had or one newer than it understands.
// It is a hard failure, and it is deliberately the store's own error rather than
// config's: a caller reading history from a store another instance wrote may
// hit a version this instance does not implement, and that is a store-boundary
// condition long before it is a configuration one.
var ErrUnknownDocumentVersion = errors.New("unsupported config document version")

// Document is the durable, versioned configuration document as it crosses the
// store boundary: opaque bytes plus the version of their shape.
//
// The store never looks inside. Validation and interpretation belong to
// config.RuntimeFromDocument, which is what keeps this package free of
// configuration semantics — and what means a document written here is validated
// by exactly the same code a YAML config is.
//
// The bytes carry route credentials and rotate-API headers. Every method that
// accepts or returns one treats it as secret material: nothing here formats a
// Document into an error, and callers must not either.
type Document struct {
	// Version is the document-shape version — the document axis of the two
	// independent version numbers this package tracks. It is not the schema
	// migration version, and the two must never be compared against each other.
	Version int
	// JSON is the document itself.
	JSON []byte
}

// NewDocument encodes a validated RuntimeConfig into a versioned document. The
// inverse of Decode, and the only supported way to build one: encoding by hand
// would mean a writer could produce a document that bypasses the shape the
// decoder requires.
func NewDocument(cfg *config.RuntimeConfig) (Document, error) {
	body, err := config.MarshalDocument(cfg)
	if err != nil {
		return Document{}, err
	}
	if len(body) > MaxDocumentBytes {
		return Document{}, fmt.Errorf("%w: %d bytes (limit %d)", ErrDocumentTooLarge, len(body), MaxDocumentBytes)
	}
	return Document{Version: config.DocumentVersion, JSON: body}, nil
}

// Decode parses a stored document into the runtime configuration the gateway
// serves from, applying every existing validation rule.
//
// It is the only path from durable storage to a RuntimeConfig, and it is
// total: a document that survives Decode is one the gateway can serve, and one
// that does not is one that never reaches the serving path. A version this
// build does not implement is refused before the bytes are decoded — a reader
// that skipped fields it did not recognize would validate less than the writer
// did, which is how a too-new configuration turns into a silently weakened one.
func Decode(doc Document) (*config.RuntimeConfig, error) {
	if doc.Version != config.DocumentVersion {
		return nil, fmt.Errorf("%w: %d (this build implements %d)", ErrUnknownDocumentVersion, doc.Version, config.DocumentVersion)
	}
	if len(doc.JSON) == 0 {
		return nil, errors.New("config document is empty")
	}
	return config.RuntimeFromDocument(doc.JSON)
}
