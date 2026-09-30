package configstore

import (
	"strings"
	"testing"

	"rotation-proxy-gateway/internal/config"
)

// The migration machinery is exercised without a database wherever it can be:
// loadMigrations, parseMigrationName and checksum are pure functions over the
// embedded assets, and their refusal cases are exactly the ones a corrupted or
// misnamed migration file would produce in a real deployment.

// migrationsUnderTest exposes the embedded set to the pure tests without a
// database connection.
func migrationsUnderTest(t *testing.T) []migration {
	t.Helper()
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	return migrations
}

func TestLoadMigrationsOrdersByVersion(t *testing.T) {
	migrations := migrationsUnderTest(t)
	if len(migrations) == 0 {
		t.Fatal("no embedded migrations")
	}
	for i := 1; i < len(migrations); i++ {
		if migrations[i-1].Version >= migrations[i].Version {
			t.Fatalf("migrations are not ordered by version: %d then %d", migrations[i-1].Version, migrations[i].Version)
		}
	}
	// The document version and the schema version are different axes. This
	// assertion does not couple them — it only records that the schema's
	// newest version is what a future migration must beat.
	if migrations[0].Version != 1 {
		t.Errorf("first migration version = %d, want 1", migrations[0].Version)
	}
}

func TestParseMigrationName(t *testing.T) {
	cases := []struct {
		filename  string
		wantVer   int
		wantName  string
		wantError string
	}{
		{filename: "0001_config_revisions.sql", wantVer: 1, wantName: "config_revisions"},
		{filename: "0042_add_routing_index.sql", wantVer: 42, wantName: "add_routing_index"},
		{filename: "no_version.sql", wantError: "positive integer version"},
		{filename: "abcd_name.sql", wantError: "positive integer version"},
		{filename: "0_name.sql", wantError: "positive integer version"},
		{filename: "-1_name.sql", wantError: "positive integer version"},
		{filename: "0001_.sql", wantError: "must be named NNNN_description.sql"},
		{filename: "0001.sql", wantError: "must be named NNNN_description.sql"},
	}
	for _, tc := range cases {
		t.Run(tc.filename, func(t *testing.T) {
			version, name, err := parseMigrationName(tc.filename)
			if tc.wantError != "" {
				if err == nil {
					t.Fatalf("parseMigrationName(%q) accepted it; want %q", tc.filename, tc.wantError)
				}
				if !strings.Contains(err.Error(), tc.wantError) {
					t.Errorf("error %q does not mention %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMigrationName(%q): %v", tc.filename, err)
			}
			if version != tc.wantVer || name != tc.wantName {
				t.Errorf("= (%d, %q), want (%d, %q)", version, name, tc.wantVer, tc.wantName)
			}
		})
	}
}

// The checksum exists to catch an edited migration. A one-byte edit anywhere in
// the file has to change it, or tamper detection is decorative.
func TestChecksumChangesOnAnyEdit(t *testing.T) {
	base := []byte("CREATE TABLE example (id bigint);")
	original := checksum(base)
	if checksum([]byte("CREATE TABLE example (id bigint)")) == original {
		t.Error("checksum ignores a trailing-whitespace edit")
	}
	// A single changed byte in the middle, the case a hand edit produces.
	edited := []byte("CREATE TABLE example (id bigint);")
	edited[len(edited)/2] = 'X'
	if checksum(edited) == original {
		t.Error("checksum ignores a one-byte edit in the middle")
	}
	if len(original) != 64 {
		t.Errorf("checksum length = %d, want 64 hex characters", len(original))
	}
}

// Every embedded migration must be checksum-stable across runs, or a boot would
// refuse to start against a schema it had itself created.
func TestEmbeddedMigrationChecksumsAreStable(t *testing.T) {
	first := migrationsUnderTest(t)
	second := migrationsUnderTest(t)
	for i := range first {
		if first[i].Checksum != second[i].Checksum {
			t.Errorf("migration %d checksum changed between loads", first[i].Version)
		}
		if first[i].Checksum == "" {
			t.Errorf("migration %d has an empty checksum", first[i].Version)
		}
	}
}

// Document version handling is a store-boundary concern: a revision written by
// a newer instance must be refused, not partially read.
func TestDecodeRejectsUnknownDocumentVersion(t *testing.T) {
	valid, err := validDocument(t)
	if err != nil {
		t.Fatalf("building a valid document: %v", err)
	}
	for _, version := range []int{0, -1, config.DocumentVersion + 1, 99} {
		doc := Document{Version: version, JSON: valid.JSON}
		if _, err := Decode(doc); err == nil {
			t.Errorf("Decode accepted document version %d; want refusal", version)
		} else if version > config.DocumentVersion && !strings.Contains(err.Error(), "this build implements") {
			t.Errorf("error %q does not report the implemented version", err)
		}
	}
}

func TestDecodeAcceptsTheCurrentDocumentVersion(t *testing.T) {
	valid, err := validDocument(t)
	if err != nil {
		t.Fatalf("building a valid document: %v", err)
	}
	cfg, err := Decode(valid)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if cfg.MaxRetries != 2 {
		t.Errorf("MaxRetries = %d, want 2", cfg.MaxRetries)
	}
}

func TestDecodeRejectsAnEmptyDocument(t *testing.T) {
	if _, err := Decode(Document{Version: config.DocumentVersion}); err == nil {
		t.Fatal("Decode accepted an empty document; want refusal")
	}
}

// Revision.String is what goes into /status and the logs, so it must identify
// the revision without carrying anything from the document.
func TestRevisionStringCarriesNoDocumentContent(t *testing.T) {
	if got := Revision(7).String(); got != "revision-7" {
		t.Errorf("Revision(7).String() = %q, want revision-7", got)
	}
	if got := NoRevision.String(); got != "revision-0" {
		t.Errorf("NoRevision.String() = %q, want revision-0", got)
	}
	if NoRevision.IsValid() {
		t.Error("NoRevision.IsValid() is true; it must not be a valid expectation")
	}
	if !Revision(1).IsValid() {
		t.Error("Revision(1).IsValid() is false; the first committed revision must be valid")
	}
}
