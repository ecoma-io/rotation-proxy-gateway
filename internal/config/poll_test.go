package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/logging"
)

func TestPollerDetectsContentChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := logging.Nop()
	p := NewPoller(path, 5*time.Millisecond, log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx, log)

	waitChange := func(what string) {
		t.Helper()
		select {
		case <-p.Changes():
		case <-time.After(2 * time.Second):
			t.Fatalf("no change signal for %s", what)
		}
	}

	// In-place write (truncate+write): the case inotify cannot see through a
	// single-file bind mount and the reason polling replaced it.
	if err := os.WriteFile(path, []byte("a: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitChange("in-place write")

	// Atomic replace (tmp + rename): the editor/updater pattern.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("a: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	waitChange("atomic replace")

	// Rewriting identical content is not a change.
	if err := os.WriteFile(path, []byte("a: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Changes():
		t.Fatal("identical content produced a change signal")
	case <-time.After(100 * time.Millisecond):
	}

	// A vanished file fabricates no change at all: the baseline keeps pointing
	// at the content that is actually serving, so no signal fires while it is
	// gone and no reload attempt is made for it.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Changes():
		t.Fatal("deleted file produced a change signal")
	case <-time.After(100 * time.Millisecond):
	}
}

// A read failure must not corrupt the applied-content baseline: while the file
// is unreadable no signal fires, and once it is readable again the comparison
// resumes against the pre-failure content — restored unchanged stays quiet,
// real new content signals exactly once.
func TestPollerReadFailureKeepsBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := logging.Nop()
	p := NewPoller(path, 5*time.Millisecond, log)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx, log)

	assertQuiet := func(what string, window time.Duration) {
		t.Helper()
		select {
		case <-p.Changes():
			t.Fatalf("unexpected change signal while %s", what)
		case <-time.After(window):
		}
	}

	// Content below is replaced atomically (tmp + rename). An in-place
	// truncate+write leaves a readable empty window between the truncate and
	// the write, and a tick landing inside it fires a second, legitimate
	// change once the real content appears — the exactly-once guarantee this
	// test asserts only holds across a reader-atomic transition.
	replaceFile := func(content string) {
		t.Helper()
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}

	// Put a directory where the file was: reads fail for any uid, simulating
	// a hostile replace window lasting several ticks.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	assertQuiet("unreadable", 60*time.Millisecond)

	// Restore the file with unchanged content. A poller that had clobbered
	// its baseline on the read errors would signal this harmless state.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	replaceFile("a: 1\n")
	assertQuiet("restored unchanged", 60*time.Millisecond)

	// A real content change still signals, exactly once.
	replaceFile("a: 2\n")
	select {
	case <-p.Changes():
	case <-time.After(2 * time.Second):
		t.Fatal("no change signal for the content change after the read failures")
	}
	assertQuiet("second tick after the change", 60*time.Millisecond)
}
