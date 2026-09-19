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

	// A vanished file is one change (the reload attempt logs the sanitized
	// warning and keeps serving); it must not signal every tick.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	waitChange("delete")
	select {
	case <-p.Changes():
		t.Fatal("deleted file signaled more than once")
	case <-time.After(100 * time.Millisecond):
	}
}
