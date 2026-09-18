package main

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"os"
	"time"

	"rotation-proxy-gateway/internal/sanitize"
)

// configPollInterval is how often the runtime config file is re-read and
// compared against the last applied content. Polling deliberately replaces
// event-based watching (Viper/fsnotify): reading and hashing the file detects
// changes under every mount style, including the single-file bind mounts that
// inotify cannot see through.
const configPollInterval = time.Second

// configWatcher polls the runtime config file for content changes. It hashes
// the file's bytes instead of trusting events or timestamps, so in-place
// edits, atomic replacements, and directory or single-file bind mounts all
// behave identically. The one invisible case is a rename-over a single-file
// bind mount: the mount pins the old inode, so no in-process reader can
// observe the replacement (see README "Reload behavior").
type configWatcher struct {
	path     string
	interval time.Duration
	changes  chan struct{}
	last     [sha256.Size]byte
}

// newConfigWatcher seeds the baseline with the content present now, so the
// initial load is never itself reported as a change and the first write after
// startup is always seen.
func newConfigWatcher(path string, interval time.Duration, log *slog.Logger) *configWatcher {
	return &configWatcher{
		path:     path,
		interval: interval,
		changes:  make(chan struct{}, 1),
		last:     hashFile(path, log),
	}
}

// Changes receives one coalesced signal per detected content change.
func (w *configWatcher) Changes() <-chan struct{} { return w.changes }

// Run polls until ctx is canceled. Read failures are skipped without logging
// at warn: a transient replace window must not spam, and the next successful
// read with different content signals exactly once.
func (w *configWatcher) Run(ctx context.Context, log *slog.Logger) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sum := hashFile(w.path, log)
			if sum == w.last {
				continue
			}
			w.last = sum
			select {
			case w.changes <- struct{}{}:
			default: // a change is already pending; coalesce
			}
		}
	}
}

func hashFile(path string, log *slog.Logger) [sha256.Size]byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Debug("config poll read skipped", "error", sanitize.ErrorString(err))
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(data)
}
