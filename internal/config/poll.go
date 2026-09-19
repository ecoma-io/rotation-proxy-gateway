package config

import (
	"context"
	"crypto/sha256"
	"os"
	"time"

	"rotation-proxy-gateway/internal/sanitize"

	"github.com/rs/zerolog"
)

// DefaultPollInterval is how often the runtime config file is re-read and
// compared against the last applied content. Polling deliberately replaces
// event-based watching (Viper/fsnotify): reading and hashing the file detects
// changes under every mount style, including the single-file bind mounts that
// inotify cannot see through.
const DefaultPollInterval = time.Second

// Poller watches the runtime config file for content changes. It hashes the
// file's bytes instead of trusting events or timestamps, so in-place edits,
// atomic replacements, and directory or single-file bind mounts all behave
// identically. The one invisible case is a rename-over a single-file bind
// mount: the mount pins the old inode, so no in-process reader can observe
// the replacement (see README "Reload behavior").
type Poller struct {
	path     string
	interval time.Duration
	changes  chan struct{}
	last     [sha256.Size]byte
}

// NewPoller seeds the baseline with the content present now, so the initial
// load is never itself reported as a change and the first write after startup
// is always seen. The bootstrap load read this same file moments before, so a
// seed failure is a narrow race: the zero baseline makes the first successful
// read signal once, and that reload of identical content is harmless.
func NewPoller(path string, interval time.Duration, log zerolog.Logger) *Poller {
	last, err := hashFile(path)
	if err != nil {
		log.Debug().Str("error", sanitize.ErrorString(err)).Msg("config poll baseline seed skipped")
	}
	return &Poller{
		path:     path,
		interval: interval,
		changes:  make(chan struct{}, 1),
		last:     last,
	}
}

// Changes receives one coalesced signal per detected content change.
func (p *Poller) Changes() <-chan struct{} { return p.changes }

// Run polls until ctx is canceled. A read failure leaves both the baseline
// and the change channel untouched — a vanished file or a transient replace
// window must never fabricate a change — so the next successful read compares
// against the content that is actually serving.
func (p *Poller) Run(ctx context.Context, log zerolog.Logger) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sum, err := hashFile(p.path)
			if err != nil {
				log.Debug().Str("error", sanitize.ErrorString(err)).Msg("config poll read skipped")
				continue
			}
			if sum == p.last {
				continue
			}
			log.Debug().Msg("config file content changed; signaling reload")
			p.last = sum
			select {
			case p.changes <- struct{}{}:
			default: // a change is already pending; coalesce
			}
		}
	}
}

func hashFile(path string) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}
