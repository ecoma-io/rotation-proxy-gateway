package coord

import (
	"bufio"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// lineReader consumes a subprocess's output line by line, retaining everything
// so a failure can show the whole transcript.
//
// The two-process tests need to observe events a helper reports while the test
// is blocked elsewhere — a lease acquired, a commit refused — so a plain pipe
// read would deadlock the helper once its pipe buffer filled. Each line is
// therefore appended under a lock and offered to any waiter as it arrives.
type lineReader struct {
	mu    sync.Mutex
	lines []string
	// notify is closed and replaced each time a line is appended, so a waiter
	// can select on it without missing a line that arrived first.
	notify chan struct{}
}

func newLineReader(r io.Reader) *lineReader {
	lr := &lineReader{notify: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			lr.append(sc.Text())
		}
		lr.close()
	}()
	return lr
}

func (lr *lineReader) append(line string) {
	lr.mu.Lock()
	lr.lines = append(lr.lines, line)
	ch := lr.notify
	lr.notify = make(chan struct{})
	lr.mu.Unlock()
	close(ch)
}

func (lr *lineReader) close() {
	lr.mu.Lock()
	ch := lr.notify
	lr.notify = make(chan struct{})
	lr.mu.Unlock()
	close(ch)
}

// all returns the transcript so far.
func (lr *lineReader) all() string {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	return strings.Join(lr.lines, "\n")
}

// waitFor blocks until a line containing marker appears, returning it.
func (lr *lineReader) waitFor(marker string, d time.Duration) (string, bool) {
	deadline := time.Now().Add(d)
	scanned := 0
	for {
		lr.mu.Lock()
		for ; scanned < len(lr.lines); scanned++ {
			if strings.Contains(lr.lines[scanned], marker) {
				line := lr.lines[scanned]
				lr.mu.Unlock()
				return line, true
			}
		}
		ch := lr.notify
		lr.mu.Unlock()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", false
		}
		timer := time.NewTimer(remaining)
		select {
		case <-ch:
			timer.Stop()
		case <-timer.C:
			return "", false
		}
	}
}

// waitForField blocks until a line carries `key=`, returning the line and the
// value.
func (lr *lineReader) waitForField(key string, d time.Duration) (string, string) {
	deadline := time.Now().Add(d)
	scanned := 0
	for {
		lr.mu.Lock()
		for ; scanned < len(lr.lines); scanned++ {
			line := lr.lines[scanned]
			if v, ok := fieldValue(line, key); ok {
				lr.mu.Unlock()
				return line, v
			}
		}
		ch := lr.notify
		lr.mu.Unlock()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", ""
		}
		timer := time.NewTimer(remaining)
		select {
		case <-ch:
			timer.Stop()
		case <-timer.C:
			return "", ""
		}
	}
}

// fieldValue extracts `key=value` from a line, where the value runs to the next
// space. The helper writes space-separated key=value pairs precisely so this
// stays trivial and unambiguous.
func fieldValue(line, key string) (string, bool) {
	for _, field := range strings.Fields(line) {
		if v, ok := strings.CutPrefix(field, key+"="); ok {
			return v, true
		}
	}
	return "", false
}

// parseTokenLine extracts the fencing token from a helper's acquisition line.
func parseTokenLine(line string) (uint64, bool) {
	for _, field := range strings.Fields(line) {
		if v, ok := strings.CutPrefix(field, "token="); ok {
			n, err := strconv.ParseUint(v, 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// freeLoopbackAddr reserves and releases a loopback port, returning its address.
//
// The helper listens on it purely so the parent has a readiness signal: a bound
// listener means the process got far enough to start polling, which removes the
// race of the parent talking to a helper that has not opened its store yet.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// helperConfig is the helper process's configuration, passed through the
// environment so no secret is ever an argv entry (argv is world-readable in /proc).
type helperConfig struct {
	Addr          string
	Namespace     string
	Listen        string
	LeaseName     string
	Route         string
	WaitForCommit bool
	WatchInterval time.Duration
}

// env renders the configuration as environment entries.
func (c helperConfig) env() []string {
	out := []string{
		"RPGW_HELPER_REDIS=" + c.Addr,
		"RPGW_HELPER_NAMESPACE=" + c.Namespace,
		"RPGW_HELPER_LISTEN=" + c.Listen,
		"RPGW_HELPER_LEASE=" + c.LeaseName,
		"RPGW_HELPER_ROUTE=" + c.Route,
	}
	if c.WaitForCommit {
		out = append(out, "RPGW_HELPER_WAIT=1")
	}
	if c.WatchInterval > 0 {
		out = append(out, "RPGW_HELPER_WATCH="+c.WatchInterval.String())
	}
	return out
}

// envOr returns an environment variable, for the helper's own reads.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
