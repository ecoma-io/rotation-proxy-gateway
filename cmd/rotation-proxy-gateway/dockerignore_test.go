package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The Dockerfile's builder stage runs `COPY . .`, so every file the build
// context admits lands in the builder layer, where it persists in local build
// cache and travels with any `--cache-to` export even though the final
// scratch image stays clean. The documented credential files are
// `config.yaml` (routes, rotate-API credentials) and `.env` (bootstrap
// values, including RPGW_ACCOUNT): `.dockerignore` must keep both out of the
// context, while `.env.example` is documentation and must stay in it. These
// tests pin both directions — a dropped pattern and an over-broad one each
// fail loudly (issue #41). They only read the file: no Docker daemon, no
// build, no network.

// dockerignorePatterns returns the active patterns (non-empty, non-comment
// lines) of the repository-root .dockerignore.
func dockerignorePatterns(t *testing.T) []string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this test file")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", ".dockerignore")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var patterns []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	if len(patterns) == 0 {
		t.Fatalf("%s contains no active patterns", path)
	}
	return patterns
}

// matchingPattern returns the first pattern that matches name, or "" when
// none does. filepath.Match is exact enough here: the file's patterns are
// plain names, and a Docker-only extension (** or a ! re-include) never
// matches a plain file name, so a reported match is always a real match.
func matchingPattern(patterns []string, name string) string {
	for _, p := range patterns {
		if ok, err := filepath.Match(p, name); err == nil && ok {
			return p
		}
	}
	return ""
}

func TestDockerignoreExcludesCredentialFiles(t *testing.T) {
	patterns := dockerignorePatterns(t)
	for _, cred := range []string{"config.yaml", ".env"} {
		if matchingPattern(patterns, cred) == "" {
			t.Errorf(
				".dockerignore must exclude %q — a documented credential file that COPY . . would bake into the builder layer; patterns = %v",
				cred, patterns,
			)
		}
	}
}

func TestDockerignoreKeepsEnvExample(t *testing.T) {
	patterns := dockerignorePatterns(t)
	if p := matchingPattern(patterns, ".env.example"); p != "" {
		t.Errorf(
			".dockerignore pattern %q also excludes .env.example, which is documentation and belongs in the context; use the literal .env",
			p,
		)
	}
}

func TestDockerignoreExcludesNodeModules(t *testing.T) {
	patterns := dockerignorePatterns(t)
	if matchingPattern(patterns, "node_modules") == "" {
		t.Errorf(
			".dockerignore must exclude node_modules — a local dev artifact that only bloats the build context; patterns = %v",
			patterns,
		)
	}
}
