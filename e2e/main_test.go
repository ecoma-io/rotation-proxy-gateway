package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// testBinaryPath is the real gateway binary built once for the whole e2e
// package. Tests exercise the binary as a subprocess so config parsing,
// listener startup, hot reload, and logging match production behavior.
var testBinaryPath string

func shortMode() bool {
	for _, arg := range os.Args {
		if arg == "-test.short" || arg == "-test.short=true" {
			return true
		}
	}
	return false
}

func TestMain(m *testing.M) {
	if shortMode() {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "rpgw-e2e-bin")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	out := filepath.Join(dir, "rpgw")
	build := exec.Command("go", "build", "-o", out, "rotation-proxy-gateway/cmd/rotation-proxy-gateway")
	if output, err := build.CombinedOutput(); err != nil {
		panic("build gateway binary for e2e: " + err.Error() + "\n" + string(output))
	}
	testBinaryPath = out
	os.Exit(m.Run())
}
