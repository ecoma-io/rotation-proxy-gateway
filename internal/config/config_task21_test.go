package config

import (
	"strings"
	"testing"
)

func TestTask21CooldownBaseMustNotExceedMax(t *testing.T) {
	t.Setenv("COOLDOWN_BASE", "10m")
	t.Setenv("COOLDOWN_MAX", "15s")
	_, err := Load()
	if err == nil {
		t.Fatalf("Load() with COOLDOWN_BASE=10m > COOLDOWN_MAX=15s succeeded, want rejection")
	}
	if !strings.Contains(err.Error(), "COOLDOWN_BASE") || !strings.Contains(err.Error(), "COOLDOWN_MAX") {
		t.Fatalf("error %q must mention COOLDOWN_BASE and COOLDOWN_MAX", err)
	}
}
