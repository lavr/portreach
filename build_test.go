package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMakeBuildSmoke builds the binary via `make build` and checks that the
// resulting `portreach version` prints a non-empty version string.
func TestMakeBuildSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build smoke test in -short mode")
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not available")
	}

	out, err := exec.Command("make", "build").CombinedOutput()
	if err != nil {
		t.Fatalf("make build failed: %v\n%s", err, out)
	}

	bin := filepath.Join("dist", "portreach")
	out, err = exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("%s version failed: %v\n%s", bin, err, out)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Fatalf("expected version output, got empty")
	}
}
