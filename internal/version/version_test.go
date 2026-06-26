package version

import "testing"

func TestSet(t *testing.T) {
	orig := Get()
	t.Cleanup(func() { version = orig })

	Set("1.2.3")
	if got := Get(); got != "1.2.3" {
		t.Fatalf("Get() = %q, want 1.2.3", got)
	}

	// An empty ldflags value must not wipe the version.
	Set("")
	if got := Get(); got != "1.2.3" {
		t.Errorf("Set(\"\") changed version to %q, want it unchanged at 1.2.3", got)
	}
}
