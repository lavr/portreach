package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/lavr/portreach/internal/version"
)

func newDeps() (Deps, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return Deps{Stdout: &out, Stderr: &errb}, &out, &errb
}

func TestRunVersion(t *testing.T) {
	prev := version.Get()
	t.Cleanup(func() { version.Set(prev) })
	version.Set("1.2.3")
	for _, arg := range []string{"version", "--version", "-v"} {
		deps, out, _ := newDeps()
		if err := Run([]string{arg}, deps); err != nil {
			t.Fatalf("%s: unexpected error: %v", arg, err)
		}
		if got := strings.TrimSpace(out.String()); got != "1.2.3" {
			t.Errorf("%s: got version %q, want %q", arg, got, "1.2.3")
		}
	}
}

func TestRunHelp(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		deps, out, _ := newDeps()
		if err := Run([]string{arg}, deps); err != nil {
			t.Fatalf("%s: unexpected error: %v", arg, err)
		}
		if !strings.Contains(out.String(), "Usage:") {
			t.Errorf("%s: help output missing usage, got %q", arg, out.String())
		}
	}
}

func TestRunNoCommand(t *testing.T) {
	deps, _, errb := newDeps()
	err := Run(nil, deps)
	if err == nil {
		t.Fatal("expected error for no command")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T", err)
	}
	if ee.Code != 2 {
		t.Errorf("got exit code %d, want 2", ee.Code)
	}
	if !strings.Contains(errb.String(), "Usage:") {
		t.Errorf("expected usage on stderr, got %q", errb.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	deps, _, errb := newDeps()
	err := Run([]string{"frobnicate"}, deps)
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T", err)
	}
	if ee.Code != 2 {
		t.Errorf("got exit code %d, want 2", ee.Code)
	}
	if !strings.Contains(ee.Error(), "frobnicate") {
		t.Errorf("error should mention the command, got %q", ee.Error())
	}
	if !strings.Contains(errb.String(), "Usage:") {
		t.Errorf("expected usage on stderr, got %q", errb.String())
	}
}

func TestRunNilWritersNoPanic(t *testing.T) {
	if err := Run([]string{"version"}, Deps{}); err != nil {
		t.Fatalf("unexpected error with nil writers: %v", err)
	}
}

func TestExitErrorUnwrap(t *testing.T) {
	inner := errors.New("boom")
	ee := &ExitError{Code: 3, Err: inner}
	if !errors.Is(ee, inner) {
		t.Error("ExitError should unwrap to its inner error")
	}
	if ee.Error() != "boom" {
		t.Errorf("got %q, want %q", ee.Error(), "boom")
	}
	bare := &ExitError{Code: 5}
	if !strings.Contains(bare.Error(), "5") {
		t.Errorf("bare ExitError should mention code, got %q", bare.Error())
	}
}

// assertExit runs Run and asserts it returns an *ExitError with the given code.
func assertExit(t *testing.T, args []string, wantCode int) {
	t.Helper()
	deps, _, _ := newDeps()
	err := Run(args, deps)
	if err == nil {
		t.Fatalf("%v: expected error, got nil", args)
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("%v: expected *ExitError, got %T", args, err)
	}
	if ee.Code != wantCode {
		t.Errorf("%v: exit code = %d, want %d", args, ee.Code, wantCode)
	}
}

func TestRunAgentBadFlags(t *testing.T) {
	assertExit(t, []string{"agent", "--allow=not-a-cidr"}, 2) // invalid policy
	assertExit(t, []string{"agent", "--nonexistent-flag"}, 2) // flag parse error
}

func TestRunUIBadFlags(t *testing.T) {
	assertExit(t, []string{"ui", "--agents=a:1", "--agents-dns=svc"}, 2) // both set
	assertExit(t, []string{"ui"}, 2)                                     // neither set
	assertExit(t, []string{"ui", "--nonexistent-flag"}, 2)               // flag parse error
}

func TestRunAgentServeError(t *testing.T) {
	// An out-of-range port makes ListenAndServe fail immediately, exercising the
	// serveWithShutdown error path without hanging on a real listener.
	assertExit(t, []string{"agent", "--listen=127.0.0.1:99999"}, 1)
}

func TestEnvInt(t *testing.T) {
	t.Setenv("PORTREACH_AGENT_PORT", "9001")
	if got := envInt("PORTREACH_AGENT_PORT", 8732); got != 9001 {
		t.Fatalf("envInt = %d, want 9001", got)
	}
	t.Setenv("PORTREACH_AGENT_PORT", "not-a-number")
	if got := envInt("PORTREACH_AGENT_PORT", 8732); got != 8732 {
		t.Fatalf("envInt invalid = %d, want fallback 8732", got)
	}
	if got := envInt("PORTREACH_UNSET_VAR", 8732); got != 8732 {
		t.Fatalf("envInt unset = %d, want fallback 8732", got)
	}
}
