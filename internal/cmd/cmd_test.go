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

func TestRunAgentEnabledChecksUnknownName(t *testing.T) {
	assertExit(t, []string{"agent", "--enabled-checks=tcp,mysql"}, 2)
}

func TestRunAgentEnabledChecksPostgresRequiresToken(t *testing.T) {
	// No --auth-token / PORTREACH_AGENT_TOKEN and postgres enabled → config
	// error (fail-closed), regardless of what's in the ambient environment.
	t.Setenv("PORTREACH_AGENT_TOKEN", "")
	assertExit(t, []string{"agent", "--enabled-checks=postgres"}, 2)
}

func TestRunAgentEnabledChecksPostgresWithTokenPassesValidation(t *testing.T) {
	// postgres enabled + a token set must clear config validation; the bad
	// listen address then fails at bind (exit 1), proving the exit 2 path
	// above was specifically about the missing token, not the flag itself.
	// This also covers "tcp can be disabled": enabled-checks names postgres
	// only, with no tcp.
	assertExit(t, []string{"agent", "--enabled-checks=postgres", "--auth-token=s3cr3t", "--listen=127.0.0.1:99999"}, 1)
}

func TestRunAgentEnabledChecksDefaultIsTCPOnly(t *testing.T) {
	// Default --enabled-checks (tcp only) needs no token; config validation
	// passes and the bad listen address fails at bind (exit 1), not exit 2.
	t.Setenv("PORTREACH_AGENT_TOKEN", "")
	assertExit(t, []string{"agent", "--listen=127.0.0.1:99999"}, 1)
}

func TestRunAgentEnabledChecksBlankIsStartupError(t *testing.T) {
	// An explicitly blank --enabled-checks parses without error (see
	// checkapi.ParseEnabledChecks) but leaves nothing for Handler to route —
	// since the agent now registers a check endpoint per Has(name), that must
	// be a startup configuration error rather than a silently-empty agent.
	assertExit(t, []string{"agent", "--enabled-checks="}, 2)
}

func TestRunAgentEnabledChecksEnvMirror(t *testing.T) {
	// PORTREACH_ENABLED_CHECKS=postgres with no token reaches the same
	// fail-closed error as the flag form, proving the env mirror is wired.
	t.Setenv("PORTREACH_ENABLED_CHECKS", "postgres")
	t.Setenv("PORTREACH_AGENT_TOKEN", "")
	assertExit(t, []string{"agent"}, 2)
}

func TestRunUIEnabledChecksUnknownName(t *testing.T) {
	assertExit(t, []string{"ui", "--agents=a:1", "--enabled-checks=tcp,mysql"}, 2)
}

func TestRunUIEnabledChecksPostgresRequiresToken(t *testing.T) {
	t.Setenv("PORTREACH_AGENT_TOKEN", "")
	assertExit(t, []string{"ui", "--agents=a:1", "--enabled-checks=postgres"}, 2)
}

func TestRunUIEnabledChecksPostgresWithTokenPassesValidation(t *testing.T) {
	assertExit(t, []string{"ui", "--agents=a:1", "--enabled-checks=postgres", "--agent-token=s3cr3t", "--listen=127.0.0.1:99999"}, 1)
}

func TestRunUIEnabledChecksDefaultIsTCPOnly(t *testing.T) {
	t.Setenv("PORTREACH_AGENT_TOKEN", "")
	assertExit(t, []string{"ui", "--agents=a:1", "--listen=127.0.0.1:99999"}, 1)
}

func TestRunUIEnabledChecksEnvMirror(t *testing.T) {
	t.Setenv("PORTREACH_ENABLED_CHECKS", "postgres")
	t.Setenv("PORTREACH_AGENT_TOKEN", "")
	assertExit(t, []string{"ui", "--agents=a:1"}, 2)
}

func TestRunUIEnabledChecksBlankIsStartupError(t *testing.T) {
	// An explicitly blank --enabled-checks parses without error (see
	// checkapi.ParseEnabledChecks) but leaves nothing for Handler to route —
	// since the UI now registers a check route per Has(name) (Task 7), that
	// must be a startup configuration error rather than a silently-empty UI,
	// mirroring the agent's identical check.
	assertExit(t, []string{"ui", "--agents=a:1", "--enabled-checks="}, 2)
}

func TestEnvString(t *testing.T) {
	t.Setenv("PORTREACH_TEST_ENABLED_CHECKS", "postgres")
	if got := envString("PORTREACH_TEST_ENABLED_CHECKS", "tcp"); got != "postgres" {
		t.Fatalf("envString = %q, want postgres", got)
	}
	t.Setenv("PORTREACH_TEST_ENABLED_CHECKS", "")
	if got := envString("PORTREACH_TEST_ENABLED_CHECKS", "tcp"); got != "tcp" {
		t.Fatalf("envString unset = %q, want fallback tcp", got)
	}
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
