// Package cmd implements the portreach subcommand dispatcher.
package cmd

import (
	"fmt"
	"io"

	"github.com/lavr/portreach/internal/version"
)

// ExitError carries a process exit code from a subcommand back to main.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit code %d", e.Code)
}

func (e *ExitError) Unwrap() error {
	return e.Err
}

// Deps holds the externally-supplied dependencies for command execution.
type Deps struct {
	Stdout io.Writer
	Stderr io.Writer
}

const usage = `portreach — distributed network reachability checker

Usage:
  portreach <command> [flags]

Commands:
  agent      run the probe HTTP server (one per point)
  ui         run the aggregator + web form
  version    print the version
  help       show this help

Run "portreach <command> --help" for command-specific flags.
`

// Run dispatches args[0] to the matching subcommand. args is os.Args[1:].
func Run(args []string, deps Deps) error {
	if deps.Stdout == nil {
		deps.Stdout = io.Discard
	}
	if deps.Stderr == nil {
		deps.Stderr = io.Discard
	}

	if len(args) == 0 {
		_, _ = fmt.Fprint(deps.Stderr, usage)
		return &ExitError{Code: 2, Err: fmt.Errorf("no command given")}
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "version", "--version", "-v":
		_, _ = fmt.Fprintln(deps.Stdout, version.Get())
		return nil
	case "help", "--help", "-h":
		_, _ = fmt.Fprint(deps.Stdout, usage)
		return nil
	case "agent":
		return runAgent(rest, deps)
	case "ui":
		return runUI(rest, deps)
	default:
		_, _ = fmt.Fprint(deps.Stderr, usage)
		return &ExitError{Code: 2, Err: fmt.Errorf("unknown command %q", cmd)}
	}
}
