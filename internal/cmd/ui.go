package cmd

import (
	"errors"
	"flag"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/lavr/portreach/internal/auth"
	"github.com/lavr/portreach/internal/discovery"
	"github.com/lavr/portreach/internal/ui"
)

func runUI(args []string, deps Deps) error {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(deps.Stderr)
	listen := fs.String("listen", ":8080", "address to listen on")
	agents := fs.String("agents", os.Getenv("PORTREACH_AGENTS"), "comma-separated static agent list host[:port] (env PORTREACH_AGENTS)")
	agentsDNS := fs.String("agents-dns", os.Getenv("PORTREACH_AGENTS_DNS"), "headless service name to resolve agents from (env PORTREACH_AGENTS_DNS)")
	agentPort := fs.Int("agent-port", envInt("PORTREACH_AGENT_PORT", 8732), "agent port for DNS-discovered and port-less agents (env PORTREACH_AGENT_PORT)")
	timeout := fs.Duration("timeout", 8*time.Second, "overall fan-out budget per check")
	authConfig := fs.String("auth-config", os.Getenv("PORTREACH_AUTH_CONFIG"), "path to SSO auth config YAML; empty = auth disabled (env PORTREACH_AUTH_CONFIG)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // -h/--help: flag already printed usage, exit cleanly
		}
		return &ExitError{Code: 2, Err: err}
	}

	disc, err := discovery.New(*agents, *agentsDNS, *agentPort, *agentPort, nil)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}

	// Auth is disabled by default: empty path = pass-through. When a config is
	// supplied we load and validate it early so misconfiguration fails fast.
	// (Middleware wiring lands in a later task.)
	if *authConfig != "" {
		cfg, err := auth.LoadConfig(*authConfig)
		if err != nil {
			return &ExitError{Code: 2, Err: err}
		}
		if err := cfg.Validate(); err != nil {
			return &ExitError{Code: 2, Err: err}
		}
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           ui.New(disc, *timeout).Handler(),
		ReadHeaderTimeout: 10 * time.Second, // bound slow-header (Slowloris) clients
	}
	return serveWithShutdown(srv, deps)
}

// envInt returns the integer value of env var name, or def when unset/invalid.
func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
