package cmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
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

	handler, err := buildUIHandler(disc, *timeout, *authConfig, deps.Stdout)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second, // bound slow-header (Slowloris) clients
	}
	return serveWithShutdown(srv, deps)
}

// buildUIHandler assembles the UI HTTP handler, wrapping it in the SSO auth
// middleware when an auth config is supplied and enabled. Auth is disabled by
// default: an empty path or a provider-less config yields the raw,
// unauthenticated UI (backward compatible). A malformed or invalid enabled
// config returns an error so runUI can fail fast with exit code 2.
func buildUIHandler(disc discovery.Discoverer, timeout time.Duration, authConfigPath string, out io.Writer) (http.Handler, error) {
	handler := ui.New(disc, timeout).Handler()

	if authConfigPath == "" {
		return handler, nil
	}

	cfg, err := auth.LoadConfig(authConfigPath)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled() {
		// A config file with no providers is valid and leaves the UI open.
		return handler, nil
	}

	authn, err := auth.New(cfg)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		ids = append(ids, p.ID)
	}
	_, _ = fmt.Fprintf(out, "ui: SSO auth enabled; providers: %s\n", strings.Join(ids, ", "))

	return authn.Middleware(handler), nil
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
