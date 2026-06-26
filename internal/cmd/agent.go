package cmd

import (
	"errors"
	"flag"
	"net/http"
	"time"

	"github.com/lavr/portreach/internal/agent"
)

func runAgent(args []string, deps Deps) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(deps.Stderr)
	listen := fs.String("listen", ":8732", "address to listen on")
	allow := fs.String("allow", "", "comma-separated allow CIDR list (empty = allow all)")
	deny := fs.String("deny", "", "comma-separated deny CIDR list (takes precedence over allow)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // -h/--help: flag already printed usage, exit cleanly
		}
		return &ExitError{Code: 2, Err: err}
	}

	policy, err := agent.ParsePolicy(*allow, *deny)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           agent.New("", policy).Handler(),
		ReadHeaderTimeout: 10 * time.Second, // bound slow-header (Slowloris) clients
	}
	return serveWithShutdown(srv, deps)
}
