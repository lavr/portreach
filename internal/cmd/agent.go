package cmd

import (
	"errors"
	"flag"
	"net/http"
	"os"
	"time"

	"github.com/lavr/portreach/internal/agent"
)

func runAgent(args []string, deps Deps) error {
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(deps.Stderr)
	listen := fs.String("listen", ":8732", "address to listen on")
	allow := fs.String("allow", "", "comma-separated allow CIDR list (empty = allow all)")
	deny := fs.String("deny", "", "comma-separated deny CIDR list (takes precedence over allow)")
	authToken := fs.String("auth-token", os.Getenv("PORTREACH_AGENT_TOKEN"), "shared bearer token required on /check and /metrics; empty = open (env PORTREACH_AGENT_TOKEN)")
	metricsPublic := fs.Bool("metrics-public", envBool("PORTREACH_AGENT_METRICS_PUBLIC", false), "leave /metrics open for scraping even when a token is set; /check stays gated (env PORTREACH_AGENT_METRICS_PUBLIC)")
	allowMetadata := fs.Bool("allow-metadata", envBool("PORTREACH_AGENT_ALLOW_METADATA", false), "remove the built-in cloud-metadata/link-local (169.254.0.0/16, fd00:ec2::254) connect guard; operator --deny still applies (env PORTREACH_AGENT_ALLOW_METADATA)")
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
		Handler:           agent.New("", policy, agent.WithToken(*authToken), agent.WithMetricsPublic(*metricsPublic), agent.WithAllowMetadata(*allowMetadata)).Handler(),
		ReadHeaderTimeout: 10 * time.Second, // bound slow-header (Slowloris) clients
	}
	return serveWithShutdown(srv, deps)
}
