package cmd

import (
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/lavr/portreach/internal/agent"
	"github.com/lavr/portreach/internal/checkapi"
	"github.com/lavr/portreach/internal/ratelimit"
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
	rateLimit := fs.Bool("rate-limit", envBool("PORTREACH_RATE_LIMIT", false), "enable the /check rate limiter (defence-in-depth for direct calls); off = unlimited (env PORTREACH_RATE_LIMIT)")
	rateTargetRate := fs.Float64("rate-target-rate", envFloat("PORTREACH_RATE_TARGET_RATE", 0), "per-target (host:port) tokens/sec; 0 disables (env PORTREACH_RATE_TARGET_RATE)")
	rateTargetBurst := fs.Int("rate-target-burst", envInt("PORTREACH_RATE_TARGET_BURST", 0), "per-target bucket capacity (env PORTREACH_RATE_TARGET_BURST)")
	rateGlobalRate := fs.Float64("rate-global-rate", envFloat("PORTREACH_RATE_GLOBAL_RATE", 0), "process-wide tokens/sec; 0 disables (env PORTREACH_RATE_GLOBAL_RATE)")
	rateGlobalBurst := fs.Int("rate-global-burst", envInt("PORTREACH_RATE_GLOBAL_BURST", 0), "process-wide bucket capacity (env PORTREACH_RATE_GLOBAL_BURST)")
	enabledChecksFlag := fs.String("enabled-checks", envString("PORTREACH_ENABLED_CHECKS", checkapi.DefaultEnabledChecks), "comma-separated checks this agent serves: tcp, postgres (env PORTREACH_ENABLED_CHECKS)")
	disablePostgresRateLimit := fs.Bool("disable-postgres-rate-limit", envBool("PORTREACH_AGENT_DISABLE_POSTGRES_RATE_LIMIT", false), "disable the built-in postgres-specific rate limiter (auto-on with the postgres check: per-target 12/min burst 3, global 60/min burst 10); it layers on top of --rate-limit, not a replacement for it (env PORTREACH_AGENT_DISABLE_POSTGRES_RATE_LIMIT)")
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

	enabledChecks, err := checkapi.ParseEnabledChecks(*enabledChecksFlag)
	if err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	// Routing (Handler) registers a check endpoint per enabledChecks.Has(name),
	// so a blank/empty set would silently come up serving no check endpoint at
	// all — almost certainly a configuration mistake, not an intentional
	// deployment. Fail fast rather than let it through.
	if err := enabledChecks.RequireNonEmpty(); err != nil {
		return &ExitError{Code: 2, Err: err}
	}
	// Fail closed: postgres checks accept a username/password and forward them to
	// a dialed-out server, so serving them without a shared token would let
	// anyone on the network run authenticated probes through this agent for free.
	if err := enabledChecks.RequireTokenForPostgres(*authToken, "--auth-token", "PORTREACH_AGENT_TOKEN"); err != nil {
		return &ExitError{Code: 2, Err: err}
	}

	// Build the optional /check limiter. Unset (--rate-limit off) leaves it nil =
	// unlimited (today's behaviour); when enabled, an invalid config fails fast.
	// The agent has no per-user identity, so only the per-target and global
	// scopes apply.
	var limiter *ratelimit.Limiter
	if *rateLimit {
		limiter, err = ratelimit.New(ratelimit.Config{
			Enabled: true,
			Target:  ratelimit.Scope{Rate: *rateTargetRate, Burst: *rateTargetBurst},
			Global:  ratelimit.Scope{Rate: *rateGlobalRate, Burst: *rateGlobalBurst},
		})
		if err != nil {
			return &ExitError{Code: 2, Err: err}
		}
	}

	// Structured JSON audit logger for the postgres check trail (matches the UI's
	// audit pipeline in ui.go). Without this the agent falls back to slog.Default
	// (text to stderr); wiring it here makes the audit output structured JSON.
	logger := slog.New(slog.NewJSONHandler(deps.Stdout, nil))

	srv := &http.Server{
		Addr:              *listen,
		Handler:           agent.New("", policy, agent.WithToken(*authToken), agent.WithMetricsPublic(*metricsPublic), agent.WithAllowMetadata(*allowMetadata), agent.WithLimiter(limiter), agent.WithEnabledChecks(enabledChecks), agent.WithDisablePostgresRateLimit(*disablePostgresRateLimit), agent.WithLogger(logger)).Handler(),
		ReadHeaderTimeout: 10 * time.Second, // bound slow-header (Slowloris) clients
	}
	return serveWithShutdown(srv, deps)
}
