package cmd

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lavr/portreach/internal/auth"
	"github.com/lavr/portreach/internal/discovery"
	"github.com/lavr/portreach/internal/ratelimit"
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
	agentToken := fs.String("agent-token", os.Getenv("PORTREACH_AGENT_TOKEN"), "shared bearer token sent to agents on /check; empty = no token (env PORTREACH_AGENT_TOKEN)")
	uiTitle := fs.String("ui-title", os.Getenv("PORTREACH_UI_TITLE"), "HTML page heading; empty when explicitly set suppresses it (env PORTREACH_UI_TITLE)")
	uiDescription := fs.String("ui-description", os.Getenv("PORTREACH_UI_DESCRIPTION"), "HTML block rendered under the page heading (env PORTREACH_UI_DESCRIPTION)")
	uiFooter := fs.String("ui-footer", os.Getenv("PORTREACH_UI_FOOTER"), "HTML footer block rendered at the bottom of the page (env PORTREACH_UI_FOOTER)")
	loginTitle := fs.String("login-title", os.Getenv("PORTREACH_LOGIN_TITLE"), "HTML login/denied browser title; empty when explicitly set keeps localized tab title (env PORTREACH_LOGIN_TITLE)")
	loginHeader := fs.String("login-header", os.Getenv("PORTREACH_LOGIN_HEADER"), "HTML login/denied heading; empty when explicitly set suppresses it (env PORTREACH_LOGIN_HEADER)")
	loginFooter := fs.String("login-footer", os.Getenv("PORTREACH_LOGIN_FOOTER"), "HTML footer block rendered on the login page (env PORTREACH_LOGIN_FOOTER)")
	rateLimit := fs.Bool("rate-limit", envBool("PORTREACH_RATE_LIMIT", false), "enable the API rate limiter; off = unlimited (env PORTREACH_RATE_LIMIT)")
	rateUserRate := fs.Float64("rate-user-rate", envFloat("PORTREACH_RATE_USER_RATE", 0), "per-identity tokens/sec; 0 disables this scope (env PORTREACH_RATE_USER_RATE)")
	rateUserBurst := fs.Int("rate-user-burst", envInt("PORTREACH_RATE_USER_BURST", 0), "per-identity bucket capacity (env PORTREACH_RATE_USER_BURST)")
	rateTargetRate := fs.Float64("rate-target-rate", envFloat("PORTREACH_RATE_TARGET_RATE", 0), "per-target (host:port) tokens/sec; 0 disables (env PORTREACH_RATE_TARGET_RATE)")
	rateTargetBurst := fs.Int("rate-target-burst", envInt("PORTREACH_RATE_TARGET_BURST", 0), "per-target bucket capacity (env PORTREACH_RATE_TARGET_BURST)")
	rateGlobalRate := fs.Float64("rate-global-rate", envFloat("PORTREACH_RATE_GLOBAL_RATE", 0), "process-wide tokens/sec; 0 disables (env PORTREACH_RATE_GLOBAL_RATE)")
	rateGlobalBurst := fs.Int("rate-global-burst", envInt("PORTREACH_RATE_GLOBAL_BURST", 0), "process-wide bucket capacity (env PORTREACH_RATE_GLOBAL_BURST)")
	trustedProxies := fs.String("trusted-proxies", os.Getenv("PORTREACH_TRUSTED_PROXIES"), "comma-separated CIDRs/IPs whose forwarded header is trusted for client-IP keying (env PORTREACH_TRUSTED_PROXIES)")
	forwardedHeader := fs.String("forwarded-header", os.Getenv("PORTREACH_FORWARDED_HEADER"), "forwarded client-IP header trusted only from trusted-proxies; empty = X-Forwarded-For (env PORTREACH_FORWARDED_HEADER)")
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

	uiBranding := ui.Branding{
		Title:       expandOptionalEnv(resolveOptionalString(fs, "ui-title", uiTitle, "PORTREACH_UI_TITLE")),
		Description: expandEnv(resolveString(fs, "ui-description", uiDescription, "PORTREACH_UI_DESCRIPTION")),
		Footer:      expandEnv(resolveString(fs, "ui-footer", uiFooter, "PORTREACH_UI_FOOTER")),
	}
	loginBranding := auth.LoginBranding{
		Title:  expandOptionalEnv(resolveOptionalString(fs, "login-title", loginTitle, "PORTREACH_LOGIN_TITLE")),
		Header: expandOptionalEnv(resolveOptionalString(fs, "login-header", loginHeader, "PORTREACH_LOGIN_HEADER")),
		Footer: expandEnv(resolveString(fs, "login-footer", loginFooter, "PORTREACH_LOGIN_FOOTER")),
	}

	// Build the optional rate limiter. Unset (--rate-limit off) leaves it nil =
	// unlimited, today's behaviour; when enabled, an invalid config fails fast.
	var limiter *ratelimit.Limiter
	if *rateLimit {
		limiter, err = ratelimit.New(ratelimit.Config{
			Enabled:         true,
			User:            ratelimit.Scope{Rate: *rateUserRate, Burst: *rateUserBurst},
			Target:          ratelimit.Scope{Rate: *rateTargetRate, Burst: *rateTargetBurst},
			Global:          ratelimit.Scope{Rate: *rateGlobalRate, Burst: *rateGlobalBurst},
			TrustedProxies:  splitList(*trustedProxies),
			ForwardedHeader: *forwardedHeader,
		})
		if err != nil {
			return &ExitError{Code: 2, Err: err}
		}
	}

	handler, err := buildUIHandler(disc, *timeout, *authConfig, *agentToken, limiter, deps.Stdout, handlerBranding{ui: uiBranding, login: loginBranding})
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
type handlerBranding struct {
	ui    ui.Branding
	login auth.LoginBranding
}

func buildUIHandler(disc discovery.Discoverer, timeout time.Duration, authConfigPath, agentToken string, limiter *ratelimit.Limiter, out io.Writer, brandings ...handlerBranding) (http.Handler, error) {
	var branding handlerBranding
	if len(brandings) > 0 {
		branding = brandings[0]
	}
	// Audit events go to stdout as JSON for the ИБ log pipeline (ELK/Loki).
	logger := slog.New(slog.NewJSONHandler(out, nil))
	handler := ui.New(disc, timeout,
		ui.WithBranding(branding.ui),
		ui.WithAgentToken(agentToken),
		ui.WithLimiter(limiter),
		ui.WithLogger(logger),
	).Handler()
	// Audit every reachability check, attributing it to the authenticated user
	// (or anonymous when auth is off, since no identity reaches the context).
	audited := auth.AuditCheck(logger, handler)

	if authConfigPath == "" {
		return audited, nil
	}

	cfg, err := auth.LoadConfig(authConfigPath)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled() {
		// A config file with no providers is valid and leaves the UI open.
		return audited, nil
	}

	authn, err := auth.New(cfg, auth.WithLogger(logger), auth.WithBranding(branding.login))
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		ids = append(ids, p.ID)
	}
	apiIDs := make([]string, 0, len(cfg.API))
	for _, e := range cfg.API {
		apiIDs = append(apiIDs, e.ID)
	}
	// Emit the startup banner through the same JSON logger so it does not
	// interleave a plain-text line into the audit log pipeline on stdout. Either
	// list may be empty (browser-only or bearer-only deployments are both valid).
	logger.Info("ui: auth enabled",
		slog.String("providers", strings.Join(ids, ", ")),
		slog.String("api", strings.Join(apiIDs, ", ")))

	// Gate first (injecting Identity into the context), then audit so the
	// check events carry the authenticated user.
	return authn.Middleware(audited), nil
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

// envBool returns the boolean value of env var name, or def when unset/invalid.
func envBool(name string, def bool) bool {
	if v := os.Getenv(name); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

// envFloat returns the float value of env var name, or def when unset/invalid.
func envFloat(name string, def float64) float64 {
	if v := os.Getenv(name); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

// splitList splits a comma-separated flag value into trimmed, non-empty entries.
// An empty/whitespace input yields nil so an unset flag leaves the list empty.
func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
