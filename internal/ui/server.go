package ui

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/lavr/portreach/internal/checkapi"
	"github.com/lavr/portreach/internal/discovery"
	"github.com/lavr/portreach/internal/probe"
	"github.com/lavr/portreach/internal/ratelimit"
)

// Server serves the UI aggregator HTTP endpoints.
type Server struct {
	disc       discovery.Discoverer
	client     *http.Client
	timeout    time.Duration
	branding   Branding
	agentToken string
	limiter    *ratelimit.Limiter // nil = unlimited (default)
	logger     *slog.Logger       // throttle audit events; nil = slog.Default()
	fanoutCfg  FanoutConfig       // per-check fan-out bounds; zero = unlimited

	// enabledChecks is the --enabled-checks allowlist (default tcp-only; see
	// checkapi.ParseEnabledChecks). Handler consults it to decide which of
	// /api/check/tcp and /api/check/postgres to register at all: a disabled
	// check's route is never added to the mux, so a request for it 404s
	// exactly like any other unknown path. It never governs /healthz.
	enabledChecks checkapi.EnabledChecks

	// postgresLimiter is a SEPARATE limiter layered on top of limiter for the
	// postgres endpoint only (see internal/ui/ratelimit.go's
	// uiPostgresLimiterConfig doc): a Postgres check drives a real
	// authentication attempt against the target, so it warrants a tighter,
	// dedicated budget rather than sharing the general limiter's buckets. New
	// auto-builds one with the built-in defaults whenever the postgres check
	// is enabled, unless disablePostgresRateLimit opts out or a caller
	// supplied one directly via WithPostgresLimiter. Both limiters are
	// consulted independently (see allow/allowPostgres) — tripping one never
	// spends tokens from the other.
	postgresLimiter *ratelimit.Limiter
	// disablePostgresRateLimit, set via WithDisablePostgresRateLimit, is the
	// only way to opt out of the auto-built postgres limiter above.
	disablePostgresRateLimit bool
}

// New builds a UI Server. timeout bounds the whole fan-out budget; a
// non-positive value falls back to a sensible default.
func New(disc discovery.Discoverer, timeout time.Duration, opts ...Option) *Server {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	s := &Server{
		disc:    disc,
		client:  &http.Client{Timeout: timeout},
		timeout: timeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	// Auto-build the postgres-specific limiter whenever the postgres check is
	// served, unless the operator opted out or already supplied one via
	// WithPostgresLimiter (checked after options so both overrides apply).
	// The bounds are fixed, known-good constants (see uiPostgresLimiterConfig),
	// so a Validate failure here would only mean one of them regressed — a
	// programming error, not a runtime condition to recover from.
	if s.enabledChecks.Has(checkapi.CheckPostgres) && !s.disablePostgresRateLimit && s.postgresLimiter == nil {
		lim, err := ratelimit.New(uiPostgresLimiterConfig)
		if err != nil {
			panic("ui: built-in postgres limiter config is invalid: " + err.Error())
		}
		s.postgresLimiter = lim
	}
	return s
}

// Handler returns the UI's HTTP routes. Each check endpoint (/api/check/tcp,
// /api/check/postgres) is registered only when the corresponding check is in
// enabledChecks — a disabled check's route is never added to the mux, so a
// request for it 404s exactly like any unknown path, mirroring the agent's
// Handler (internal/agent/agent.go). The pre-Task-7 GET /api/check is gone
// entirely: both routes are POST-only, since a Postgres check's credentials
// belong in a JSON body, never a URL.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	if s.enabledChecks.Has(checkapi.CheckTCP) {
		mux.HandleFunc("/api/check/tcp", requireMethod(http.MethodPost, s.handleAPICheckTCP))
	}
	if s.enabledChecks.Has(checkapi.CheckPostgres) {
		mux.HandleFunc("/api/check/postgres", requireMethod(http.MethodPost, s.handleAPICheckPostgres))
	}
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

// requireMethod rejects any request whose method isn't method with a 405
// before next ever sees it. The check endpoints take a JSON body and have no
// meaningful query-string form, so a non-POST request is a protocol error
// (wrong verb), not a validation failure on the payload — hence 405, not 400.
// Mirrors internal/agent's requireMethod exactly.
func requireMethod(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		next(w, r)
	}
}

// parseTarget extracts and validates the target from the query string.
func parseTarget(q map[string][]string) (Target, error) {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}

	host := get("host")
	proto := get("proto")
	if proto == "" {
		proto = "tcp"
	}

	port, err := strconv.Atoi(get("port"))
	if err != nil {
		return Target{}, errBadPort
	}

	timeout := get("timeout")
	if timeout != "" {
		if _, err := time.ParseDuration(timeout); err != nil {
			return Target{}, errBadTimeout
		}
	}

	if _, _, err := probe.Validate(host, port, proto, 0); err != nil {
		return Target{}, err
	}

	return Target{Host: host, Port: port, Proto: proto, Timeout: timeout}, nil
}

// clampTimeout bounds the per-agent probe timeout to stay safely under the
// fan-out budget. Without this, a user-supplied timeout >= the budget would let
// the UI's client/context deadline fire first, replacing the agent's clean
// per-node timeout result with a generic transport error. An empty/invalid
// value falls back to the probe default, also clamped.
func clampTimeout(user string, budget time.Duration) string {
	d := probe.DefaultTimeout
	if user != "" {
		if parsed, err := time.ParseDuration(user); err == nil && parsed > 0 {
			d = parsed
		}
	}
	max := budget - time.Second
	if max < time.Second {
		max = budget / 2
	}
	if d > max {
		d = max
	}
	// Keep the result strictly positive without overriding a valid user choice: a
	// non-positive value would serialize as "0s"/"-…s", which probe.Validate reads
	// as "use the 5s default" — silently defeating the clamp. A deliberately small
	// positive timeout (e.g. 1ms/10ms) is left untouched, matching probe.Validate,
	// which only substitutes the default when timeout <= 0. The cap above yields a
	// non-positive value only for an already-exhausted budget (budget <= 0); the
	// floor guards that edge so handlers can fan out on any positive remainder
	// without the serialized timeout silently reverting to the 5s default.
	if d <= 0 {
		d = minClampTimeout
	}
	return d.String()
}

// minClampTimeout is the per-agent probe timeout clampTimeout falls back to when
// the clamp would otherwise yield a non-positive value, keeping it positive so
// probe.Validate never substitutes its default.
const minClampTimeout = 100 * time.Millisecond

// runCheck is the shared discovery+fan-out body behind both
// handleAPICheckTCP and handleAPICheckPostgres (and, for the TCP-only web
// form, handleIndex): given an already-validated, already-rate-limited
// target, it discovers agents, clamps the per-agent timeout to the remaining
// budget, fans out, and writes the aggregated Response envelope. auth carries
// Postgres credentials/TLS (nil for a TCP check; see PostgresAuth) — it is
// threaded straight through to CheckAll and never touches target or the
// written response, so a Postgres password can't leak into the JSON envelope
// this handler writes back to the client.
func (s *Server) runCheck(w http.ResponseWriter, r *http.Request, target Target, auth *PostgresAuth) {
	ctx, cancel := contextWithTimeout(r, s.timeout)
	defer cancel()

	agents, err := s.disc.Agents(ctx)
	if err != nil {
		// The DNS discoverer surfaces a deadline as a LookupHost error rather than a
		// nil result, so a discovery error caused by the shared budget expiring must
		// be reported as a clean timeout — not a generic 502 — mirroring the
		// post-discovery deadline check below.
		if ctxErr := ctx.Err(); ctxErr != nil {
			writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "deadline exceeded during discovery: " + ctxErr.Error()})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "discovery: " + err.Error()})
		return
	}

	// If discovery consumed the whole budget, there is no time left to probe.
	// Report a clean deadline error rather than fanning out with an expired ctx,
	// which would yield generic per-node transport errors.
	if err := ctx.Err(); err != nil {
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "deadline exceeded after discovery: " + err.Error()})
		return
	}

	// Clamp against the budget that actually remains after discovery so the
	// per-agent timeout can't outlast the ctx deadline and replace clean
	// per-node results with a generic transport error. clampTimeout keeps the
	// result strictly positive and under the remaining budget for any positive
	// remainder, so even a small (sub-second) post-discovery budget still yields a
	// real probe attempt rather than an automatic failure.
	target.Timeout = clampTimeout(target.Timeout, remainingBudget(ctx, s.timeout))

	// A check whose targets all failed to connect/authenticate is still a
	// successful agent operation from the UI's perspective — it ran and
	// reported structured per-node results — so this always writes 200. Only
	// a request the UI itself could not process (bad input, throttled, denied
	// discovery) gets a non-200 status, and those all return earlier above.
	results, discovered, queried, dropped := s.fanout(ctx, r, agents, target, auth)
	writeJSON(w, http.StatusOK, Response{
		Target:     target,
		Agents:     results,
		Summary:    Summarize(results),
		Discovered: discovered,
		Queried:    queried,
		Dropped:    dropped,
	})
}

// fanout applies the optional MaxAgentsPerCheck cap (deterministic, sorted by
// Addr), runs the bounded fan-out, and returns the results plus the
// discovered/queried/dropped counts so callers can report partial results
// unambiguously. A positive drop count is also surfaced as an audit event.
func (s *Server) fanout(ctx context.Context, r *http.Request, agents []discovery.Agent, target Target, auth *PostgresAuth) (results []AgentResult, discovered, queried, dropped int) {
	discovered = len(agents)
	selected, dropped := selectAgents(agents, s.fanoutCfg.MaxAgentsPerCheck)
	queried = len(selected)
	if dropped > 0 {
		s.logDrop(r, target, discovered, queried, dropped)
	}
	results = CheckAll(ctx, s.client, selected, target, auth, s.agentToken, s.fanoutCfg.MaxConcurrentFanout)
	return results, discovered, queried, dropped
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
