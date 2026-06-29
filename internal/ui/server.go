package ui

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

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
	return s
}

// Handler returns the UI's HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/check", s.handleAPICheck)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
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

func (s *Server) handleAPICheck(w http.ResponseWriter, r *http.Request) {
	target, err := parseTarget(r.URL.Query())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Gate before any discovery/fan-out work so a throttled request is cheap.
	if retry, ok := s.allow(r, target); !ok {
		ra := retryAfterSeconds(retry)
		w.Header().Set("Retry-After", ra)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error":       "rate limit exceeded",
			"retry_after": ra,
		})
		return
	}
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

	results := CheckAll(ctx, s.client, agents, target, s.agentToken)
	writeJSON(w, http.StatusOK, Response{
		Target:  target,
		Agents:  results,
		Summary: Summarize(results),
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
