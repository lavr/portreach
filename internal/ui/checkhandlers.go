package ui

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/lavr/portreach/internal/checkapi"
	"github.com/lavr/portreach/internal/ratelimit"
)

// decodeAPIRequest reads r's body under the shared size cap
// (checkapi.MaxRequestBody) and decodes it as JSON into dst, writing a 400 and
// returning false on failure. http.MaxBytesReader bounds how much an
// oversized or malicious POST body this handler goroutine will buffer before
// rejecting it (resource-exhaustion DoS via request size); a body over the
// cap or malformed JSON is a client error, not something the fan-out should
// ever see. Mirrors internal/agent's decodeCheckRequest exactly. A generic
// function (rather than a method) because Go does not support type
// parameters on methods.
func decodeAPIRequest[T any](w http.ResponseWriter, r *http.Request, dst *T) bool {
	r.Body = http.MaxBytesReader(w, r.Body, checkapi.MaxRequestBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body: " + err.Error()})
		return false
	}
	return true
}

// handleAPICheckTCP serves POST /api/check/tcp: decode, validate, gate on the
// general rate limiter, then hand off to runCheck for discovery/fan-out. No
// Postgres auth is ever involved on this path (auth is nil throughout).
func (s *Server) handleAPICheckTCP(w http.ResponseWriter, r *http.Request) {
	var req checkapi.TCPCheckRequest
	if !decodeAPIRequest(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	target := Target{Host: req.Host, Port: req.Port, Proto: string(checkapi.CheckTCP), Timeout: durationString(req.Timeout)}

	// Gate before any discovery/fan-out work so a throttled request is cheap.
	if retry, ok := s.allow(r, target); !ok {
		writeThrottled(w, retry)
		return
	}
	s.runCheck(w, r, target, nil)
}

// handleAPICheckPostgres serves POST /api/check/postgres: it validates the
// request, applies both the general and the postgres-specific rate limiters,
// then hands off to runCheck exactly like the TCP path — the only difference
// is the non-nil PostgresAuth carrying credentials/TLS through to CheckAll.
// Every request that reaches the rate-limit gate is audited (see
// auditPostgres) — actor, target, username and a safe outcome/reason, never
// the password — mirroring internal/agent's auditPostgres.
func (s *Server) handleAPICheckPostgres(w http.ResponseWriter, r *http.Request) {
	var req checkapi.PostgresCheckRequest
	if !decodeAPIRequest(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	target := Target{Host: req.Host, Port: req.Port, Proto: string(checkapi.CheckPostgres), Timeout: durationString(req.Timeout)}
	auth := &PostgresAuth{Credentials: req.Credentials, TLS: req.TLS}

	// Two independent gates apply, in order: the general limiter (shared with
	// TCP) and the postgres-specific limiter below. Each is backed by its own
	// *ratelimit.Limiter instance, so tripping one never spends tokens the
	// other is tracking (see allow/allowPostgres).
	if retry, ok := s.allow(r, target); !ok {
		s.auditPostgres(r, req, "throttled", "")
		writeThrottled(w, retry)
		return
	}
	if retry, ok := s.allowPostgres(r, target); !ok {
		s.auditPostgres(r, req, "throttled", "")
		writeThrottled(w, retry)
		return
	}

	s.runCheckPostgres(w, r, target, auth, req)
}

// runCheckPostgres wraps runCheck to audit the request's outcome. Unlike the
// agent (which runs a single check and knows the exact auth outcome), the UI
// fans out to every discovered agent, so its audit trail is deliberately
// coarser: it records that a Postgres credential check for this
// actor/target/username was dispatched and how many agents reported success,
// not a re-derivation of each node's individual result — every agent already
// audits its own outcome (see internal/agent's auditPostgres), so duplicating
// that detail here would add noise, not safety.
func (s *Server) runCheckPostgres(w http.ResponseWriter, r *http.Request, target Target, auth *PostgresAuth, req checkapi.PostgresCheckRequest) {
	ctx, cancel := contextWithTimeout(r, s.timeout)
	defer cancel()

	agents, err := s.disc.Agents(ctx)
	if err != nil {
		reason := "discovery: " + err.Error()
		status := http.StatusBadGateway
		if ctxErr := ctx.Err(); ctxErr != nil {
			reason = "deadline exceeded during discovery: " + ctxErr.Error()
			status = http.StatusGatewayTimeout
		}
		s.auditPostgres(r, req, "error", reason)
		writeJSON(w, status, map[string]string{"error": reason})
		return
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		reason := "deadline exceeded after discovery: " + ctxErr.Error()
		s.auditPostgres(r, req, "error", reason)
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": reason})
		return
	}

	target.Timeout = clampTimeout(target.Timeout, remainingBudget(ctx, s.timeout))
	results, discovered, queried, dropped := s.fanout(ctx, r, agents, target, auth)
	summary := Summarize(results)
	s.auditPostgres(r, req, "completed", reachableSummary(summary))
	writeJSON(w, http.StatusOK, Response{
		Target:     target,
		Agents:     results,
		Summary:    summary,
		Discovered: discovered,
		Queried:    queried,
		Dropped:    dropped,
	})
}

// reachableSummary renders a Summary as a safe (password-free) audit reason
// string, e.g. "2/3 agents reachable".
func reachableSummary(s Summary) string {
	return strconv.Itoa(s.OK) + "/" + strconv.Itoa(s.Total) + " agents reachable"
}

// durationString renders a checkapi.Duration as the string form Target.Timeout
// expects, or "" for the zero value — leaving "use the default" to
// clampTimeout/probe, exactly as an omitted query-string timeout does today.
func durationString(d checkapi.Duration) string {
	if d <= 0 {
		return ""
	}
	return time.Duration(d).String()
}

// writeThrottled writes the standard 429 response (with a Retry-After hint)
// shared by both check endpoints and both limiters (general + postgres) that
// can produce this outcome. Mirrors internal/agent's throttled helper.
func writeThrottled(w http.ResponseWriter, retry time.Duration) {
	ra := ratelimit.RetryAfterSeconds(retry)
	w.Header().Set("Retry-After", ra)
	writeJSON(w, http.StatusTooManyRequests, map[string]string{
		"error":       "rate limit exceeded",
		"retry_after": ra,
	})
}

// auditPostgres emits a structured "audit" log entry for a postgres check
// this UI dispatched: the calling address, the target, the username, and a
// safe outcome/reason — never req.Credentials.Password. Mirrors the pattern
// internal/agent's auditPostgres already uses. Called for every postgres
// request that got past body validation (throttled, discovery-error, and
// completed checks all pass through here), so the audit trail covers every
// request this UI actually acted on.
func (s *Server) auditPostgres(r *http.Request, req checkapi.PostgresCheckRequest, outcome, reason string) {
	s.auditLogger().LogAttrs(r.Context(), slog.LevelInfo, "audit",
		slog.String("event", "postgres_check"),
		slog.String("remote", r.RemoteAddr),
		slog.String("target", net.JoinHostPort(req.Host, strconv.Itoa(req.Port))),
		slog.String("username", req.Credentials.Username),
		slog.String("outcome", outcome),
		slog.String("reason", reason),
	)
}
