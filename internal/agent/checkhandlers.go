package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/lavr/portreach/internal/checkapi"
	"github.com/lavr/portreach/internal/probe"
)

// decodeCheckRequest reads r's body under the shared size cap
// (checkapi.MaxRequestBody) and decodes it as JSON into dst, writing a 400 and
// returning false on failure. http.MaxBytesReader bounds how much an
// oversized or malicious POST body this handler goroutine will buffer before
// rejecting it (resource-exhaustion DoS via request size); a body over the
// cap or malformed JSON is a client error, not something the probe layer
// should ever see. A generic function (rather than a method) because Go does
// not support type parameters on methods.
func decodeCheckRequest[T any](s *Server, w http.ResponseWriter, r *http.Request, dst *T) bool {
	r.Body = http.MaxBytesReader(w, r.Body, checkapi.MaxRequestBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return false
	}
	return true
}

// handleCheckTCP serves POST /api/check/tcp. It mirrors the pre-Task-6
// handleCheck's TCP path exactly (same validation, rate-limit, policy and
// probe.Run flow), reading its input from a JSON body via checkapi instead of
// the query string.
func (s *Server) handleCheckTCP(w http.ResponseWriter, r *http.Request) {
	var req checkapi.TCPCheckRequest
	if !decodeCheckRequest(s, w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	timeout := req.EffectiveTimeout()

	// Defence-in-depth rate limit on direct calls. Gate after validation (so a
	// valid host:port keys the bucket) but before any DNS/dial work, so a
	// throttled request is cheap. A nil limiter always allows (unlimited).
	if retry, ok := s.allow(req.Host, req.Port); !ok {
		s.throttled(w, retry)
		return
	}

	// Bound the policy DNS resolution by the same capped timeout the probe uses
	// (see resolveTarget's doc for why this reuses resolveCtx rather than
	// r.Context()).
	resolveCtx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	dialHosts, dns, ok := s.resolveTarget(resolveCtx, req.Host)
	if !ok {
		s.denied(w)
		return
	}

	res := probe.Run(resolveCtx, req.Host, dialHosts, req.Port, "tcp", timeout, dns, s.guard)

	// A connect-guard refusal (cloud metadata / link-local) surfaces as
	// res.Denied; route it to the same denial path as a resolveTarget policy
	// deny so metadata and policy denials are indistinguishable to clients.
	if res.Denied {
		s.denied(w)
		return
	}
	if res.TCP != nil && res.TCP.OK {
		s.metrics.ok.Add(1)
	} else {
		s.metrics.fail.Add(1)
	}
	writeJSON(w, http.StatusOK, checkResponse{Node: s.nodeName, Result: res})
}

// handleCheckPostgres serves POST /api/check/postgres: it validates the
// request, applies both the general and the postgres-specific rate limiters,
// enforces the connection policy/metadata guard exactly as the TCP path does,
// then drives a PostgreSQL auth probe via s.postgres (real pgconn-backed
// Connector in production; tests inject a fake Prober). Every request that
// reaches the rate-limit gate is audited (see auditPostgres) — actor, target,
// username and a safe outcome/reason, never the password.
//
// The 200-vs-4xx boundary: a check that runs and reports a failing target
// (wrong password -> auth_rejected, untrusted cert -> tls_error, unreachable
// port, ...) is a successful agent operation and returns 200 with the
// structured Result describing the failure. Only a request the agent itself
// could not process — bad input, unauthenticated, throttled, or denied by
// policy — gets a 4xx.
func (s *Server) handleCheckPostgres(w http.ResponseWriter, r *http.Request) {
	var req checkapi.PostgresCheckRequest
	if !decodeCheckRequest(s, w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	timeout := req.EffectiveTimeout()

	// Two independent gates apply, in order: the general check limiter (shared
	// with TCP, defence-in-depth for direct calls) and the postgres-specific
	// limiter below. Each is backed by its own *ratelimit.Limiter instance, so
	// tripping one never spends tokens the other is tracking (see
	// allow/allowPostgres). A throttled request never reached far enough to
	// touch the target, so it is audited as such rather than silently dropped.
	if retry, ok := s.allow(req.Host, req.Port); !ok {
		s.auditPostgres(r, req, "throttled", "")
		s.throttled(w, retry)
		return
	}
	if retry, ok := s.allowPostgres(req.Host, req.Port); !ok {
		s.auditPostgres(r, req, "throttled", "")
		s.throttled(w, retry)
		return
	}

	resolveCtx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	dialHosts, dns, ok := s.resolveTarget(resolveCtx, req.Host)
	if !ok {
		s.auditPostgres(r, req, "denied", probe.DenyReason)
		s.denied(w)
		return
	}

	res := s.postgres.Run(resolveCtx, req.Host, dialHosts, req.Port, timeout, dns, s.guard, req.Credentials, req.TLS)
	if res.Denied {
		s.auditPostgres(r, req, "denied", probe.DenyReason)
		s.denied(w)
		return
	}

	// outcome/reason describe the check result for the audit trail and never
	// touch req.Credentials.Password: res.Auth (when set) is a
	// checkapi.AuthResult, a response type guaranteed password-free (see
	// checkapi's TestResponseTypesNeverCarryPassword); the reachability-failure
	// reasons (res.TCP.Error / res.DNS.Error / res.Error) are the same
	// dial/DNS failure strings the TCP path already reports.
	outcome, reason := "unreachable", ""
	switch {
	case res.Auth == nil:
		// No auth attempt ran: the reachability dial itself failed (DNS or
		// connect), same as the TCP path's failure mode.
		switch {
		case res.TCP != nil && res.TCP.Error != "":
			reason = res.TCP.Error
		case res.DNS != nil && res.DNS.Error != "":
			reason = res.DNS.Error
		default:
			reason = res.Error
		}
	case res.Auth.OK:
		outcome, reason = "ok", ""
	default:
		outcome, reason = res.Auth.Code, res.Auth.Reason
	}
	s.auditPostgres(r, req, outcome, reason)

	if res.Auth != nil && res.Auth.OK {
		s.metrics.ok.Add(1)
	} else {
		s.metrics.fail.Add(1)
	}
	writeJSON(w, http.StatusOK, checkResponse{Node: s.nodeName, Result: res})
}

// auditPostgres emits a structured "audit" log entry for a postgres check
// this agent attempted: the calling address, the target, the username, and a
// safe outcome/reason — never req.Credentials.Password. It follows the audit
// pattern internal/auth already uses for UI-side check logging (event name +
// slog.LogAttrs with the request's context). Called for every postgres
// request that got past body validation (throttled, denied, and completed
// checks all pass through here), so the audit trail covers every request
// this agent actually acted on.
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
