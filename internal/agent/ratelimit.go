package agent

import (
	"net"
	"strconv"
	"time"

	"github.com/lavr/portreach/internal/ratelimit"
)

// WithLimiter attaches an optional rate limiter that gates /check as
// defence-in-depth for direct calls. The UI fan-out already gates at the API,
// but an agent is reachable on the node (hostNetwork) and may be called
// directly, so a per-process/per-target cap bounds that path too. A nil limiter
// (the default) leaves /check unlimited — today's behaviour.
func WithLimiter(l *ratelimit.Limiter) Option {
	return func(s *Server) { s.limiter = l }
}

// postgresLimiterTargetPerMin, postgresLimiterGlobalPerMin and the paired
// burst constants are the built-in, non-configurable bound for the
// postgres-specific limiter (see the Server.postgresLimiter field doc):
// per-target 12/min burst 3, global 60/min burst 10. It is deliberately
// tighter than a bare TCP connect's typical limiter, since a postgres check
// drives a real authentication attempt (and, on success, a live query)
// against the target.
const (
	postgresLimiterTargetPerMin = 12
	postgresLimiterTargetBurst  = 3
	postgresLimiterGlobalPerMin = 60
	postgresLimiterGlobalBurst  = 10
)

// postgresLimiterConfig converts the per-minute constants above into
// ratelimit.Scope's tokens/sec unit.
var postgresLimiterConfig = ratelimit.Config{
	Enabled: true,
	Target:  ratelimit.Scope{Rate: postgresLimiterTargetPerMin / 60.0, Burst: postgresLimiterTargetBurst},
	Global:  ratelimit.Scope{Rate: postgresLimiterGlobalPerMin / 60.0, Burst: postgresLimiterGlobalBurst},
}

// allow gates one /check against the general limiter, keyed per target
// (host:port) and the process global. See allowReservation for the shared
// reservation logic; allowPostgres applies the same keying to the separate
// postgres-specific limiter.
func (s *Server) allow(host string, port int) (retryAfter time.Duration, ok bool) {
	return allowReservation(s.limiter, host, port)
}

// allowPostgres gates one postgres check against the dedicated postgres
// limiter (see the Server.postgresLimiter field doc). It is consulted in
// addition to allow, never instead of it — both apply, using independent
// *ratelimit.Limiter instances (and therefore independent buckets), so
// tripping one never spends tokens the other is tracking.
func (s *Server) allowPostgres(host string, port int) (retryAfter time.Duration, ok bool) {
	return allowReservation(s.postgresLimiter, host, port)
}

// allowReservation is the shared reservation call behind allow and
// allowPostgres: both key on ("", host:port) — the agent carries no
// per-user identity (internal cluster traffic), so the identity scope is
// left empty and only the target and global buckets apply. A nil limiter
// always allows (unlimited). Over limit it returns a bounded Retry-After
// hint and ok=false.
func allowReservation(l *ratelimit.Limiter, host string, port int) (retryAfter time.Duration, ok bool) {
	if l == nil {
		return 0, true
	}
	targetKey := net.JoinHostPort(host, strconv.Itoa(port))
	res := l.Reserve("", targetKey)
	if res.OK {
		return 0, true
	}
	return res.RetryAfter, false
}
