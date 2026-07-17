package ui

import (
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/lavr/portreach/internal/auth"
	"github.com/lavr/portreach/internal/ratelimit"
)

// WithLimiter attaches an optional API rate limiter to the UI. A nil limiter
// (the default) leaves the UI unlimited — today's behaviour. The limiter gates
// both /api/check/tcp, /api/check/postgres, and a submitted / form before any
// discovery or fan-out work.
func WithLimiter(l *ratelimit.Limiter) Option {
	return func(s *Server) { s.limiter = l }
}

// WithLogger sets the slog.Logger used for throttle audit events. A nil logger
// is ignored, leaving slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(s *Server) {
		if l != nil {
			s.logger = l
		}
	}
}

// uiPostgresLimiterUserPerMin, uiPostgresLimiterTargetPerMin,
// uiPostgresLimiterGlobalPerMin and their paired burst constants are the
// built-in, non-configurable bound for the UI's postgres-specific limiter
// (see the Server.postgresLimiter field doc): per-user 6/min burst 3,
// per-target 12/min burst 3, global 60/min burst 10. Unlike the agent's
// postgres limiter (internal/agent/ratelimit.go), the UI adds a per-user
// scope — the UI, unlike the agent, has an identity to key on (see
// identityKey) — layered on top of the same per-target/global bounds the
// agent uses, since a Postgres check drives a real authentication attempt
// (and, on success, a live query) against the target regardless of which
// layer gates it.
const (
	uiPostgresLimiterUserPerMin   = 6
	uiPostgresLimiterUserBurst    = 3
	uiPostgresLimiterTargetPerMin = 12
	uiPostgresLimiterTargetBurst  = 3
	uiPostgresLimiterGlobalPerMin = 60
	uiPostgresLimiterGlobalBurst  = 10
)

// uiPostgresLimiterConfig converts the per-minute constants above into
// ratelimit.Scope's tokens/sec unit.
var uiPostgresLimiterConfig = ratelimit.Config{
	Enabled: true,
	User:    ratelimit.Scope{Rate: uiPostgresLimiterUserPerMin / 60.0, Burst: uiPostgresLimiterUserBurst},
	Target:  ratelimit.Scope{Rate: uiPostgresLimiterTargetPerMin / 60.0, Burst: uiPostgresLimiterTargetBurst},
	Global:  ratelimit.Scope{Rate: uiPostgresLimiterGlobalPerMin / 60.0, Burst: uiPostgresLimiterGlobalBurst},
}

// WithPostgresLimiter overrides the postgres-specific limiter New would
// otherwise auto-build (see the postgresLimiter field doc). Tests use this to
// inject a limiter with an injected clock (ratelimit.WithClock) so the 429
// path is exercised hermetically; production code should prefer
// WithDisablePostgresRateLimit to opt out rather than supplying a permissive
// limiter here.
func WithPostgresLimiter(l *ratelimit.Limiter) Option {
	return func(s *Server) { s.postgresLimiter = l }
}

// WithDisablePostgresRateLimit opts out of the auto-built postgres limiter
// entirely (the only supported way to disable it — see the postgresLimiter
// field doc). The general limiter (WithLimiter), if any, still applies.
func WithDisablePostgresRateLimit(disable bool) Option {
	return func(s *Server) { s.disablePostgresRateLimit = disable }
}

// auditLogger returns the configured logger, falling back to the process default
// so a Server built without WithLogger still emits throttle events.
func (s *Server) auditLogger() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}

// allow gates one check request against the rate limiter. When the request is
// over limit it returns ok=false and a bounded Retry-After hint, having already
// emitted a "throttle" audit event; the caller renders the 429 in its own format
// (JSON for /api/check, an inline page message for /). A nil limiter always
// allows (unlimited — today's behaviour).
func (s *Server) allow(r *http.Request, target Target) (retryAfter time.Duration, ok bool) {
	if s.limiter == nil {
		return 0, true
	}
	idKey := s.identityKey(r)
	targetKey := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	res := s.limiter.Reserve(idKey, targetKey)
	if res.OK {
		return 0, true
	}
	s.logThrottle(r, idKey, targetKey, res.RetryAfter)
	return res.RetryAfter, false
}

// allowPostgres gates one postgres check against the dedicated postgres
// limiter (see the Server.postgresLimiter field doc). It is consulted in
// addition to allow, never instead of it — both apply, using independent
// *ratelimit.Limiter instances (and therefore independent buckets), so
// tripping one never spends tokens the other is tracking. A nil limiter
// (postgres limiter disabled or never built) always allows.
func (s *Server) allowPostgres(r *http.Request, target Target) (retryAfter time.Duration, ok bool) {
	if s.postgresLimiter == nil {
		return 0, true
	}
	idKey := s.identityKey(r)
	targetKey := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	res := s.postgresLimiter.Reserve(idKey, targetKey)
	if res.OK {
		return 0, true
	}
	s.logThrottle(r, idKey, targetKey, res.RetryAfter)
	return res.RetryAfter, false
}

// identityKey keys the limiter on the authenticated user when present, else the
// proxy-aware client IP (review finding #8). The "user:"/"ip:" prefixes keep the
// two namespaces from colliding (a user literally named like an IP address).
func (s *Server) identityKey(r *http.Request) string {
	if sess, ok := auth.IdentityFromContext(r.Context()); ok && sess.User != "" {
		return "user:" + sess.User
	}
	return "ip:" + s.limiter.ClientIP(r)
}

// logThrottle emits a structured "throttle" audit event mirroring AuditCheck's
// who/target/remote shape so throttles land in the same ИБ log pipeline as the
// check events, attributed to the same identity key the limiter used.
func (s *Server) logThrottle(r *http.Request, idKey, targetKey string, retryAfter time.Duration) {
	s.auditLogger().LogAttrs(r.Context(), slog.LevelWarn, "audit",
		slog.String("event", "throttle"),
		slog.String("identity", idKey),
		slog.String("target", targetKey),
		slog.String("remote", r.RemoteAddr),
		slog.Duration("retry_after", retryAfter),
	)
}

// logDrop emits a structured "fanout_drop" audit event when a MaxAgentsPerCheck
// cap truncates the fan-out, mirroring the check/throttle who/target/remote shape
// so partial-coverage checks are visible in the same ИБ log pipeline (a broad
// scan that repeatedly trips the cap is then auditable).
func (s *Server) logDrop(r *http.Request, target Target, discovered, queried, dropped int) {
	s.auditLogger().LogAttrs(r.Context(), slog.LevelWarn, "audit",
		slog.String("event", "fanout_drop"),
		slog.String("target", net.JoinHostPort(target.Host, strconv.Itoa(target.Port))),
		slog.String("remote", r.RemoteAddr),
		slog.Int("discovered", discovered),
		slog.Int("queried", queried),
		slog.Int("dropped", dropped),
	)
}
