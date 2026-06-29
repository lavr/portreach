package ui

import (
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/lavr/portreach/internal/auth"
	"github.com/lavr/portreach/internal/ratelimit"
)

// WithLimiter attaches an optional API rate limiter to the UI. A nil limiter
// (the default) leaves the UI unlimited — today's behaviour. The limiter gates
// both /api/check and a submitted / form before any discovery or fan-out work.
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

// retryAfterSeconds renders a Retry-After header value: whole seconds rounded up,
// floored at 1 so a sub-second hint never serializes as "0" (which clients read
// as "retry immediately", defeating the throttle).
func retryAfterSeconds(d time.Duration) string {
	secs := int(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}
