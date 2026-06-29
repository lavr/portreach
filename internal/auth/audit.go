package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
)

// anonymousUser is the audit-log actor recorded when no authenticated identity
// is attached to the request — i.e. auth is disabled, or the request never
// passed through the gating middleware.
const anonymousUser = "anonymous"

// Audit paths the check audit middleware attributes a reachability check to.
const (
	apiCheckPath = "/api/check"
	indexPath    = "/"
)

// Option customises an Authenticator at construction time.
type Option func(*Authenticator)

// WithLogger sets the slog.Logger used for audit events (login + check). A nil
// logger is ignored, leaving the default (slog.Default()).
func WithLogger(l *slog.Logger) Option {
	return func(a *Authenticator) {
		if l != nil {
			a.logger = l
		}
	}
}

// auditLogger returns the configured audit logger, falling back to the process
// default so Authenticators built without WithLogger (e.g. in tests) still log.
func (a *Authenticator) auditLogger() *slog.Logger {
	if a.logger != nil {
		return a.logger
	}
	return slog.Default()
}

// auditActor resolves the audit "who" from the request context: the
// authenticated user + provider, or anonymous (with empty provider) when no
// identity is present.
func auditActor(ctx context.Context) (user, provider string) {
	if s, ok := IdentityFromContext(ctx); ok && s.User != "" {
		return s.User, s.Provider
	}
	return anonymousUser, ""
}

// logLogin emits an audit "login" event recording who logged in via which
// provider, the outcome (ok|denied) and the client address.
func (a *Authenticator) logLogin(r *http.Request, user, provider, result string) {
	a.auditLogger().LogAttrs(r.Context(), slog.LevelInfo, "audit",
		slog.String("event", "login"),
		slog.String("user", user),
		slog.String("provider", provider),
		slog.String("result", result),
		slog.String("remote", r.RemoteAddr),
	)
}

// AuditCheck wraps next with security audit logging for reachability checks. It
// emits a structured slog "check" event recording who (user+provider, or
// anonymous when auth is off) ran what check (target host:port/proto) from where
// (remote addr): for every /api/check request, and for / only when a target is
// actually submitted. A nil logger falls back to slog.Default().
func AuditCheck(logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if target, ok := auditTarget(r); ok {
			user, provider := auditActor(r.Context())
			logger.LogAttrs(r.Context(), slog.LevelInfo, "audit",
				slog.String("event", "check"),
				slog.String("user", user),
				slog.String("provider", provider),
				slog.String("auth_method", AuthMethodFromContext(r.Context())),
				slog.String("target", target),
				slog.String("remote", r.RemoteAddr),
			)
		}
		next.ServeHTTP(w, r)
	})
}

// auditTarget reports whether r is a reachability check and, if so, the
// target rendered as host:port/proto for the audit log. /api/check always
// counts; / counts only when the form carried a target (host or port present).
func auditTarget(r *http.Request) (string, bool) {
	switch r.URL.Path {
	case apiCheckPath:
	case indexPath:
		q := r.URL.Query()
		if !q.Has("host") && !q.Has("port") {
			return "", false
		}
	default:
		return "", false
	}
	q := r.URL.Query()
	host := strings.TrimSpace(q.Get("host"))
	port := strings.TrimSpace(q.Get("port"))
	proto := strings.TrimSpace(q.Get("proto"))
	if proto == "" {
		proto = "tcp"
	}
	return host + ":" + port + "/" + proto, true
}
