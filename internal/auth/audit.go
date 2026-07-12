package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// anonymousUser is the audit-log actor recorded when no authenticated identity
// is attached to the request — i.e. auth is disabled, or the request never
// passed through the gating middleware.
const anonymousUser = "anonymous"

// Audit paths the check audit middleware attributes a reachability check to.
// The per-protocol POST endpoints each map to a fixed proto; the web form (/)
// carries the proto in its input (query for a GET link, body for a POST).
const (
	apiCheckTCPPath      = "/api/check/tcp"
	apiCheckPostgresPath = "/api/check/postgres"
	indexPath            = "/"
)

// maxAuditBodyPeek bounds how much of a POST body the audit middleware buffers
// to extract the target. It is a small cap: the handlers enforce their own
// (larger) body limit, and a check request's routing fields are tiny — this
// only needs host/port/proto, never the credentials.
const maxAuditBodyPeek = 64 << 10

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
// target rendered as host:port/proto for the audit log. The per-protocol POST
// endpoints always count (proto fixed by the path); / counts only when the
// form carried a target (host or port present). For a POST the routing fields
// come from the body (JSON for the API, form for /); the body is buffered and
// restored so the downstream handler still reads it. The password is never
// touched — only host/port/proto are extracted.
func auditTarget(r *http.Request) (string, bool) {
	switch r.URL.Path {
	case apiCheckTCPPath:
		host, port, _ := checkFields(r)
		return host + ":" + port + "/tcp", true
	case apiCheckPostgresPath:
		host, port, _ := checkFields(r)
		return host + ":" + port + "/postgres", true
	case indexPath:
		host, port, proto := checkFields(r)
		if host == "" && port == "" {
			return "", false
		}
		if proto == "" {
			proto = "tcp"
		}
		return host + ":" + port + "/" + proto, true
	default:
		return "", false
	}
}

// checkFields extracts the host/port/proto routing fields from a check request,
// from the query string for a GET and from the body for a POST (JSON body for
// the API endpoints, form-encoded for the web form). For a POST the body is
// buffered under a small cap and restored, so this peek is transparent to the
// handler. Only routing fields are read; credentials are never parsed here.
func checkFields(r *http.Request) (host, port, proto string) {
	if r.Method != http.MethodPost {
		q := r.URL.Query()
		return strings.TrimSpace(q.Get("host")), strings.TrimSpace(q.Get("port")), strings.TrimSpace(q.Get("proto"))
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxAuditBodyPeek+1))
	if err != nil {
		return "", "", ""
	}
	// Restore the body for the handler regardless of what we can parse.
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
	if len(body) > maxAuditBodyPeek {
		// Oversized for a routing peek; let the handler's own limit deal with it.
		return "", "", ""
	}

	if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
		var m struct {
			Host string `json:"host"`
			Port any    `json:"port"`
		}
		if json.Unmarshal(body, &m) == nil {
			return strings.TrimSpace(m.Host), portString(m.Port), ""
		}
		return "", "", ""
	}

	// Form-encoded (the web form). ParseQuery over the buffered body avoids
	// consuming r.PostForm state the handler may re-parse.
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", ""
	}
	proto = strings.TrimSpace(vals.Get("proto"))
	if strings.TrimSpace(vals.Get("check")) == "postgres" {
		proto = "postgres"
	}
	return strings.TrimSpace(vals.Get("host")), strings.TrimSpace(vals.Get("port")), proto
}

// portString renders a JSON port value (number or string) as a trimmed string.
func portString(v any) string {
	switch p := v.(type) {
	case float64:
		return strconv.FormatInt(int64(p), 10)
	case json.Number:
		return p.String()
	case string:
		return strings.TrimSpace(p)
	default:
		return ""
	}
}
