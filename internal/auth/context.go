package auth

import "context"

// ctxKey is the unexported key type for auth context values, avoiding
// collisions with keys from other packages.
type ctxKey int

const (
	identityKey ctxKey = iota
	authMethodKey
)

// Auth method labels recorded by the audit log to distinguish how a request
// authenticated: a sealed session cookie (browser SSO) or a bearer access token.
const (
	AuthMethodCookie = "cookie"
	AuthMethodBearer = "bearer"
)

// WithIdentity returns a copy of ctx carrying the authenticated session. The
// gating middleware attaches it on every authenticated request so downstream
// handlers (and the audit logger) can attribute work to a user + provider.
func WithIdentity(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, identityKey, s)
}

// IdentityFromContext returns the authenticated session attached by the
// middleware. ok is false for unauthenticated requests (e.g. auth disabled, or
// public paths), letting callers fall back to "anonymous".
func IdentityFromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(identityKey).(Session)
	return s, ok
}

// WithAuthMethod returns a copy of ctx tagged with how the request
// authenticated (AuthMethodCookie or AuthMethodBearer). The middleware sets it
// alongside the identity so the audit log can record the credential type.
func WithAuthMethod(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, authMethodKey, method)
}

// AuthMethodFromContext returns the auth method tagged by the middleware, or ""
// when none was recorded (e.g. auth disabled / anonymous request).
func AuthMethodFromContext(ctx context.Context) string {
	m, _ := ctx.Value(authMethodKey).(string)
	return m
}
