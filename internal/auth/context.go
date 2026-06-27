package auth

import "context"

// ctxKey is the unexported key type for auth context values, avoiding
// collisions with keys from other packages.
type ctxKey int

const identityKey ctxKey = iota

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
