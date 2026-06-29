package auth

import (
	"io"
	"net/http"
	"strings"
	"time"
)

// healthzPath stays public so Kubernetes liveness/readiness probes never get
// redirected to the login page.
const healthzPath = "/healthz"

// apiPathPrefix marks the programmatic API surface. Requests under it never get
// an HTML login redirect: an unauthenticated /api/* request returns 401 JSON.
const apiPathPrefix = "/api/"

// Middleware gates next behind authentication. It:
//   - serves the /auth/* routes itself (login chooser, callback, logout),
//     reachable without an existing session;
//   - lets /healthz through unauthenticated for k8s probes;
//   - accepts an `Authorization: Bearer <JWT>` access token when the API path is
//     configured, and/or a sealed session cookie when browser SSO is configured.
//
// Failure handling depends on the surface. A presented-but-invalid bearer token
// always yields 401 (it is a programmatic client, never an interactive browser).
// Otherwise: /api/* always returns 401 JSON; a browser path redirects to
// /auth/login only when browser SSO is configured — in API-only mode there is no
// login page, so it too returns 401.
//
// On an authenticated request the decoded Session is injected into the request
// context via WithIdentity so downstream handlers and the audit logger can
// attribute the request to a user + provider.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	authMux := a.Mux()
	apiEnabled := a.cfg.apiEnabled()
	browserEnabled := a.cfg.browserEnabled()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/auth/"):
			authMux.ServeHTTP(w, r)
			return
		case r.URL.Path == healthzPath:
			next.ServeHTTP(w, r)
			return
		}

		// Bearer first: a presented token is an explicit programmatic credential.
		// If it is invalid it is a hard 401 — we never fall back to a cookie or a
		// login redirect for it (and never attach an identity for an unmatched
		// token).
		if apiEnabled {
			if tok := bearerToken(r); tok != "" {
				sess, ok := a.authenticateBearer(r.Context(), tok)
				if !ok {
					writeUnauthorized(w)
					return
				}
				// RBAC is enforced here for bearer identities exactly as it is at
				// callback time for cookie sessions: a verified token whose
				// identity is outside the matched entry's allowlist is a 403.
				if !a.allowed(sess.Provider, Identity{Login: sess.User, Groups: sess.Groups}) {
					writeForbidden(w)
					return
				}
				ctx := WithAuthMethod(WithIdentity(r.Context(), sess), AuthMethodBearer)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Cookie path, when browser SSO is configured. The allowlist was already
		// enforced at /auth/callback before the session was sealed, so a present,
		// unexpired cookie is trusted as-is here.
		if browserEnabled {
			if sess, err := a.readSessionCookie(r); err == nil {
				ctx := WithAuthMethod(WithIdentity(r.Context(), sess), AuthMethodCookie)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// No usable credential. Redirect to login only for a browser path when
		// browser SSO exists; otherwise (API path, or API-only deployment) 401.
		if browserEnabled && !strings.HasPrefix(r.URL.Path, apiPathPrefix) {
			http.Redirect(w, r, LoginPath, http.StatusFound)
			return
		}
		writeUnauthorized(w)
	})
}

// writeUnauthorized writes a 401 JSON body with a Bearer challenge. It is the
// uniform rejection for programmatic (/api/*) and API-only requests, so clients
// get a machine-readable error instead of an HTML login page.
func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"error":"unauthorized"}`+"\n")
}

// writeForbidden writes a 403 JSON body for an authenticated-but-not-authorized
// bearer request (the token verified, but its identity is outside the matched
// entry's allowlist). Bearer is always programmatic, so the rejection is JSON
// rather than the HTML denied page used for browser sessions.
func writeForbidden(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, `{"error":"forbidden"}`+"\n")
}

// readSessionCookie opens and validates the session cookie, rejecting a
// missing, tampered or expired cookie.
func (a *Authenticator) readSessionCookie(r *http.Request) (Session, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return Session{}, err
	}
	return open(a.cfg.CookieKey, c.Value, time.Now())
}
