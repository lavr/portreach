package auth

import (
	"net/http"
	"strings"
	"time"
)

// healthzPath stays public so Kubernetes liveness/readiness probes never get
// redirected to the login page.
const healthzPath = "/healthz"

// Middleware gates next behind authentication. It:
//   - serves the /auth/* routes itself (login chooser, callback, logout),
//     reachable without an existing session;
//   - lets /healthz through unauthenticated for k8s probes;
//   - for any other path, requires a valid sealed session cookie, redirecting
//     to /auth/login (302) when it is missing, tampered or expired.
//
// On an authenticated request the decoded Session is injected into the request
// context via WithIdentity so downstream handlers and the audit logger can
// attribute the request to a user + provider.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	authMux := a.Mux()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/auth/"):
			authMux.ServeHTTP(w, r)
			return
		case r.URL.Path == healthzPath:
			next.ServeHTTP(w, r)
			return
		}

		sess, err := a.readSessionCookie(r)
		if err != nil {
			http.Redirect(w, r, LoginPath, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), sess)))
	})
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
