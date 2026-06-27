package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// okHandler records whether it ran and the Session it saw on the context.
type okHandler struct {
	called bool
	sess   Session
	hadID  bool
}

func (h *okHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.sess, h.hadID = IdentityFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

// authForMiddleware builds a single-provider Authenticator for middleware tests.
func authForMiddleware() *Authenticator {
	return newTestAuth(nil, []ProviderConfig{{ID: "gh", Type: TypeGitHub}},
		&fakeProvider{id: "gh", display: "GitHub", ptype: TypeGitHub})
}

func TestMiddlewareHealthzPublic(t *testing.T) {
	a := authForMiddleware()
	next := &okHandler{}
	h := a.Middleware(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, healthzPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (healthz must be public)", rec.Code)
	}
	if !next.called {
		t.Error("healthz must reach the wrapped handler unauthenticated")
	}
	if next.hadID {
		t.Error("public healthz request should carry no identity")
	}
}

func TestMiddlewareProtectedRedirectsWhenNoSession(t *testing.T) {
	a := authForMiddleware()
	next := &okHandler{}
	h := a.Middleware(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 for unauthenticated protected path", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != LoginPath {
		t.Errorf("redirect = %q, want %q", loc, LoginPath)
	}
	if next.called {
		t.Error("unauthenticated request must not reach the wrapped handler")
	}
}

func TestMiddlewareServesAuthRoutes(t *testing.T) {
	a := authForMiddleware()
	next := &okHandler{}
	h := a.Middleware(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, LoginPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("login page status = %d, want 200", rec.Code)
	}
	if next.called {
		t.Error("/auth/* routes must be served by the auth mux, not the wrapped handler")
	}
}

func TestMiddlewareValidSessionPassesAndInjectsIdentity(t *testing.T) {
	a := authForMiddleware()
	next := &okHandler{}
	h := a.Middleware(next)

	sess := Session{User: "alice", Provider: "gh", Groups: []string{"infra"},
		Expiry: time.Now().Add(time.Hour).Unix()}
	rec := httptest.NewRecorder()
	if err := setSessionCookie(rec, a.cfg.CookieKey, sess, true); err != nil {
		t.Fatalf("seal session: %v", err)
	}
	cookie := sessionCookie(rec)
	if cookie == nil {
		t.Fatal("no session cookie produced")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)

	if out.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for valid session", out.Code)
	}
	if !next.called {
		t.Fatal("valid session must reach the wrapped handler")
	}
	if !next.hadID {
		t.Fatal("authenticated request must carry identity in context")
	}
	if next.sess.User != "alice" || next.sess.Provider != "gh" {
		t.Errorf("context session = %+v, want user=alice provider=gh", next.sess)
	}
}

func TestMiddlewareRejectsTamperedSession(t *testing.T) {
	a := authForMiddleware()
	next := &okHandler{}
	h := a.Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "not-a-valid-token"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 for tampered session", rec.Code)
	}
	if next.called {
		t.Error("tampered session must not reach the wrapped handler")
	}
}
