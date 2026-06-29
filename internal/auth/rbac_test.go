package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAllowedFailsClosedOnUnknownProvider guards the core fail-closed contract:
// a Session.Provider id present in neither the browser providers nor the API
// entries must be denied, never default-allowed against an empty allowlist.
func TestAllowedFailsClosedOnUnknownProvider(t *testing.T) {
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{ID: "ci", Issuer: bi.url, Audience: "portreach"})

	// "ci" with no allowlist passes (open entry); an unknown id is denied.
	if !a.allowed("ci", Identity{Login: "alice"}) {
		t.Error("known open entry should allow")
	}
	if a.allowed("forged", Identity{Login: "alice", Groups: []string{"platform"}}) {
		t.Error("unknown provider id must fail closed (deny)")
	}
}

// TestBearerAllowlistGroupEnforced exercises the middleware end-to-end: a bearer
// identity is subject to the matched entry's group allowlist exactly like a
// cookie session — member → 200, non-member → 403 JSON.
func TestBearerAllowlistGroupEnforced(t *testing.T) {
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{
		ID: "ci", Issuer: bi.url, Audience: "portreach",
		AllowedGroups: []string{"platform"},
	})

	// Member of an allowed group → authorized.
	member := bi.mint(t, map[string]any{"sub": "alice", "groups": []string{"platform", "other"}})
	if code := serveBearer(t, a, "/api/check", member); code != http.StatusOK {
		t.Errorf("allowlisted member = %d, want 200", code)
	}

	// Verified token, but no allowed group → 403, not 401 (it authenticated).
	nonmember := bi.mint(t, map[string]any{"sub": "mallory", "groups": []string{"interns"}})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/check", nil)
	req.Header.Set("Authorization", "Bearer "+nonmember)
	a.Middleware(&okHandler{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-member = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("403 content-type = %q, want json", ct)
	}
}

// TestBearerAllowlistUserEnforced covers the per-entry AllowedUsers list (which
// browser providers lack — they only honour the global AllowedUsers).
func TestBearerAllowlistUserEnforced(t *testing.T) {
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{
		ID: "ci", Issuer: bi.url, Audience: "portreach",
		AllowedUsers: []string{"svc-deploy"},
	})

	if code := serveBearer(t, a, "/api/check", bi.mint(t, map[string]any{"sub": "svc-deploy"})); code != http.StatusOK {
		t.Errorf("per-entry allowed user = %d, want 200", code)
	}
	if code := serveBearer(t, a, "/api/check", bi.mint(t, map[string]any{"sub": "stranger"})); code != http.StatusForbidden {
		t.Errorf("user outside per-entry allowlist = %d, want 403", code)
	}
}

// TestBearerAuditCarriesIdentityAndMethod confirms the audit event for a token
// call records the token's user, the matched entry id as provider, and
// auth_method=bearer.
func TestBearerAuditCarriesIdentityAndMethod(t *testing.T) {
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{ID: "ci", Issuer: bi.url, Audience: "portreach"})
	logger, decode := captureLogger()

	// Middleware injects identity + method; AuditCheck reads them off the context.
	h := a.Middleware(AuditCheck(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	req := httptest.NewRequest(http.MethodGet, apiCheckPath+"?host=db&port=5432", nil)
	req.Header.Set("Authorization", "Bearer "+bi.mint(t, map[string]any{"sub": "alice"}))
	h.ServeHTTP(httptest.NewRecorder(), req)

	ev := onlyEvent(t, decode(t))
	wantField(t, ev, "event", "check")
	wantField(t, ev, "user", "alice")
	wantField(t, ev, "provider", "ci")
	wantField(t, ev, "auth_method", "bearer")
}

// TestCookieAuditMethod confirms a cookie session is audited with
// auth_method=cookie (the counterpart to the bearer case above).
func TestCookieAuditMethod(t *testing.T) {
	a := newTestAuth(nil, []ProviderConfig{{ID: "corp", Type: TypeOIDC}},
		&fakeProvider{id: "corp", ptype: TypeOIDC})
	logger, decode := captureLogger()

	rec := httptest.NewRecorder()
	sess := Session{User: "bob", Provider: "corp", Expiry: time.Now().Add(time.Hour).Unix()}
	if err := setSessionCookie(rec, a.cfg.CookieKey, sess, true); err != nil {
		t.Fatalf("seal session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, indexPath+"?host=db&port=5432", nil)
	req.AddCookie(sessionCookie(rec))

	a.Middleware(AuditCheck(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))).
		ServeHTTP(httptest.NewRecorder(), req)

	ev := onlyEvent(t, decode(t))
	wantField(t, ev, "user", "bob")
	wantField(t, ev, "provider", "corp")
	wantField(t, ev, "auth_method", "cookie")
}

// serveBearer drives one request through a's middleware with the given bearer
// token and returns the status code.
func serveBearer(t *testing.T, a *Authenticator, path, token string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	a.Middleware(&okHandler{}).ServeHTTP(rec, req)
	return rec.Code
}
