package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// bearerIssuer is a hermetic OIDC issuer for bearer-token tests: it serves
// discovery + JWKS and can mint RS256 access tokens signed by its key.
type bearerIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	url string
}

// newBearerIssuer starts a fake issuer (discovery + JWKS) and returns it.
func newBearerIssuer(t *testing.T) *bearerIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	bi := &bearerIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			bi.url, bi.url+"/authorize", bi.url+"/token", bi.url+"/jwks")
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, jwksJSON(key))
	})
	bi.srv = httptest.NewServer(mux)
	bi.url = bi.srv.URL
	t.Cleanup(bi.srv.Close)
	return bi
}

// mint signs an access token for this issuer, filling iss/aud/exp/iat defaults
// (issuer url, audience "portreach", +1h) when the caller leaves them unset.
func (bi *bearerIssuer) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	c := map[string]any{}
	for k, v := range claims {
		c[k] = v
	}
	if _, ok := c["iss"]; !ok {
		c["iss"] = bi.url
	}
	if _, ok := c["aud"]; !ok {
		c["aud"] = "portreach"
	}
	if _, ok := c["exp"]; !ok {
		c["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := c["iat"]; !ok {
		c["iat"] = time.Now().Unix()
	}
	return signJWT(t, bi.key, c)
}

// newBearerAuth builds an Authenticator with a single API entry pointed at bi.
func newBearerAuth(t *testing.T, entry APIEntry) *Authenticator {
	t.Helper()
	if entry.ID == "" {
		entry.ID = "ci"
	}
	if entry.Audience == "" {
		entry.Audience = "portreach"
	}
	a, err := New(&Config{API: []APIEntry{entry}})
	if err != nil {
		t.Fatalf("New (bearer): %v", err)
	}
	return a
}

func TestBearerValidTokenAuthenticates(t *testing.T) {
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{ID: "ci", Issuer: bi.url, Audience: "portreach"})

	tok := bi.mint(t, map[string]any{"preferred_username": "alice", "name": "Alice", "groups": []string{"platform"}})
	sess, ok := a.authenticateBearer(t.Context(), tok)
	if !ok {
		t.Fatal("valid token should authenticate")
	}
	if sess.User != "alice" || sess.Provider != "ci" {
		t.Errorf("session = %+v, want user=alice provider=ci", sess)
	}
	if len(sess.Groups) != 1 || sess.Groups[0] != "platform" {
		t.Errorf("groups = %v, want [platform]", sess.Groups)
	}
}

func TestBearerSubFallbackForUsername(t *testing.T) {
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{ID: "ci", Issuer: bi.url, Audience: "portreach"})

	// No preferred_username → fall back to sub.
	tok := bi.mint(t, map[string]any{"sub": "svc-account"})
	sess, ok := a.authenticateBearer(t.Context(), tok)
	if !ok || sess.User != "svc-account" {
		t.Fatalf("sub fallback failed: ok=%v user=%q", ok, sess.User)
	}
}

func TestBearerGitLabPresetGroupsFallback(t *testing.T) {
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{ID: "ci", Type: TypeGitLab, Issuer: bi.url, Audience: "portreach"})

	// GitLab tokens may carry groups_direct instead of groups; the preset's
	// fallback must pick it up.
	tok := bi.mint(t, map[string]any{"preferred_username": "bob", "groups_direct": []string{"acme/backend"}})
	sess, ok := a.authenticateBearer(t.Context(), tok)
	if !ok {
		t.Fatal("token should authenticate")
	}
	if len(sess.Groups) != 1 || sess.Groups[0] != "acme/backend" {
		t.Errorf("groups = %v, want [acme/backend] via groups_direct fallback", sess.Groups)
	}
}

func TestBearerEmailVerifiedGate(t *testing.T) {
	// With UsernameClaim "email", an attacker-controllable email must be IdP-verified.
	// Only an explicit email_verified:false is rejected; an absent claim is allowed
	// (it is optional) and falls through to the email identity.
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{ID: "ci", Issuer: bi.url, Audience: "portreach", UsernameClaim: "email"})

	t.Run("verified-true authenticates as email", func(t *testing.T) {
		tok := bi.mint(t, map[string]any{"email": "alice@corp.com", "email_verified": true})
		sess, ok := a.authenticateBearer(t.Context(), tok)
		if !ok || sess.User != "alice@corp.com" {
			t.Fatalf("verified email: ok=%v user=%q, want alice@corp.com", ok, sess.User)
		}
	})

	t.Run("verified-false rejects the whole token", func(t *testing.T) {
		// An unverified email rejects the entry outright — it does not silently fall
		// back to sub, since a sub-based identity was not what the config asked for.
		tok := bi.mint(t, map[string]any{"email": "evil@corp.com", "email_verified": false, "sub": "svc"})
		if _, ok := a.authenticateBearer(t.Context(), tok); ok {
			t.Fatal("unverified email must not authenticate, even with a sub present")
		}
	})

	t.Run("absent claim is allowed", func(t *testing.T) {
		tok := bi.mint(t, map[string]any{"email": "bob@corp.com"})
		sess, ok := a.authenticateBearer(t.Context(), tok)
		if !ok || sess.User != "bob@corp.com" {
			t.Fatalf("absent email_verified: ok=%v user=%q, want bob@corp.com", ok, sess.User)
		}
	})
}

func TestBearerRejects(t *testing.T) {
	bi := newBearerIssuer(t)
	other := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{ID: "ci", Issuer: bi.url, Audience: "portreach"})

	cases := []struct {
		name string
		tok  string
	}{
		{"wrong-audience", bi.mint(t, map[string]any{"sub": "x", "aud": "someone-else"})},
		{"absent-audience", bi.mint(t, map[string]any{"sub": "x", "aud": ""})},
		{"expired", bi.mint(t, map[string]any{"sub": "x", "exp": time.Now().Add(-time.Minute).Unix()})},
		{"wrong-issuer", other.mint(t, map[string]any{"sub": "x"})}, // signed by a different issuer/key
		{"garbage", "not.a.jwt"},
		{"empty-subject", bi.mint(t, map[string]any{})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := a.authenticateBearer(t.Context(), c.tok); ok {
				t.Fatalf("%s token must not authenticate", c.name)
			}
		})
	}
}

func TestBearerBadSignatureRejected(t *testing.T) {
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{ID: "ci", Issuer: bi.url, Audience: "portreach"})

	// A token signed by a foreign key but claiming bi's issuer/audience: the
	// signature will not verify against bi's JWKS.
	foreign, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	claims := map[string]any{"iss": bi.url, "aud": "portreach", "sub": "evil",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
	tok := signJWT(t, foreign, claims)
	if _, ok := a.authenticateBearer(t.Context(), tok); ok {
		t.Fatal("forged-signature token must not authenticate")
	}
}

func TestBearerUnmatchedIssuerAcrossEntries(t *testing.T) {
	// Two configured entries; a token minted by a third, unconfigured issuer must
	// match neither (fail-closed, not an open pass with empty groups).
	bi1 := newBearerIssuer(t)
	bi2 := newBearerIssuer(t)
	stranger := newBearerIssuer(t)
	a, err := New(&Config{API: []APIEntry{
		{ID: "a", Issuer: bi1.url, Audience: "portreach"},
		{ID: "b", Issuer: bi2.url, Audience: "portreach"},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok := stranger.mint(t, map[string]any{"sub": "x"})
	if _, ok := a.authenticateBearer(t.Context(), tok); ok {
		t.Fatal("token from an unconfigured issuer must not authenticate")
	}
	// Sanity: a token for entry b's issuer resolves to provider id "b".
	tok2 := bi2.mint(t, map[string]any{"sub": "y"})
	sess, ok := a.authenticateBearer(t.Context(), tok2)
	if !ok || sess.Provider != "b" {
		t.Fatalf("entry-b token: ok=%v provider=%q, want provider=b", ok, sess.Provider)
	}
}

// --- Middleware route-semantics tests (API-only + mixed) ---

func TestMiddlewareAPIOnlyBearerPaths(t *testing.T) {
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{ID: "ci", Issuer: bi.url, Audience: "portreach"})
	next := &okHandler{}
	h := a.Middleware(next)

	// /api/check with no token → 401 JSON, never a redirect.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/check", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/api/check no token = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q, want json", ct)
	}
	if next.called {
		t.Error("unauthenticated /api/check must not reach the handler")
	}

	// /api/check with a valid token → handler runs with identity.
	next = &okHandler{}
	h = a.Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/api/check", nil)
	req.Header.Set("Authorization", "Bearer "+bi.mint(t, map[string]any{"sub": "alice"}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/check valid token = %d, want 200", rec.Code)
	}
	if !next.called || !next.hadID || next.sess.User != "alice" || next.sess.Provider != "ci" {
		t.Errorf("identity not injected: called=%v hadID=%v sess=%+v", next.called, next.hadID, next.sess)
	}
}

func TestMiddlewareAPIOnlyBrowserPathReturns401NotRedirect(t *testing.T) {
	// In API-only mode there is no login page, so a browser path must 401 rather
	// than redirect to an empty login.
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{ID: "ci", Issuer: bi.url, Audience: "portreach"})
	next := &okHandler{}
	h := a.Middleware(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/ in API-only mode = %d, want 401 (no login page)", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("must not redirect in API-only mode, got Location=%q", loc)
	}
}

func TestMiddlewareInvalidBearerAlways401(t *testing.T) {
	bi := newBearerIssuer(t)
	a := newBearerAuth(t, APIEntry{ID: "ci", Issuer: bi.url, Audience: "portreach"})
	next := &okHandler{}
	h := a.Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid bearer on browser path = %d, want 401", rec.Code)
	}
	if next.called {
		t.Error("invalid bearer must not reach the handler")
	}
}

func TestMiddlewareMixedModeCookieStillWorks(t *testing.T) {
	// Browser + API both configured: a valid session cookie authenticates a
	// browser path even though the bearer path is also enabled.
	bi := newBearerIssuer(t)
	srv := newIssuerServer(t)
	a, err := New(&Config{
		RedirectURL: "https://portreach.corp/auth/callback",
		CookieKey:   testKey(7),
		Providers:   []ProviderConfig{{ID: "corp", Type: TypeOIDC, Issuer: srv.URL, ClientID: "c", ClientSecret: "s"}},
		API:         []APIEntry{{ID: "ci", Issuer: bi.url, Audience: "portreach"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	next := &okHandler{}
	h := a.Middleware(next)

	sess := Session{User: "bob", Provider: "corp", Expiry: time.Now().Add(time.Hour).Unix()}
	rec := httptest.NewRecorder()
	if err := setSessionCookie(rec, a.cfg.CookieKey, sess, true); err != nil {
		t.Fatalf("seal session: %v", err)
	}
	cookie := sessionCookie(rec)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != http.StatusOK || !next.called || next.sess.User != "bob" {
		t.Fatalf("cookie path broken in mixed mode: code=%d called=%v sess=%+v", out.Code, next.called, next.sess)
	}

	// And a browser path with neither credential still redirects to login.
	next = &okHandler{}
	h = a.Middleware(next)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("mixed-mode browser path no creds = %d, want 302 redirect", rec.Code)
	}
}

func TestBearerDisabledWhenUnconfigured(t *testing.T) {
	// No API entries: a bearer token is ignored (the cookie path governs) and the
	// browser redirect still applies.
	a := authForMiddleware() // GitHub provider only, no API
	if a.cfg.apiEnabled() {
		t.Fatal("config without api entries must not report apiEnabled")
	}
	next := &okHandler{}
	h := a.Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer whatever")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("bearer ignored when unconfigured: code=%d, want 302 redirect", rec.Code)
	}

	// On an /api/* path the cookie governs (no api entry honors the bearer), so a
	// presented bearer is ignored and the missing cookie yields a 401 JSON — never
	// an auth bypass that lets the handler run.
	next2 := &okHandler{}
	h = a.Middleware(next2)
	apiReq := httptest.NewRequest(http.MethodGet, "/api/check", nil)
	apiReq.Header.Set("Authorization", "Bearer whatever")
	apiRec := httptest.NewRecorder()
	h.ServeHTTP(apiRec, apiReq)
	if apiRec.Code != http.StatusUnauthorized {
		t.Fatalf("bearer on /api/* when unconfigured: code=%d, want 401", apiRec.Code)
	}
	if next2.called {
		t.Error("unconfigured bearer must not reach the /api/* handler")
	}
}

func TestBearerTokenHeaderParsing(t *testing.T) {
	cases := []struct {
		hdr  string
		want string
	}{
		{"Bearer abc", "abc"},
		{"bearer abc", "abc"},
		{"BEARER  abc  ", "abc"},
		{"Basic abc", ""},
		{"abc", ""},
		{"", ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.hdr != "" {
			r.Header.Set("Authorization", c.hdr)
		}
		if got := bearerToken(r); got != c.want {
			t.Errorf("bearerToken(%q) = %q, want %q", c.hdr, got, c.want)
		}
	}
}
