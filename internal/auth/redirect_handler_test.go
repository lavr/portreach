package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// newDynamicAuth builds an Authenticator in host-derived callback mode (empty
// RedirectURL) wired to a single fake provider. mut may tweak the config (e.g.
// set header names or the allowlist) before use.
func newDynamicAuth(fp *fakeProvider, mut func(*Config)) *Authenticator {
	pc := ProviderConfig{ID: fp.id, Type: fp.ptype}
	cfg := &Config{CookieKey: testKey(7), Providers: []ProviderConfig{pc}}
	if mut != nil {
		mut(cfg)
	}
	return &Authenticator{
		cfg:       cfg,
		providers: map[string]Provider{fp.id: fp},
		pcs:       map[string]ProviderConfig{fp.id: pc},
		order:     []string{fp.id},
	}
}

// loginWith runs handleLogin for a request carrying the given headers and
// returns the recorder plus the redirect_uri the fake provider saw.
func loginWith(t *testing.T, a *Authenticator, fp *fakeProvider, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, LoginPath+"?provider="+fp.id, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	a.handleLogin(rec, req)
	return rec
}

func TestCallbackDerivedFromForwardedHeaders(t *testing.T) {
	fp := &fakeProvider{id: "gh", ptype: TypeGitHub}
	a := newDynamicAuth(fp, nil)

	loginWith(t, a, fp, map[string]string{
		"X-Forwarded-Host":  "portreach.cluster-one.k8s",
		"X-Forwarded-Proto": "https",
	})

	if want := "https://portreach.cluster-one.k8s/auth/callback"; fp.lastAuthURL != want {
		t.Errorf("AuthCodeURL redirect = %q, want %q", fp.lastAuthURL, want)
	}
}

func TestCallbackDerivedFromOverriddenHeaderNames(t *testing.T) {
	fp := &fakeProvider{id: "gh", ptype: TypeGitHub}
	a := newDynamicAuth(fp, func(c *Config) {
		c.ForwardedHostHeader = "X-Original-Host"
		c.ForwardedProtoHeader = "X-Original-Proto"
	})

	// The standard headers must be ignored when custom names are configured.
	loginWith(t, a, fp, map[string]string{
		"X-Original-Host":   "vanity.corp",
		"X-Original-Proto":  "https",
		"X-Forwarded-Host":  "attacker.example",
		"X-Forwarded-Proto": "http",
	})

	if want := "https://vanity.corp/auth/callback"; fp.lastAuthURL != want {
		t.Errorf("AuthCodeURL redirect = %q, want %q (from custom headers)", fp.lastAuthURL, want)
	}
}

func TestCallbackDerivedFallbackToHost(t *testing.T) {
	fp := &fakeProvider{id: "gh", ptype: TypeGitHub}
	a := newDynamicAuth(fp, nil)

	// No forwarded headers: scheme falls back to plain http (no TLS) and host to
	// r.Host, which httptest sets to example.com.
	loginWith(t, a, fp, nil)

	if want := "http://example.com/auth/callback"; fp.lastAuthURL != want {
		t.Errorf("AuthCodeURL redirect = %q, want %q (fallback)", fp.lastAuthURL, want)
	}
}

func TestCallbackPinnedAcrossLoginAndCallback(t *testing.T) {
	// The redirect_uri derived at login must be replayed verbatim at the callback
	// even when the callback request's forwarded headers differ — proving the
	// value is pinned in the sealed state cookie, not recomputed.
	fp := &fakeProvider{id: "gh", ptype: TypeGitHub, identity: Identity{Login: "alice"}}
	a := newDynamicAuth(fp, nil)

	rec := loginWith(t, a, fp, map[string]string{
		"X-Forwarded-Host":  "login-host.k8s",
		"X-Forwarded-Proto": "https",
	})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")
	sc := stateCookie(rec)
	if sc == nil {
		t.Fatal("no state cookie set")
	}

	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&code=c", nil)
	// Deliberately different host on the callback leg.
	req.Header.Set("X-Forwarded-Host", "other-host.k8s")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.AddCookie(sc)
	a.handleCallback(httptest.NewRecorder(), req)

	if want := "https://login-host.k8s/auth/callback"; fp.lastExchURL != want {
		t.Errorf("Exchange redirect = %q, want %q (pinned from login)", fp.lastExchURL, want)
	}
}

func TestFixedRedirectURLDisablesOverride(t *testing.T) {
	// With a fixed redirectURL configured, no per-request override is applied:
	// both AuthCodeURL and Exchange receive an empty redirectURL (today's
	// behaviour), regardless of forwarded headers.
	fp := &fakeProvider{id: "gh", ptype: TypeGitHub, identity: Identity{Login: "alice"}}
	a := newTestAuth(nil, []ProviderConfig{{ID: "gh", Type: TypeGitHub}}, fp)

	req := httptest.NewRequest(http.MethodGet, LoginPath+"?provider=gh", nil)
	req.Header.Set("X-Forwarded-Host", "spoofed.example")
	rec := httptest.NewRecorder()
	a.handleLogin(rec, req)

	if fp.lastAuthURL != "" {
		t.Errorf("fixed mode AuthCodeURL redirect = %q, want empty", fp.lastAuthURL)
	}

	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")
	sc := stateCookie(rec)
	creq := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&code=c", nil)
	creq.AddCookie(sc)
	a.handleCallback(httptest.NewRecorder(), creq)
	if fp.lastExchURL != "" {
		t.Errorf("fixed mode Exchange redirect = %q, want empty", fp.lastExchURL)
	}
}

func TestAllowedRedirectHostsDeny(t *testing.T) {
	fp := &fakeProvider{id: "gh", ptype: TypeGitHub}
	a := newDynamicAuth(fp, func(c *Config) {
		c.AllowedRedirectHosts = []string{"good.k8s"}
	})

	rec := loginWith(t, a, fp, map[string]string{"X-Forwarded-Host": "evil.example"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for disallowed host", rec.Code)
	}
	if fp.lastAuthURL != "" {
		t.Error("disallowed host must not reach the provider (no IdP hit)")
	}
	if stateCookie(rec) != nil {
		t.Error("disallowed host must not set a state cookie")
	}
}

func TestAllowedRedirectHostsAllow(t *testing.T) {
	fp := &fakeProvider{id: "gh", ptype: TypeGitHub}
	a := newDynamicAuth(fp, func(c *Config) {
		c.AllowedRedirectHosts = []string{"good.k8s"}
	})

	rec := loginWith(t, a, fp, map[string]string{
		"X-Forwarded-Host":  "good.k8s",
		"X-Forwarded-Proto": "https",
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 for allowed host", rec.Code)
	}
	if want := "https://good.k8s/auth/callback"; fp.lastAuthURL != want {
		t.Errorf("AuthCodeURL redirect = %q, want %q", fp.lastAuthURL, want)
	}
}

func TestAllowedRedirectHostsEmptyAllowsAny(t *testing.T) {
	fp := &fakeProvider{id: "gh", ptype: TypeGitHub}
	a := newDynamicAuth(fp, nil) // empty allowlist

	rec := loginWith(t, a, fp, map[string]string{"X-Forwarded-Host": "anything.example"})
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (empty allowlist allows any)", rec.Code)
	}
}
