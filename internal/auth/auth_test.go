package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeProvider is a hermetic Provider for handler tests: AuthCodeURL echoes the
// state/nonce into a query string and Exchange returns a canned Identity (or
// error), recording the nonce it was given.
type fakeProvider struct {
	id        string
	display   string
	ptype     string
	identity  Identity
	exchErr   error
	lastNonce string
}

func (f *fakeProvider) ID() string          { return f.id }
func (f *fakeProvider) DisplayName() string { return f.display }
func (f *fakeProvider) Type() string        { return f.ptype }

func (f *fakeProvider) AuthCodeURL(state, nonce string) string {
	return "https://provider.example/authorize?state=" + url.QueryEscape(state) +
		"&nonce=" + url.QueryEscape(nonce)
}

func (f *fakeProvider) Exchange(_ context.Context, _, nonce string) (Identity, error) {
	f.lastNonce = nonce
	return f.identity, f.exchErr
}

// newTestAuth builds an Authenticator wired to the given fake providers. pcs must
// align by index with providers (same id), supplying the allowlists.
func newTestAuth(allowedUsers []string, pcs []ProviderConfig, providers ...Provider) *Authenticator {
	cfg := &Config{
		RedirectURL:  "https://portreach.corp/auth/callback",
		CookieKey:    testKey(7),
		AllowedUsers: allowedUsers,
		Providers:    pcs,
	}
	a := &Authenticator{
		cfg:       cfg,
		providers: make(map[string]Provider),
		pcs:       make(map[string]ProviderConfig),
	}
	for i, p := range providers {
		a.providers[p.ID()] = p
		a.pcs[p.ID()] = pcs[i]
		a.order = append(a.order, p.ID())
	}
	return a
}

func TestLoginPageListsAllProviders(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}, {ID: "gl", Type: TypeGitLab}}
	a := newTestAuth(nil, pcs,
		&fakeProvider{id: "gh", display: "GitHub", ptype: TypeGitHub},
		&fakeProvider{id: "gl", display: "Corporate GitLab", ptype: TypeGitLab},
	)

	rec := httptest.NewRecorder()
	a.handleLogin(rec, httptest.NewRequest(http.MethodGet, LoginPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"GitHub", "Corporate GitLab",
		LoginPath + "?provider=gh", LoginPath + "?provider=gl"} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %q\n%s", want, body)
		}
	}
}

func TestLoginPageSingleProviderShowsButtonNoRedirect(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth(nil, pcs, &fakeProvider{id: "gh", display: "GitHub", ptype: TypeGitHub})

	rec := httptest.NewRecorder()
	a.handleLogin(rec, httptest.NewRequest(http.MethodGet, LoginPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("single provider should render a page (200), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), LoginPath+"?provider=gh") {
		t.Errorf("single-provider login page missing its button:\n%s", rec.Body.String())
	}
}

func TestLoginPageLocalizedRussian(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth(nil, pcs, &fakeProvider{id: "gh", display: "GitHub", ptype: TypeGitHub})

	req := httptest.NewRequest(http.MethodGet, LoginPath, nil)
	req.Header.Set("Accept-Language", "ru")
	rec := httptest.NewRecorder()
	a.handleLogin(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Вход в portreach") {
		t.Errorf("ru login page missing Russian heading:\n%s", body)
	}
	if !strings.Contains(body, `lang="ru"`) {
		t.Errorf("ru login page missing lang attribute:\n%s", body)
	}
}

func TestLoginPageLocalizedDefaultEnglish(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth(nil, pcs, &fakeProvider{id: "gh", display: "GitHub", ptype: TypeGitHub})

	rec := httptest.NewRecorder()
	a.handleLogin(rec, httptest.NewRequest(http.MethodGet, LoginPath, nil))

	body := rec.Body.String()
	if !strings.Contains(body, "Sign in to portreach") {
		t.Errorf("default login page should be English:\n%s", body)
	}
	if !strings.Contains(body, `lang="en"`) {
		t.Errorf("default login page missing en lang attribute:\n%s", body)
	}
}

func TestLoginProviderSelectionRedirects(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth(nil, pcs, &fakeProvider{id: "gh", display: "GitHub", ptype: TypeGitHub})

	rec := httptest.NewRecorder()
	a.handleLogin(rec, httptest.NewRequest(http.MethodGet, LoginPath+"?provider=gh", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "provider.example/authorize") {
		t.Errorf("redirect Location = %q, want provider authorize URL", loc)
	}
	if !strings.Contains(loc, "state=") || !strings.Contains(loc, "nonce=") {
		t.Errorf("redirect Location = %q, missing state/nonce", loc)
	}
	// The sealed state cookie must be set.
	if stateCookie(rec) == nil {
		t.Error("provider selection did not set the oauth state cookie")
	}
}

func TestLoginUnknownProvider(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth(nil, pcs, &fakeProvider{id: "gh", display: "GitHub", ptype: TypeGitHub})

	rec := httptest.NewRecorder()
	a.handleLogin(rec, httptest.NewRequest(http.MethodGet, LoginPath+"?provider=nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for unknown provider", rec.Code)
	}
}

// stateCookie extracts the oauth state cookie from a recorder, or nil.
func stateCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == oauthStateCookieName {
			return c
		}
	}
	return nil
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

// beginLogin runs handleLogin for a provider and returns the minted state plus
// the state cookie, ready to feed into a callback request.
func beginLogin(t *testing.T, a *Authenticator, provider string) (string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.handleLogin(rec, httptest.NewRequest(http.MethodGet, LoginPath+"?provider="+provider, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("beginLogin status = %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state in redirect")
	}
	sc := stateCookie(rec)
	if sc == nil {
		t.Fatal("no state cookie set")
	}
	return state, sc
}

func TestCallbackHappyPathSetsSession(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth(nil, pcs, &fakeProvider{
		id: "gh", display: "GitHub", ptype: TypeGitHub,
		identity: Identity{Login: "alice", Name: "Alice", Groups: []string{"myorg"}},
	})

	state, sc := beginLogin(t, a, "gh")

	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&code=thecode", nil)
	req.AddCookie(sc)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302\n%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("redirect = %q, want /", loc)
	}
	session := sessionCookie(rec)
	if session == nil {
		t.Fatal("happy-path callback did not set a session cookie")
	}
	sess, err := open(a.cfg.CookieKey, session.Value, time.Now())
	if err != nil {
		t.Fatalf("session cookie did not open: %v", err)
	}
	if sess.User != "alice" || sess.Provider != "gh" {
		t.Errorf("session = %+v, want user=alice provider=gh", sess)
	}
}

func TestCallbackThreadsNonce(t *testing.T) {
	fp := &fakeProvider{
		id: "gl", display: "GitLab", ptype: TypeGitLab,
		identity: Identity{Login: "bob"},
	}
	pcs := []ProviderConfig{{ID: "gl", Type: TypeGitLab}}
	a := newTestAuth(nil, pcs, fp)

	// Capture the nonce baked into the redirect, then ensure Exchange sees it.
	rec := httptest.NewRecorder()
	a.handleLogin(rec, httptest.NewRequest(http.MethodGet, LoginPath+"?provider=gl", nil))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	wantNonce := loc.Query().Get("nonce")
	state := loc.Query().Get("state")
	sc := stateCookie(rec)

	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&code=c", nil)
	req.AddCookie(sc)
	a.handleCallback(httptest.NewRecorder(), req)

	if fp.lastNonce != wantNonce {
		t.Errorf("Exchange nonce = %q, want %q (threaded from state cookie)", fp.lastNonce, wantNonce)
	}
}

func TestCallbackStateMismatch(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth(nil, pcs, &fakeProvider{id: "gh", ptype: TypeGitHub, identity: Identity{Login: "alice"}})

	_, sc := beginLogin(t, a, "gh")

	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?state=wrong&code=c", nil)
	req.AddCookie(sc)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 on state mismatch", rec.Code)
	}
	if sessionCookie(rec) != nil {
		t.Error("state mismatch must not set a session cookie")
	}
}

func TestCallbackMissingStateCookie(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth(nil, pcs, &fakeProvider{id: "gh", ptype: TypeGitHub})

	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?state=x&code=c", nil)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 when state cookie absent", rec.Code)
	}
}

func TestCallbackAllowlistDeny(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub, AllowedOrgs: []string{"infra"}}}
	a := newTestAuth(nil, pcs, &fakeProvider{
		id: "gh", ptype: TypeGitHub,
		identity: Identity{Login: "alice", Groups: []string{"other-team"}},
	})

	state, sc := beginLogin(t, a, "gh")
	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&code=c", nil)
	req.AddCookie(sc)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for denied user", rec.Code)
	}
	if sessionCookie(rec) != nil {
		t.Error("denied user must not get a session cookie")
	}
	if !strings.Contains(rec.Body.String(), "Access denied") {
		t.Errorf("denied page missing message:\n%s", rec.Body.String())
	}
}

func TestCallbackAllowlistAllowByGroup(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub, AllowedOrgs: []string{"infra"}}}
	a := newTestAuth(nil, pcs, &fakeProvider{
		id: "gh", ptype: TypeGitHub,
		identity: Identity{Login: "alice", Groups: []string{"infra"}},
	})

	state, sc := beginLogin(t, a, "gh")
	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&code=c", nil)
	req.AddCookie(sc)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 for allowed group member", rec.Code)
	}
}

func TestCallbackAllowlistAllowByUser(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth([]string{"alice"}, pcs, &fakeProvider{
		id: "gh", ptype: TypeGitHub,
		identity: Identity{Login: "alice"},
	})

	state, sc := beginLogin(t, a, "gh")
	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&code=c", nil)
	req.AddCookie(sc)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 for allowed user", rec.Code)
	}
}

func TestAllowedNoListsAllowsAny(t *testing.T) {
	a := newTestAuth(nil, []ProviderConfig{{ID: "gh", Type: TypeGitHub}},
		&fakeProvider{id: "gh", ptype: TypeGitHub})
	if !a.allowed("gh", Identity{Login: "anyone", Groups: []string{"random"}}) {
		t.Error("with no allowlist any authenticated user should pass")
	}
}

func TestCallbackExchangeError(t *testing.T) {
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth(nil, pcs, &fakeProvider{
		id: "gh", ptype: TypeGitHub, exchErr: context.DeadlineExceeded,
	})

	state, sc := beginLogin(t, a, "gh")
	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&code=c", nil)
	req.AddCookie(sc)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 on exchange failure", rec.Code)
	}
}

func TestLogoutClearsSession(t *testing.T) {
	a := newTestAuth(nil, []ProviderConfig{{ID: "gh", Type: TypeGitHub}},
		&fakeProvider{id: "gh", ptype: TypeGitHub})

	rec := httptest.NewRecorder()
	a.handleLogout(rec, httptest.NewRequest(http.MethodGet, LogoutPath, nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	sc := sessionCookie(rec)
	if sc == nil || sc.MaxAge >= 0 {
		t.Errorf("logout should expire the session cookie, got %+v", sc)
	}
}

func TestButtonLabelFallsBackToType(t *testing.T) {
	// A provider with no DisplayName uses the localized "Sign in with <type>".
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth(nil, pcs, &fakeProvider{id: "gh", display: "", ptype: TypeGitHub})

	rec := httptest.NewRecorder()
	a.handleLogin(rec, httptest.NewRequest(http.MethodGet, LoginPath, nil))

	if !strings.Contains(rec.Body.String(), "Sign in with github") {
		t.Errorf("expected fallback label, body:\n%s", rec.Body.String())
	}
}
