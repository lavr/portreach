package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRequestScheme(t *testing.T) {
	cases := []struct {
		name        string
		protoHeader string // configured override; "" = default X-Forwarded-Proto
		url         string // https:// sets r.TLS
		hdrName     string
		hdrVal      string
		want        string
	}{
		{"forwarded-https", "", "http://x/", "X-Forwarded-Proto", "https", "https"},
		{"forwarded-http-wins-over-tls", "", "https://x/", "X-Forwarded-Proto", "http", "http"},
		{"no-header-no-tls", "", "http://x/", "", "", "http"},
		{"no-header-tls", "", "https://x/", "", "", "https"},
		{"custom-header", "X-Scheme", "http://x/", "X-Scheme", "https", "https"},
		{"custom-header-ignores-standard", "X-Scheme", "http://x/", "X-Forwarded-Proto", "https", "http"},
		{"comma-list-takes-first", "", "http://x/", "X-Forwarded-Proto", "https, http", "https"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &Authenticator{cfg: &Config{ForwardedProtoHeader: c.protoHeader}}
			r := httptest.NewRequest(http.MethodGet, c.url, nil)
			if c.hdrName != "" {
				r.Header.Set(c.hdrName, c.hdrVal)
			}
			if got := a.requestScheme(r); got != c.want {
				t.Errorf("requestScheme = %q, want %q", got, c.want)
			}
			if got := a.requestIsHTTPS(r); got != (c.want == "https") {
				t.Errorf("requestIsHTTPS = %v, want %v", got, c.want == "https")
			}
		})
	}
}

func TestSecureForRequest(t *testing.T) {
	httpsReq := httptest.NewRequest(http.MethodGet, "https://x/", nil)
	httpReq := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	cases := []struct {
		mode        string
		https, http bool
	}{
		{"", true, false}, // empty == auto
		{cookieSecureAuto, true, false},
		{cookieSecureAlways, true, true},
		{cookieSecureNever, false, false},
	}
	for _, c := range cases {
		a := &Authenticator{cfg: &Config{CookieSecure: c.mode}}
		if got := a.secureForRequest(httpsReq); got != c.https {
			t.Errorf("mode %q over https: got %v, want %v", c.mode, got, c.https)
		}
		if got := a.secureForRequest(httpReq); got != c.http {
			t.Errorf("mode %q over http: got %v, want %v", c.mode, got, c.http)
		}
	}
}

// secureModeCases drives the per-mode/scheme expectations for the cookie tests.
var secureModeCases = []struct {
	mode  string
	proto string // X-Forwarded-Proto; "" = none
	want  bool
}{
	{cookieSecureAuto, "https", true},
	{cookieSecureAuto, "http", false},
	{cookieSecureAuto, "", false}, // no header, no TLS → http
	{cookieSecureAlways, "http", true},
	{cookieSecureAlways, "", true},
	{cookieSecureNever, "https", false},
}

func TestStateCookieSecureAttribute(t *testing.T) {
	for _, c := range secureModeCases {
		pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
		a := newTestAuth(nil, pcs, &fakeProvider{id: "gh", ptype: TypeGitHub})
		a.cfg.CookieSecure = c.mode

		req := httptest.NewRequest(http.MethodGet, LoginPath+"?provider=gh", nil)
		if c.proto != "" {
			req.Header.Set("X-Forwarded-Proto", c.proto)
		}
		rec := httptest.NewRecorder()
		a.handleLogin(rec, req)

		sc := stateCookie(rec)
		if sc == nil {
			t.Fatalf("mode=%s proto=%q: no state cookie set", c.mode, c.proto)
		}
		if sc.Secure != c.want {
			t.Errorf("mode=%s proto=%q: state cookie Secure=%v, want %v", c.mode, c.proto, sc.Secure, c.want)
		}
	}
}

// runHappyCallback runs the login+callback legs with the given headers on both
// and returns the callback recorder (which carries the session cookie and the
// cleared state cookie).
func runHappyCallback(t *testing.T, a *Authenticator, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	lreq := httptest.NewRequest(http.MethodGet, LoginPath+"?provider=gh", nil)
	for k, v := range headers {
		lreq.Header.Set(k, v)
	}
	lrec := httptest.NewRecorder()
	a.handleLogin(lrec, lreq)
	loc, _ := url.Parse(lrec.Header().Get("Location"))
	state := loc.Query().Get("state")
	sc := stateCookie(lrec)
	if sc == nil {
		t.Fatal("login leg set no state cookie")
	}

	creq := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&code=c", nil)
	for k, v := range headers {
		creq.Header.Set(k, v)
	}
	creq.AddCookie(sc)
	crec := httptest.NewRecorder()
	a.handleCallback(crec, creq)
	return crec
}

func TestSessionCookieSecureAttribute(t *testing.T) {
	for _, c := range secureModeCases {
		pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
		a := newTestAuth(nil, pcs, &fakeProvider{
			id: "gh", ptype: TypeGitHub, identity: Identity{Login: "alice"},
		})
		a.cfg.CookieSecure = c.mode

		headers := map[string]string{}
		if c.proto != "" {
			headers["X-Forwarded-Proto"] = c.proto
		}
		rec := runHappyCallback(t, a, headers)

		sess := sessionCookie(rec)
		if sess == nil {
			t.Fatalf("mode=%s proto=%q: no session cookie (status %d)", c.mode, c.proto, rec.Code)
		}
		if sess.Secure != c.want {
			t.Errorf("mode=%s proto=%q: session cookie Secure=%v, want %v", c.mode, c.proto, sess.Secure, c.want)
		}
		// The state cookie cleared during callback must carry the same Secure flag.
		if cleared := stateCookie(rec); cleared != nil && cleared.Secure != c.want {
			t.Errorf("mode=%s proto=%q: cleared state cookie Secure=%v, want %v", c.mode, c.proto, cleared.Secure, c.want)
		}
	}
}

func TestLogoutCookieSecureAttribute(t *testing.T) {
	newA := func() *Authenticator {
		a := newTestAuth(nil, []ProviderConfig{{ID: "gh", Type: TypeGitHub}},
			&fakeProvider{id: "gh", ptype: TypeGitHub})
		a.cfg.CookieSecure = cookieSecureAuto
		return a
	}

	// https → cleared with Secure.
	req := httptest.NewRequest(http.MethodGet, LogoutPath, nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	newA().handleLogout(rec, req)
	if sc := sessionCookie(rec); sc == nil || !sc.Secure {
		t.Errorf("logout over https should clear with Secure, got %+v", sc)
	}

	// http → cleared without Secure (so the browser actually removes it).
	req2 := httptest.NewRequest(http.MethodGet, LogoutPath, nil)
	rec2 := httptest.NewRecorder()
	newA().handleLogout(rec2, req2)
	if sc := sessionCookie(rec2); sc == nil || sc.Secure {
		t.Errorf("logout over http should clear without Secure, got %+v", sc)
	}
}

func TestCookieSecureMatchesDerivedCallbackScheme(t *testing.T) {
	// In auto mode the cookie Secure flag must agree with the scheme of the
	// host-derived redirect_uri for the same request.
	for _, proto := range []string{"https", "http"} {
		fp := &fakeProvider{id: "gh", ptype: TypeGitHub}
		a := newDynamicAuth(fp, nil) // RedirectURL empty, CookieSecure auto
		req := httptest.NewRequest(http.MethodGet, LoginPath+"?provider=gh", nil)
		req.Header.Set("X-Forwarded-Host", "portreach.k8s")
		req.Header.Set("X-Forwarded-Proto", proto)
		rec := httptest.NewRecorder()
		a.handleLogin(rec, req)

		sc := stateCookie(rec)
		if sc == nil {
			t.Fatalf("proto=%s: no state cookie", proto)
		}
		wantSecure := strings.HasPrefix(fp.lastAuthURL, "https://")
		if sc.Secure != wantSecure {
			t.Errorf("proto=%s: cookie Secure=%v but derived callback=%q", proto, sc.Secure, fp.lastAuthURL)
		}
	}
}

func TestCookieSecureValidation(t *testing.T) {
	base := func() *Config {
		return &Config{
			CookieKey: make([]byte, cookieKeyLen),
			Providers: []ProviderConfig{{ID: "gh", Type: TypeGitHub, ClientID: "a", ClientSecret: "b"}},
		}
	}
	for _, v := range []string{"", cookieSecureAuto, cookieSecureAlways, cookieSecureNever} {
		c := base()
		c.CookieSecure = v
		if err := c.Validate(); err != nil {
			t.Errorf("cookieSecure %q should validate: %v", v, err)
		}
	}
	c := base()
	c.CookieSecure = "bogus"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "cookieSecure") {
		t.Errorf("want cookieSecure error, got %v", err)
	}
}
