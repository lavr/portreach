package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The configured (fixed) callback used by the provider test fixtures.
const fixedCallback = "https://portreach.corp/auth/callback"

func TestGitHubAuthCodeURLRedirectOverride(t *testing.T) {
	p := newGitHubProvider(ProviderConfig{ID: "gh", Type: TypeGitHub}, fixedCallback)

	// A non-empty override replaces the configured redirect_uri for this request.
	got := p.AuthCodeURL("s", "", "https://vanity.corp/auth/callback")
	if !strings.Contains(got, "redirect_uri="+url.QueryEscape("https://vanity.corp/auth/callback")) {
		t.Errorf("override not applied: %q", got)
	}
	// An empty override leaves the configured default in place.
	def := p.AuthCodeURL("s", "", "")
	if !strings.Contains(def, "redirect_uri="+url.QueryEscape(fixedCallback)) {
		t.Errorf("default redirect_uri missing: %q", def)
	}
	if strings.Contains(def, "vanity.corp") {
		t.Errorf("empty override should not inject a host: %q", def)
	}
}

func TestOIDCAuthCodeURLRedirectOverride(t *testing.T) {
	p, _ := newTestOIDC(t, ProviderConfig{}, func(string) map[string]any { return map[string]any{} })

	got := p.AuthCodeURL("s", "n", "https://vanity.corp/auth/callback")
	if !strings.Contains(got, "redirect_uri="+url.QueryEscape("https://vanity.corp/auth/callback")) {
		t.Errorf("override not applied: %q", got)
	}
	def := p.AuthCodeURL("s", "n", "")
	if !strings.Contains(def, "redirect_uri="+url.QueryEscape(fixedCallback)) {
		t.Errorf("default redirect_uri missing: %q", def)
	}
	if strings.Contains(def, "vanity.corp") {
		t.Errorf("empty override should not inject a host: %q", def)
	}
}

func TestGitHubExchangeSendsRedirectURI(t *testing.T) {
	var gotRedirect string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			_ = r.ParseForm()
			gotRedirect = r.Form.Get("redirect_uri")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"t","token_type":"bearer"}`))
		case "/api/v3/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"login":"octocat"}`))
		case "/api/v3/user/orgs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	p := newTestGitHub(t, ts.URL, ts.Client())
	if _, err := p.Exchange(context.Background(), "code", "", "https://vanity.corp/auth/callback"); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if gotRedirect != "https://vanity.corp/auth/callback" {
		t.Errorf("token request redirect_uri = %q, want override", gotRedirect)
	}
}

func TestOIDCExchangeSendsRedirectURI(t *testing.T) {
	var gotRedirect string
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/jwks")
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotRedirect = r.PostForm.Get("redirect_uri")
		w.Header().Set("Content-Type", "application/json")
		// No id_token: Exchange errors after the token POST, which is fine — the
		// redirect_uri has already been captured by then.
		_, _ = w.Write([]byte(`{"access_token":"t","token_type":"bearer"}`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	p, err := newOIDCProvider(context.Background(),
		ProviderConfig{ID: "x", Type: TypeOIDC, Issuer: srv.URL, ClientID: "client-id", ClientSecret: "s"},
		fixedCallback)
	if err != nil {
		t.Fatalf("newOIDCProvider: %v", err)
	}
	// Exchange is expected to fail (no id_token); we only assert the override
	// redirect_uri reached the token endpoint.
	_, _ = p.Exchange(context.Background(), "code", "n1", "https://vanity.corp/auth/callback")
	if gotRedirect != "https://vanity.corp/auth/callback" {
		t.Errorf("token request redirect_uri = %q, want override", gotRedirect)
	}
}
