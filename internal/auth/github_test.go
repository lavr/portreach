package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestGitHub builds a githubProvider whose OAuth + REST endpoints point at
// the given test server, with the server's client injected so getJSON attaches
// the bearer token explicitly.
func newTestGitHub(t *testing.T, baseURL string, client *http.Client) *githubProvider {
	t.Helper()
	p := newGitHubProvider(ProviderConfig{
		ID:           "gh",
		Type:         TypeGitHub,
		DisplayName:  "GitHub",
		BaseURL:      baseURL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}, "https://portreach.corp/auth/callback")
	p.httpClient = client
	return p
}

func TestGitHubProviderMetadata(t *testing.T) {
	p := newGitHubProvider(ProviderConfig{
		ID:          "gh",
		Type:        TypeGitHub,
		DisplayName: "GitHub",
		BaseURL:     defaultBaseURL[TypeGitHub],
	}, "https://portreach.corp/auth/callback")

	if p.ID() != "gh" {
		t.Errorf("ID = %q, want gh", p.ID())
	}
	if p.DisplayName() != "GitHub" {
		t.Errorf("DisplayName = %q, want GitHub", p.DisplayName())
	}
	if p.Type() != TypeGitHub {
		t.Errorf("Type = %q, want %q", p.Type(), TypeGitHub)
	}
	if p.apiBase != "https://api.github.com" {
		t.Errorf("apiBase = %q, want https://api.github.com", p.apiBase)
	}

	url := p.AuthCodeURL("xyz-state")
	if !strings.Contains(url, "state=xyz-state") {
		t.Errorf("AuthCodeURL %q missing state", url)
	}
	if !strings.Contains(url, "github.com/login/oauth/authorize") {
		t.Errorf("AuthCodeURL %q missing authorize endpoint", url)
	}
	if !strings.Contains(url, "read%3Aorg") {
		t.Errorf("AuthCodeURL %q missing read:org scope", url)
	}
}

func TestGitHubProviderEnterpriseAPIBase(t *testing.T) {
	p := newGitHubProvider(ProviderConfig{
		ID:      "ghe",
		Type:    TypeGitHub,
		BaseURL: "https://github.corp",
	}, "https://portreach.corp/auth/callback")

	if p.apiBase != "https://github.corp/api/v3" {
		t.Errorf("apiBase = %q, want https://github.corp/api/v3", p.apiBase)
	}
	if got := p.AuthCodeURL("s"); !strings.Contains(got, "github.corp/login/oauth/authorize") {
		t.Errorf("AuthCodeURL %q missing enterprise authorize endpoint", got)
	}
}

func TestGitHubExchangeMapsIdentity(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"tok123","token_type":"bearer"}`))
		case "/api/v3/user":
			if r.Header.Get("Authorization") != "Bearer tok123" {
				t.Errorf("user request missing bearer token, got %q", r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"login":"octocat","name":"The Octocat"}`))
		case "/api/v3/user/orgs":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"login":"myorg"},{"login":"otherorg"}]`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	p := newTestGitHub(t, ts.URL, ts.Client())

	id, err := p.Exchange(context.Background(), "the-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Login != "octocat" {
		t.Errorf("Login = %q, want octocat", id.Login)
	}
	if id.Name != "The Octocat" {
		t.Errorf("Name = %q, want The Octocat", id.Name)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "myorg" || id.Groups[1] != "otherorg" {
		t.Errorf("Groups = %v, want [myorg otherorg]", id.Groups)
	}
}

func TestGitHubExchangeTokenError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad code", http.StatusBadRequest)
	}))
	defer ts.Close()

	p := newTestGitHub(t, ts.URL, ts.Client())
	if _, err := p.Exchange(context.Background(), "bad"); err == nil {
		t.Fatal("expected token exchange error, got nil")
	}
}

func TestGitHubExchangeUserHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"tok123","token_type":"bearer"}`))
		case "/api/v3/user":
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	p := newTestGitHub(t, ts.URL, ts.Client())
	if _, err := p.Exchange(context.Background(), "code"); err == nil {
		t.Fatal("expected user fetch error, got nil")
	}
}

func TestGitHubExchangeEmptyLogin(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"tok123","token_type":"bearer"}`))
		case "/api/v3/user":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"login":"","name":""}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	p := newTestGitHub(t, ts.URL, ts.Client())
	if _, err := p.Exchange(context.Background(), "code"); err == nil {
		t.Fatal("expected empty-login error, got nil")
	}
}
