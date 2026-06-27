package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// newTestPreset spins up a hermetic OIDC issuer (discovery + JWKS + token
// endpoint) and builds a provider from pc through the preset code path
// (applyPreset + newPresetProvider). pc.BaseURL is pointed at the fake server so
// preset issuer derivation resolves to it.
func newTestPreset(t *testing.T, pc ProviderConfig, claims func(issuer string) map[string]any) (*oidcProvider, *httptest.Server) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/jwks")
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, jwksJSON(key))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		c := claims(srv.URL)
		if _, ok := c["iss"]; !ok {
			c["iss"] = srv.URL
		}
		if _, ok := c["aud"]; !ok {
			c["aud"] = "client-id"
		}
		if _, ok := c["exp"]; !ok {
			c["exp"] = time.Now().Add(time.Hour).Unix()
		}
		if _, ok := c["iat"]; !ok {
			c["iat"] = time.Now().Unix()
		}
		idToken := signJWT(t, key, c)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"at","token_type":"bearer","id_token":%q}`, idToken)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	pc.BaseURL = srv.URL
	if pc.ID == "" {
		pc.ID = "p"
	}
	if pc.ClientID == "" {
		pc.ClientID = "client-id"
	}
	if pc.ClientSecret == "" {
		pc.ClientSecret = "client-secret"
	}
	p, err := newPresetProvider(context.Background(), pc, "https://portreach.corp/auth/callback")
	if err != nil {
		t.Fatalf("newPresetProvider: %v", err)
	}
	return p, srv
}

func TestApplyPresetDefaults(t *testing.T) {
	cases := []struct {
		typ           string
		baseURL       string
		wantIssuer    string
		wantUsername  string
		wantGroups    string
		wantDisplay   string
	}{
		{TypeGitLab, "", "https://gitlab.com", "preferred_username", "groups", "GitLab"},
		{TypeGitLab, "https://gitlab.corp", "https://gitlab.corp", "preferred_username", "groups", "GitLab"},
		{TypeOkta, "https://corp.okta.com", "https://corp.okta.com", "preferred_username", "groups", "Okta"},
		{TypeKeycloak, "https://kc.corp/realms/main", "https://kc.corp/realms/main", "preferred_username", "groups", "Keycloak"},
		{TypeEntra, "tenant-123", "https://login.microsoftonline.com/tenant-123/v2.0", "preferred_username", "groups", "Microsoft"},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			got := applyPreset(ProviderConfig{Type: c.typ, BaseURL: c.baseURL})
			if got.Issuer != c.wantIssuer {
				t.Errorf("Issuer = %q, want %q", got.Issuer, c.wantIssuer)
			}
			if got.UsernameClaim != c.wantUsername {
				t.Errorf("UsernameClaim = %q, want %q", got.UsernameClaim, c.wantUsername)
			}
			if got.GroupsClaim != c.wantGroups {
				t.Errorf("GroupsClaim = %q, want %q", got.GroupsClaim, c.wantGroups)
			}
			if got.DisplayName != c.wantDisplay {
				t.Errorf("DisplayName = %q, want %q", got.DisplayName, c.wantDisplay)
			}
			if !reflect.DeepEqual(got.Scopes, oidcScopes) {
				t.Errorf("Scopes = %v, want %v", got.Scopes, oidcScopes)
			}
		})
	}
}

func TestApplyPresetExplicitOverrides(t *testing.T) {
	in := ProviderConfig{
		Type:          TypeOkta,
		BaseURL:       "https://corp.okta.com",
		Issuer:        "https://explicit.issuer",
		Scopes:        []string{"openid", "custom"},
		UsernameClaim: "email",
		GroupsClaim:   "roles",
		DisplayName:   "Custom Name",
	}
	got := applyPreset(in)
	if got.Issuer != "https://explicit.issuer" {
		t.Errorf("Issuer = %q, want explicit issuer (not derived)", got.Issuer)
	}
	if !reflect.DeepEqual(got.Scopes, []string{"openid", "custom"}) {
		t.Errorf("Scopes = %v, want explicit", got.Scopes)
	}
	if got.UsernameClaim != "email" {
		t.Errorf("UsernameClaim = %q, want email", got.UsernameClaim)
	}
	if got.GroupsClaim != "roles" {
		t.Errorf("GroupsClaim = %q, want roles", got.GroupsClaim)
	}
	if got.DisplayName != "Custom Name" {
		t.Errorf("DisplayName = %q, want Custom Name", got.DisplayName)
	}
}

func TestApplyPresetNonPresetUnchanged(t *testing.T) {
	in := ProviderConfig{Type: TypeOIDC, Issuer: "https://issuer"}
	got := applyPreset(in)
	if !reflect.DeepEqual(got, in) {
		t.Errorf("oidc config changed by applyPreset: %+v", got)
	}
}

func TestEntraIssuerFromTenant(t *testing.T) {
	if got := entraIssuer(ProviderConfig{BaseURL: "abc-tenant"}); got != "https://login.microsoftonline.com/abc-tenant/v2.0" {
		t.Errorf("tenant issuer = %q", got)
	}
	full := "https://login.microsoftonline.com/abc/v2.0"
	if got := entraIssuer(ProviderConfig{BaseURL: full}); got != full {
		t.Errorf("full-URL issuer = %q, want passthrough", got)
	}
	if got := entraIssuer(ProviderConfig{}); got != "" {
		t.Errorf("empty tenant issuer = %q, want empty", got)
	}
}

func TestGitLabPresetExchange(t *testing.T) {
	p, _ := newTestPreset(t, ProviderConfig{Type: TypeGitLab}, func(string) map[string]any {
		return map[string]any{
			"sub":                "42",
			"preferred_username": "alice",
			"name":               "Alice Example",
			"nonce":              "n1",
			"groups":             []string{"infra", "sre"},
		}
	})

	if p.Type() != TypeGitLab {
		t.Errorf("Type = %q, want %q", p.Type(), TypeGitLab)
	}
	if p.DisplayName() != "GitLab" {
		t.Errorf("DisplayName = %q, want GitLab", p.DisplayName())
	}
	id, err := p.Exchange(context.Background(), "code", "n1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Login != "alice" {
		t.Errorf("Login = %q, want alice", id.Login)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "infra" || id.Groups[1] != "sre" {
		t.Errorf("Groups = %v, want [infra sre]", id.Groups)
	}
}

func TestGitLabPresetGroupsDirectFallback(t *testing.T) {
	p, _ := newTestPreset(t, ProviderConfig{Type: TypeGitLab}, func(string) map[string]any {
		return map[string]any{
			"sub":           "user-99",
			"name":          "No Username",
			"nonce":         "n1",
			"groups_direct": []string{"team-a"},
		}
	})

	id, err := p.Exchange(context.Background(), "code", "n1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Login != "user-99" {
		t.Errorf("Login = %q, want user-99 (sub fallback)", id.Login)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "team-a" {
		t.Errorf("Groups = %v, want [team-a] (groups_direct fallback)", id.Groups)
	}
}

func TestGitLabPresetGroupsOverrideDisablesFallback(t *testing.T) {
	// An explicit groupsClaim must take over completely: the gitlab groups_direct
	// fallback should not silently fill in.
	p, _ := newTestPreset(t, ProviderConfig{Type: TypeGitLab, GroupsClaim: "roles"}, func(string) map[string]any {
		return map[string]any{
			"sub":           "1",
			"nonce":         "n1",
			"groups_direct": []string{"team-a"},
		}
	})
	if p.groupsFallback != "" {
		t.Errorf("groupsFallback = %q, want empty when groupsClaim overridden", p.groupsFallback)
	}
	id, err := p.Exchange(context.Background(), "code", "n1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(id.Groups) != 0 {
		t.Errorf("Groups = %v, want empty (no fallback)", id.Groups)
	}
}

func TestOktaKeycloakPresetExchange(t *testing.T) {
	for _, typ := range []string{TypeOkta, TypeKeycloak} {
		t.Run(typ, func(t *testing.T) {
			p, _ := newTestPreset(t, ProviderConfig{Type: typ}, func(string) map[string]any {
				return map[string]any{
					"sub":                "7",
					"preferred_username": "bob",
					"nonce":              "n1",
					"groups":             []string{"ops"},
				}
			})
			if p.Type() != typ {
				t.Errorf("Type = %q, want %q", p.Type(), typ)
			}
			id, err := p.Exchange(context.Background(), "code", "n1")
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if id.Login != "bob" {
				t.Errorf("Login = %q, want bob", id.Login)
			}
			if len(id.Groups) != 1 || id.Groups[0] != "ops" {
				t.Errorf("Groups = %v, want [ops]", id.Groups)
			}
		})
	}
}

func TestEntraPresetExchange(t *testing.T) {
	// Entra issuer passes through a full BaseURL unchanged, so the hermetic fake
	// issuer is reachable. Group claims arrive as object IDs.
	p, _ := newTestPreset(t, ProviderConfig{Type: TypeEntra}, func(string) map[string]any {
		return map[string]any{
			"sub":                "oid-1",
			"preferred_username": "carol@corp.com",
			"nonce":              "n1",
			"groups":             []string{"00000000-0000-0000-0000-000000000001"},
		}
	})
	if p.Type() != TypeEntra {
		t.Errorf("Type = %q, want %q", p.Type(), TypeEntra)
	}
	id, err := p.Exchange(context.Background(), "code", "n1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Login != "carol@corp.com" {
		t.Errorf("Login = %q, want carol@corp.com", id.Login)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("Groups = %v, want [object-id]", id.Groups)
	}
}
