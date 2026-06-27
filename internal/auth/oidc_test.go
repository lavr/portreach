package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestOIDC spins up a hermetic OIDC issuer (discovery + JWKS + token endpoint)
// and returns a generic oidcProvider built from pc pointed at it. pc.Issuer is
// overwritten with the fake server URL. claims is called per token request with
// the issuer URL so tests can shape the id_token; standard claims (iss, aud, exp,
// iat) are filled in automatically when absent.
func newTestOIDC(t *testing.T, pc ProviderConfig, claims func(issuer string) map[string]any) (*oidcProvider, *httptest.Server) {
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

	pc.Issuer = srv.URL
	if pc.ID == "" {
		pc.ID = "oidc"
	}
	if pc.Type == "" {
		pc.Type = TypeOIDC
	}
	if pc.ClientID == "" {
		pc.ClientID = "client-id"
	}
	if pc.ClientSecret == "" {
		pc.ClientSecret = "client-secret"
	}
	p, err := newOIDCProvider(context.Background(), pc, "https://portreach.corp/auth/callback")
	if err != nil {
		t.Fatalf("newOIDCProvider: %v", err)
	}
	return p, srv
}

func TestOIDCProviderMetadataAndDefaults(t *testing.T) {
	p, _ := newTestOIDC(t, ProviderConfig{DisplayName: "Corporate SSO"},
		func(string) map[string]any { return map[string]any{} })

	if p.ID() != "oidc" {
		t.Errorf("ID = %q, want oidc", p.ID())
	}
	if p.DisplayName() != "Corporate SSO" {
		t.Errorf("DisplayName = %q, want Corporate SSO", p.DisplayName())
	}
	if p.Type() != TypeOIDC {
		t.Errorf("Type = %q, want %q", p.Type(), TypeOIDC)
	}
	if p.usernameClaim != defaultUsernameClaim {
		t.Errorf("usernameClaim = %q, want %q", p.usernameClaim, defaultUsernameClaim)
	}
	if p.groupsClaim != defaultGroupsClaim {
		t.Errorf("groupsClaim = %q, want %q", p.groupsClaim, defaultGroupsClaim)
	}

	url := p.AuthCodeURL("xyz-state", "the-nonce")
	for _, want := range []string{"state=xyz-state", "nonce=the-nonce", "authorize", "scope=openid"} {
		if !strings.Contains(url, want) {
			t.Errorf("AuthCodeURL %q missing %q", url, want)
		}
	}
}

func TestOIDCRequiresIssuer(t *testing.T) {
	if _, err := newOIDCProvider(context.Background(),
		ProviderConfig{ID: "x", Type: TypeOIDC, ClientID: "c"},
		"https://portreach.corp/auth/callback"); err == nil {
		t.Fatal("expected error for missing issuer, got nil")
	}
}

func TestOIDCExchangeMapsIdentity(t *testing.T) {
	p, _ := newTestOIDC(t, ProviderConfig{}, func(string) map[string]any {
		return map[string]any{
			"sub":                "42",
			"preferred_username": "alice",
			"name":               "Alice Example",
			"nonce":              "the-nonce",
			"groups":             []string{"infra", "sre"},
		}
	})

	id, err := p.Exchange(context.Background(), "the-code", "the-nonce")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Login != "alice" {
		t.Errorf("Login = %q, want alice", id.Login)
	}
	if id.Name != "Alice Example" {
		t.Errorf("Name = %q, want Alice Example", id.Name)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "infra" || id.Groups[1] != "sre" {
		t.Errorf("Groups = %v, want [infra sre]", id.Groups)
	}
}

func TestOIDCExchangeFallsBackToSub(t *testing.T) {
	p, _ := newTestOIDC(t, ProviderConfig{}, func(string) map[string]any {
		return map[string]any{
			"sub":   "user-99",
			"name":  "No Username",
			"nonce": "n1",
		}
	})

	id, err := p.Exchange(context.Background(), "code", "n1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Login != "user-99" {
		t.Errorf("Login = %q, want user-99 (sub fallback)", id.Login)
	}
}

func TestOIDCExchangeCustomClaims(t *testing.T) {
	p, _ := newTestOIDC(t,
		ProviderConfig{UsernameClaim: "email", GroupsClaim: "roles"},
		func(string) map[string]any {
			return map[string]any{
				"sub":   "42",
				"email": "bob@corp.com",
				"name":  "Bob",
				"nonce": "n1",
				"roles": []string{"admin", "ops"},
				// preferred_username present but must be ignored under custom claim
				"preferred_username": "ignored",
				"groups":             []string{"ignored-group"},
			}
		})

	if p.usernameClaim != "email" || p.groupsClaim != "roles" {
		t.Fatalf("custom claims not applied: username=%q groups=%q", p.usernameClaim, p.groupsClaim)
	}

	id, err := p.Exchange(context.Background(), "code", "n1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Login != "bob@corp.com" {
		t.Errorf("Login = %q, want bob@corp.com (email claim)", id.Login)
	}
	if len(id.Groups) != 2 || id.Groups[0] != "admin" || id.Groups[1] != "ops" {
		t.Errorf("Groups = %v, want [admin ops] (roles claim)", id.Groups)
	}
}

func TestOIDCExchangeStringGroupsClaim(t *testing.T) {
	// Some IdPs emit a single group as a bare string rather than an array.
	p, _ := newTestOIDC(t, ProviderConfig{}, func(string) map[string]any {
		return map[string]any{
			"sub":                "1",
			"preferred_username": "carol",
			"nonce":              "n1",
			"groups":             "solo-team",
		}
	})

	id, err := p.Exchange(context.Background(), "code", "n1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "solo-team" {
		t.Errorf("Groups = %v, want [solo-team]", id.Groups)
	}
}

func TestOIDCExchangeCustomScopes(t *testing.T) {
	p, _ := newTestOIDC(t, ProviderConfig{Scopes: []string{"openid", "email", "custom"}},
		func(string) map[string]any { return map[string]any{} })

	url := p.AuthCodeURL("s", "n")
	if !strings.Contains(url, "custom") {
		t.Errorf("AuthCodeURL %q missing custom scope", url)
	}
}

func TestOIDCExchangeNonceMismatch(t *testing.T) {
	p, _ := newTestOIDC(t, ProviderConfig{}, func(string) map[string]any {
		return map[string]any{
			"sub":                "42",
			"preferred_username": "alice",
			"nonce":              "server-nonce",
		}
	})

	if _, err := p.Exchange(context.Background(), "code", "expected-nonce"); err == nil {
		t.Fatal("expected nonce mismatch error, got nil")
	} else if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("error = %v, want nonce mismatch", err)
	}
}

func TestOIDCExchangeEmptyLogin(t *testing.T) {
	p, _ := newTestOIDC(t, ProviderConfig{}, func(string) map[string]any {
		return map[string]any{
			"name":  "Nameless",
			"nonce": "n1",
		}
	})

	if _, err := p.Exchange(context.Background(), "code", "n1"); err == nil {
		t.Fatal("expected empty-login error, got nil")
	}
}

func TestOIDCHostedDomainMatchMapsEmail(t *testing.T) {
	// Google-style provider: email is the login and a matching hd claim is
	// accepted.
	p, _ := newTestOIDC(t,
		ProviderConfig{Type: TypeGoogle, UsernameClaim: "email", HostedDomain: "corp.com"},
		func(string) map[string]any {
			return map[string]any{
				"sub":   "g-1",
				"email": "alice@corp.com",
				"name":  "Alice",
				"nonce": "n1",
				"hd":    "corp.com",
			}
		})

	id, err := p.Exchange(context.Background(), "code", "n1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if id.Login != "alice@corp.com" {
		t.Errorf("Login = %q, want alice@corp.com (email claim)", id.Login)
	}
}

func TestOIDCHostedDomainMismatchRejected(t *testing.T) {
	p, _ := newTestOIDC(t,
		ProviderConfig{Type: TypeGoogle, UsernameClaim: "email", HostedDomain: "corp.com"},
		func(string) map[string]any {
			return map[string]any{
				"sub":   "g-2",
				"email": "mallory@evil.com",
				"nonce": "n1",
				"hd":    "evil.com",
			}
		})

	_, err := p.Exchange(context.Background(), "code", "n1")
	if err == nil {
		t.Fatal("expected hosted-domain mismatch error, got nil")
	}
	if !errors.Is(err, errHostedDomainMismatch) {
		t.Errorf("error = %v, want errHostedDomainMismatch", err)
	}
}

func TestOIDCHostedDomainMissingClaimRejected(t *testing.T) {
	// A consumer (non-Workspace) Google account omits hd entirely; with a hd
	// restriction configured this must be rejected.
	p, _ := newTestOIDC(t,
		ProviderConfig{Type: TypeGoogle, UsernameClaim: "email", HostedDomain: "corp.com"},
		func(string) map[string]any {
			return map[string]any{
				"sub":   "g-3",
				"email": "someone@gmail.com",
				"nonce": "n1",
			}
		})

	if _, err := p.Exchange(context.Background(), "code", "n1"); !errors.Is(err, errHostedDomainMismatch) {
		t.Fatalf("error = %v, want errHostedDomainMismatch for missing hd", err)
	}
}

func TestOIDCHostedDomainAuthParam(t *testing.T) {
	p, _ := newTestOIDC(t,
		ProviderConfig{Type: TypeGoogle, HostedDomain: "corp.com"},
		func(string) map[string]any { return map[string]any{} })

	if got := p.AuthCodeURL("s", "n"); !strings.Contains(got, "hd=corp.com") {
		t.Errorf("AuthCodeURL %q missing hd=corp.com param", got)
	}

	// Without a hosted domain the hd param must be absent.
	p2, _ := newTestOIDC(t, ProviderConfig{}, func(string) map[string]any { return map[string]any{} })
	if got := p2.AuthCodeURL("s", "n"); strings.Contains(got, "hd=") {
		t.Errorf("AuthCodeURL %q should not contain hd param without HostedDomain", got)
	}
}

func TestOIDCExchangeWrongAudienceRejected(t *testing.T) {
	p, _ := newTestOIDC(t, ProviderConfig{}, func(string) map[string]any {
		return map[string]any{
			"sub":                "42",
			"preferred_username": "alice",
			"nonce":              "n1",
			"aud":                "some-other-client",
		}
	})

	if _, err := p.Exchange(context.Background(), "code", "n1"); err == nil {
		t.Fatal("expected audience verification error, got nil")
	}
}
