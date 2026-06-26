package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signJWT builds a compact RS256 JWT from the given claims, signed with key and
// tagged with kid "test-key" to match the JWKS served by the fake issuer.
func signJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "test-key"})
	payload, _ := json.Marshal(claims)
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signingInput + "." + enc.EncodeToString(sig)
}

// jwksJSON renders a single-key JWKS document exposing key's RSA public part.
func jwksJSON(key *rsa.PrivateKey) string {
	enc := base64.RawURLEncoding
	n := enc.EncodeToString(key.N.Bytes())
	e := enc.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"test-key","n":%q,"e":%q}]}`, n, e)
}

// newTestGitLab spins up a hermetic OIDC issuer (discovery + JWKS + token
// endpoint) and returns a gitlabProvider pointed at it. claims is called per
// token request with the issuer URL so tests can shape the id_token; standard
// claims (iss, aud, exp, iat) are filled in automatically when absent.
func newTestGitLab(t *testing.T, claims func(issuer string) map[string]any) (*gitlabProvider, *httptest.Server) {
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
			srv.URL, srv.URL+"/oauth/authorize", srv.URL+"/oauth/token", srv.URL+"/oauth/jwks")
	})
	mux.HandleFunc("/oauth/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, jwksJSON(key))
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
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

	p, err := newGitLabProvider(context.Background(), ProviderConfig{
		ID:           "gl",
		Type:         TypeGitLab,
		DisplayName:  "Corporate GitLab",
		BaseURL:      srv.URL,
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}, "https://portreach.corp/auth/callback")
	if err != nil {
		t.Fatalf("newGitLabProvider: %v", err)
	}
	return p, srv
}

func TestGitLabProviderMetadata(t *testing.T) {
	p, _ := newTestGitLab(t, func(string) map[string]any { return map[string]any{} })

	if p.ID() != "gl" {
		t.Errorf("ID = %q, want gl", p.ID())
	}
	if p.DisplayName() != "Corporate GitLab" {
		t.Errorf("DisplayName = %q, want Corporate GitLab", p.DisplayName())
	}
	if p.Type() != TypeGitLab {
		t.Errorf("Type = %q, want %q", p.Type(), TypeGitLab)
	}

	url := p.AuthCodeURL("xyz-state", "the-nonce")
	if !strings.Contains(url, "state=xyz-state") {
		t.Errorf("AuthCodeURL %q missing state", url)
	}
	if !strings.Contains(url, "nonce=the-nonce") {
		t.Errorf("AuthCodeURL %q missing nonce", url)
	}
	if !strings.Contains(url, "oauth/authorize") {
		t.Errorf("AuthCodeURL %q missing authorize endpoint", url)
	}
	if !strings.Contains(url, "scope=openid") {
		t.Errorf("AuthCodeURL %q missing openid scope", url)
	}
}

func TestGitLabExchangeMapsIdentity(t *testing.T) {
	p, _ := newTestGitLab(t, func(string) map[string]any {
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

func TestGitLabExchangeFallsBackToSubAndGroupsDirect(t *testing.T) {
	p, _ := newTestGitLab(t, func(string) map[string]any {
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

func TestGitLabExchangeNonceMismatch(t *testing.T) {
	p, _ := newTestGitLab(t, func(string) map[string]any {
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

func TestGitLabExchangeEmptyLogin(t *testing.T) {
	p, _ := newTestGitLab(t, func(string) map[string]any {
		return map[string]any{
			"name":  "Nameless",
			"nonce": "n1",
		}
	})

	if _, err := p.Exchange(context.Background(), "code", "n1"); err == nil {
		t.Fatal("expected empty-login error, got nil")
	}
}

func TestGitLabExchangeWrongAudienceRejected(t *testing.T) {
	p, _ := newTestGitLab(t, func(string) map[string]any {
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
