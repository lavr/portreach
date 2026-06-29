package auth

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig writes content to a temp file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func validKeyHex() string {
	return hex.EncodeToString(make([]byte, cookieKeyLen))
}

func TestLoadConfigMultiProvider(t *testing.T) {
	t.Setenv("GITLAB_SECRET", "gl-secret")
	t.Setenv("GITHUB_SECRET", "gh-secret")
	t.Setenv("GITLAB_GROUP_MATCH", "subtree")
	t.Setenv("COOKIE_KEY", validKeyHex())

	path := writeConfig(t, `
auth:
  redirectURL: https://portreach.corp/auth/callback
  cookieKey: ${COOKIE_KEY}
  allowedUsers: [alice]
  providers:
    - id: corp-gitlab
      type: gitlab
      displayName: "Corporate GitLab"
      baseURL: https://gitlab.corp
      clientID: abc
      clientSecret: ${GITLAB_SECRET}
      allowedGroups: [infra, sre]
      groupMatch: ${GITLAB_GROUP_MATCH}
    - id: github
      type: github
      clientID: def
      clientSecret: ${GITHUB_SECRET}
      allowedOrgs: [myorg]
`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.Enabled() {
		t.Fatal("expected enabled config")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(cfg.Providers) != 2 {
		t.Fatalf("want 2 providers, got %d", len(cfg.Providers))
	}
	gl := cfg.Providers[0]
	if gl.ClientSecret != "gl-secret" {
		t.Errorf("gitlab secret not interpolated: %q", gl.ClientSecret)
	}
	if gl.BaseURL != "https://gitlab.corp" {
		t.Errorf("gitlab baseURL: %q", gl.BaseURL)
	}
	if gl.GroupMatch != GroupMatchSubtree {
		t.Errorf("gitlab groupMatch: %q", gl.GroupMatch)
	}
	gh := cfg.Providers[1]
	if gh.ClientSecret != "gh-secret" {
		t.Errorf("github secret not interpolated: %q", gh.ClientSecret)
	}
	// Defaults applied for github (no baseURL/displayName given).
	if gh.BaseURL != "https://github.com" {
		t.Errorf("github default baseURL: %q", gh.BaseURL)
	}
	if gh.DisplayName != "GitHub" {
		t.Errorf("github default displayName: %q", gh.DisplayName)
	}
	if len(cfg.CookieKey) != cookieKeyLen {
		t.Errorf("cookieKey len = %d", len(cfg.CookieKey))
	}
	if len(cfg.AllowedUsers) != 1 || cfg.AllowedUsers[0] != "alice" {
		t.Errorf("allowedUsers = %v", cfg.AllowedUsers)
	}
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("FOO", "bar")
	if got := expandEnv("x-${FOO}-y"); got != "x-bar-y" {
		t.Errorf("expandEnv = %q", got)
	}
	if got := expandEnv("${MISSING_VAR_XYZ}"); got != "" {
		t.Errorf("missing env should expand to empty, got %q", got)
	}
	if got := expandEnv("no refs"); got != "no refs" {
		t.Errorf("expandEnv = %q", got)
	}
}

func TestDecodeCookieKey(t *testing.T) {
	raw := make([]byte, cookieKeyLen)
	for i := range raw {
		raw[i] = byte(i)
	}
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"hex", hex.EncodeToString(raw), true},
		{"base64-std", base64.StdEncoding.EncodeToString(raw), true},
		{"base64-url", base64.URLEncoding.EncodeToString(raw), true},
		{"base64-rawstd", base64.RawStdEncoding.EncodeToString(raw), true},
		{"too-short", hex.EncodeToString(raw[:16]), false},
		{"garbage", "not-a-key!!!", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := decodeCookieKey(c.in)
			if c.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(key) != cookieKeyLen {
					t.Fatalf("key len = %d", len(key))
				}
			} else if err == nil {
				t.Fatalf("expected error for %q", c.in)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	base := func() *Config {
		return &Config{
			RedirectURL: "https://x/cb",
			CookieKey:   make([]byte, cookieKeyLen),
			Providers: []ProviderConfig{
				{ID: "gh", Type: TypeGitHub, ClientID: "a", ClientSecret: "b"},
			},
		}
	}

	t.Run("valid", func(t *testing.T) {
		if err := base().Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	t.Run("disabled-empty-is-valid", func(t *testing.T) {
		c := &Config{}
		if c.Enabled() {
			t.Fatal("empty config should be disabled")
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("disabled config should validate: %v", err)
		}
	})

	t.Run("dup-id", func(t *testing.T) {
		c := base()
		c.Providers = append(c.Providers, ProviderConfig{ID: "gh", Type: TypeGitLab, ClientID: "a", ClientSecret: "b"})
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("want duplicate error, got %v", err)
		}
	})

	t.Run("unknown-type", func(t *testing.T) {
		c := base()
		c.Providers[0].Type = "bitbucket"
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "unknown type") {
			t.Fatalf("want unknown type error, got %v", err)
		}
	})

	t.Run("missing-clientID", func(t *testing.T) {
		c := base()
		c.Providers[0].ClientID = ""
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "clientID") {
			t.Fatalf("want clientID error, got %v", err)
		}
	})

	t.Run("missing-clientSecret", func(t *testing.T) {
		c := base()
		c.Providers[0].ClientSecret = ""
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "clientSecret") {
			t.Fatalf("want clientSecret error, got %v", err)
		}
	})

	t.Run("unknown-groupMatch", func(t *testing.T) {
		c := base()
		c.Providers[0].GroupMatch = "prefix"
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "groupMatch") || !strings.Contains(err.Error(), "gh") {
			t.Fatalf("want groupMatch error naming provider, got %v", err)
		}
	})

	t.Run("groupMatch-subtree-valid", func(t *testing.T) {
		c := base()
		c.Providers[0].GroupMatch = GroupMatchSubtree
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	t.Run("empty-redirectURL-valid", func(t *testing.T) {
		// An empty redirectURL is the host-derived callback mode, not an error.
		c := base()
		c.RedirectURL = ""
		if err := c.Validate(); err != nil {
			t.Fatalf("empty redirectURL (host-derived mode) should validate: %v", err)
		}
	})

	t.Run("bad-cookieKey", func(t *testing.T) {
		c := base()
		c.CookieKey = make([]byte, 16)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "cookieKey") {
			t.Fatalf("want cookieKey error, got %v", err)
		}
	})

	t.Run("empty-id", func(t *testing.T) {
		c := base()
		c.Providers[0].ID = ""
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "id") {
			t.Fatalf("want id error, got %v", err)
		}
	})

	t.Run("oidc-valid", func(t *testing.T) {
		c := base()
		c.Providers[0] = ProviderConfig{ID: "corp", Type: TypeOIDC, Issuer: "https://idp.corp/realm", ClientID: "a", ClientSecret: "b"}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	t.Run("oidc-missing-issuer", func(t *testing.T) {
		c := base()
		c.Providers[0] = ProviderConfig{ID: "corp", Type: TypeOIDC, ClientID: "a", ClientSecret: "b"}
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "issuer") || !strings.Contains(err.Error(), "corp") {
			t.Fatalf("want issuer error naming provider, got %v", err)
		}
	})

	t.Run("preset-baseURL-required", func(t *testing.T) {
		for _, typ := range []string{TypeOkta, TypeKeycloak, TypeEntra} {
			c := base()
			c.Providers[0] = ProviderConfig{ID: "p-" + typ, Type: typ, ClientID: "a", ClientSecret: "b"}
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), "baseURL") || !strings.Contains(err.Error(), "p-"+typ) {
				t.Fatalf("%s: want baseURL error naming provider, got %v", typ, err)
			}
		}
	})

	t.Run("preset-with-baseURL-valid", func(t *testing.T) {
		for _, typ := range []string{TypeOkta, TypeKeycloak, TypeEntra} {
			c := base()
			c.Providers[0] = ProviderConfig{ID: "p-" + typ, Type: typ, BaseURL: "https://idp.corp", ClientID: "a", ClientSecret: "b"}
			if err := c.Validate(); err != nil {
				t.Fatalf("%s: Validate: %v", typ, err)
			}
		}
	})

	t.Run("gitlab-no-baseURL-valid", func(t *testing.T) {
		c := base()
		c.Providers[0] = ProviderConfig{ID: "gl", Type: TypeGitLab, ClientID: "a", ClientSecret: "b"}
		if err := c.Validate(); err != nil {
			t.Fatalf("gitlab without baseURL should validate: %v", err)
		}
	})

	t.Run("google-without-hd-valid", func(t *testing.T) {
		c := base()
		c.Providers[0] = ProviderConfig{ID: "g", Type: TypeGoogle, ClientID: "a", ClientSecret: "b"}
		if err := c.Validate(); err != nil {
			t.Fatalf("google without hd should validate: %v", err)
		}
	})

	t.Run("google-with-hd-valid", func(t *testing.T) {
		c := base()
		c.Providers[0] = ProviderConfig{ID: "g", Type: TypeGoogle, HostedDomain: "corp.com", ClientID: "a", ClientSecret: "b"}
		if err := c.Validate(); err != nil {
			t.Fatalf("google with hd should validate: %v", err)
		}
	})

	t.Run("api-only-valid-no-cookie-no-providers", func(t *testing.T) {
		// Bearer-only mode: no providers, no cookieKey required.
		c := &Config{API: []APIEntry{{ID: "ci", Issuer: "https://idp/realm", Audience: "portreach"}}}
		if !c.Enabled() {
			t.Fatal("api entry should enable the config")
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("bearer-only config should validate: %v", err)
		}
	})

	t.Run("api-missing-issuer", func(t *testing.T) {
		c := &Config{API: []APIEntry{{ID: "ci", Audience: "portreach"}}}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "issuer") || !strings.Contains(err.Error(), "ci") {
			t.Fatalf("want issuer error naming entry, got %v", err)
		}
	})

	t.Run("api-missing-audience", func(t *testing.T) {
		c := &Config{API: []APIEntry{{ID: "ci", Issuer: "https://idp/realm"}}}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "audience") || !strings.Contains(err.Error(), "ci") {
			t.Fatalf("want audience error naming entry, got %v", err)
		}
	})

	t.Run("api-empty-id", func(t *testing.T) {
		c := &Config{API: []APIEntry{{Issuer: "https://idp/realm", Audience: "portreach"}}}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "id") {
			t.Fatalf("want id error, got %v", err)
		}
	})

	t.Run("api-dup-pair", func(t *testing.T) {
		c := &Config{API: []APIEntry{
			{ID: "a", Issuer: "https://idp/realm", Audience: "portreach"},
			{ID: "b", Issuer: "https://idp/realm", Audience: "portreach"},
		}}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "issuer, audience") {
			t.Fatalf("want duplicate (issuer, audience) error, got %v", err)
		}
	})

	t.Run("api-dup-pair-distinct-audience-ok", func(t *testing.T) {
		c := &Config{API: []APIEntry{
			{ID: "a", Issuer: "https://idp/realm", Audience: "portreach"},
			{ID: "b", Issuer: "https://idp/realm", Audience: "portreach-ci"},
		}}
		if err := c.Validate(); err != nil {
			t.Fatalf("distinct audiences on one issuer should validate: %v", err)
		}
	})

	t.Run("api-unknown-groupMatch", func(t *testing.T) {
		c := &Config{API: []APIEntry{{ID: "ci", Issuer: "https://idp/realm", Audience: "portreach", GroupMatch: "prefix"}}}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "groupMatch") {
			t.Fatalf("want groupMatch error, got %v", err)
		}
	})

	t.Run("api-id-collides-with-provider", func(t *testing.T) {
		// id must be globally unique across providers and API entries.
		c := base()
		c.API = []APIEntry{{ID: "gh", Issuer: "https://idp/realm", Audience: "portreach"}}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("want duplicate id error across provider+api, got %v", err)
		}
	})

	t.Run("browser-plus-api-valid", func(t *testing.T) {
		c := base()
		c.API = []APIEntry{{ID: "ci", Issuer: "https://idp/realm", Audience: "portreach"}}
		if err := c.Validate(); err != nil {
			t.Fatalf("browser+api config should validate: %v", err)
		}
	})
}

func TestLoadConfigAPIEntries(t *testing.T) {
	t.Setenv("API_ISSUER", "https://idp.corp/realm")
	t.Setenv("API_AUD", "portreach")
	t.Setenv("API_GROUP", "platform")

	path := writeConfig(t, `
auth:
  api:
    - id: ci
      type: gitlab
      issuer: ${API_ISSUER}
      audience: ${API_AUD}
      allowedGroups:
        - ${API_GROUP}
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.Enabled() {
		t.Fatal("api-only config should be enabled")
	}
	if cfg.browserEnabled() {
		t.Fatal("api-only config must not report browser enabled")
	}
	if len(cfg.API) != 1 {
		t.Fatalf("want 1 api entry, got %d", len(cfg.API))
	}
	e := cfg.API[0]
	if e.Issuer != "https://idp.corp/realm" || e.Audience != "portreach" {
		t.Errorf("env not expanded: issuer=%q audience=%q", e.Issuer, e.Audience)
	}
	if len(e.AllowedGroups) != 1 || e.AllowedGroups[0] != "platform" {
		t.Errorf("allowedGroups not expanded: %v", e.AllowedGroups)
	}
	if e.GroupMatch != GroupMatchExact {
		t.Errorf("groupMatch default = %q, want exact", e.GroupMatch)
	}
}

func TestLoadConfigBadCookieKey(t *testing.T) {
	path := writeConfig(t, `
auth:
  redirectURL: https://x/cb
  cookieKey: deadbeef
  providers:
    - id: gh
      type: github
      clientID: a
      clientSecret: b
`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for short cookieKey")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
