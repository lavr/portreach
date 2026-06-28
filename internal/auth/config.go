// Package auth implements optional multi-provider SSO authentication for the
// portreach UI server. It is disabled by default: with no providers configured
// the gating middleware is a pass-through and existing deployments are
// unaffected.
package auth

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Provider type identifiers. github is special (OAuth2 + REST); oidc is the
// generic OpenID Connect provider; the remaining values are named presets that
// expand into an oidc provider with per-vendor defaults (see presets.go).
const (
	TypeGitHub   = "github"
	TypeGitLab   = "gitlab"
	TypeOIDC     = "oidc"
	TypeGoogle   = "google"
	TypeEntra    = "entra"
	TypeOkta     = "okta"
	TypeKeycloak = "keycloak"
)

// Default OIDC claim names used when a provider does not override them.
const (
	defaultUsernameClaim = "preferred_username"
	defaultGroupsClaim   = "groups"
)

// cookieKeyLen is the required AES-256 key length in bytes.
const cookieKeyLen = 32

// Default forwarded-header names used to derive the OAuth callback in
// host-derived mode (auth.redirectURL empty). They are configurable so
// non-standard proxies (e.g. a cluster-specific header) work without code
// changes.
const (
	defaultForwardedHostHeader  = "X-Forwarded-Host"
	defaultForwardedProtoHeader = "X-Forwarded-Proto"
)

// Accepted values for Config.CookieSecure. Empty is treated as auto.
const (
	cookieSecureAuto   = "auto"
	cookieSecureAlways = "always"
	cookieSecureNever  = "never"
)

// Group allowlist matching modes.
const (
	GroupMatchExact   = "exact"
	GroupMatchSubtree = "subtree"
)

// Default base URL and display name for github, the one non-OIDC provider.
// OIDC presets (including gitlab) own their issuer/display-name defaults in the
// preset table (see presets.go), so they are deliberately absent here.
var (
	defaultBaseURL = map[string]string{
		TypeGitHub: "https://github.com",
	}
	defaultDisplayName = map[string]string{
		TypeGitHub: "GitHub",
	}
)

// ProviderConfig describes a single SSO provider.
//
// The OIDC fields (Issuer, Scopes, UsernameClaim, GroupsClaim, HostedDomain)
// apply to the generic `oidc` type and to the named presets that expand into it.
// They are all optional: presets supply sensible defaults and any explicit value
// here overrides the preset default.
type ProviderConfig struct {
	ID            string   `yaml:"id"`
	Type          string   `yaml:"type"`
	DisplayName   string   `yaml:"displayName"`
	BaseURL       string   `yaml:"baseURL"`
	ClientID      string   `yaml:"clientID"`
	ClientSecret  string   `yaml:"clientSecret"`
	AllowedOrgs   []string `yaml:"allowedOrgs"`
	AllowedGroups []string `yaml:"allowedGroups"`
	GroupMatch    string   `yaml:"groupMatch"` // exact (default) or subtree

	// OIDC-specific fields (generic `oidc` type and presets).
	Issuer        string   `yaml:"issuer"`        // OIDC issuer URL (discovery base)
	Scopes        []string `yaml:"scopes"`        // OAuth2 scopes; default openid profile email
	UsernameClaim string   `yaml:"usernameClaim"` // id_token claim → Identity.Login (default preferred_username, then sub)
	GroupsClaim   string   `yaml:"groupsClaim"`   // id_token claim → Identity.Groups (default groups)
	HostedDomain  string   `yaml:"hostedDomain"`  // Google Workspace `hd` restriction (optional)
}

// Config is the top-level auth configuration. CookieKey is the decoded 32-byte
// AES-256 key; the YAML carries it as a hex/base64 string in CookieKeyRaw.
type Config struct {
	// RedirectURL is the OAuth callback URL. When set it is used verbatim for
	// every request (fixed mode, one hostname). When empty the callback is
	// derived per request from the incoming host (host-derived mode), letting
	// one deployment authenticate across many ingress hostnames.
	RedirectURL  string           `yaml:"redirectURL"`
	CookieKeyRaw string           `yaml:"cookieKey"`
	AllowedUsers []string         `yaml:"allowedUsers"`
	Providers    []ProviderConfig `yaml:"providers"`

	// Host-derived callback mode (only consulted when RedirectURL is empty).
	// ForwardedHostHeader / ForwardedProtoHeader name the request headers the
	// trusted proxy sets (default X-Forwarded-Host / X-Forwarded-Proto).
	// AllowedRedirectHosts, when non-empty, restricts the derived host to a
	// known set as defence-in-depth (empty = rely on the IdP's registered-callback
	// enforcement).
	ForwardedHostHeader  string   `yaml:"forwardedHostHeader"`
	ForwardedProtoHeader string   `yaml:"forwardedProtoHeader"`
	AllowedRedirectHosts []string `yaml:"allowedRedirectHosts"`

	// CookieSecure controls the Secure attribute on the auth cookies:
	//   auto (default) — Secure iff the request scheme is https (so login works
	//                    over both http and https, secure whenever it can be);
	//   always         — Secure unconditionally (require https);
	//   never          — never Secure (deliberate http-only).
	// Empty is treated as auto. The scheme is detected exactly like the
	// host-derived callback, so the cookie's Secure flag and the redirect_uri
	// scheme always agree.
	CookieSecure string `yaml:"cookieSecure"`

	// CookieKey is the decoded key, populated by LoadConfig.
	CookieKey []byte `yaml:"-"`
}

// configFile is the on-disk wrapper: the auth block lives under an `auth:` key.
type configFile struct {
	Auth Config `yaml:"auth"`
}

// envRef matches ${NAME} references for environment-variable interpolation.
var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces every ${NAME} in s with os.Getenv(NAME) (empty if unset).
func expandEnv(s string) string {
	return envRef.ReplaceAllStringFunc(s, func(m string) string {
		name := m[2 : len(m)-1]
		return os.Getenv(name)
	})
}

// LoadConfig reads and parses the auth config at path, expands ${ENV}
// references in string fields, decodes the cookie key and applies per-type
// defaults. It does not call Validate — callers decide when to enforce.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read auth config: %w", err)
	}

	var cf configFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("parse auth config: %w", err)
	}
	cfg := cf.Auth

	cfg.RedirectURL = expandEnv(cfg.RedirectURL)
	cfg.CookieKeyRaw = expandEnv(cfg.CookieKeyRaw)
	cfg.ForwardedHostHeader = expandEnv(cfg.ForwardedHostHeader)
	cfg.ForwardedProtoHeader = expandEnv(cfg.ForwardedProtoHeader)
	cfg.CookieSecure = expandEnv(cfg.CookieSecure)
	for i := range cfg.AllowedUsers {
		cfg.AllowedUsers[i] = expandEnv(cfg.AllowedUsers[i])
	}
	for i := range cfg.AllowedRedirectHosts {
		cfg.AllowedRedirectHosts[i] = expandEnv(cfg.AllowedRedirectHosts[i])
	}
	for i := range cfg.Providers {
		p := &cfg.Providers[i]
		p.ID = expandEnv(p.ID)
		p.Type = expandEnv(p.Type)
		p.DisplayName = expandEnv(p.DisplayName)
		p.BaseURL = expandEnv(p.BaseURL)
		p.ClientID = expandEnv(p.ClientID)
		p.ClientSecret = expandEnv(p.ClientSecret)
		p.GroupMatch = expandEnv(p.GroupMatch)
		p.Issuer = expandEnv(p.Issuer)
		p.UsernameClaim = expandEnv(p.UsernameClaim)
		p.GroupsClaim = expandEnv(p.GroupsClaim)
		p.HostedDomain = expandEnv(p.HostedDomain)
		for j := range p.Scopes {
			p.Scopes[j] = expandEnv(p.Scopes[j])
		}
		for j := range p.AllowedOrgs {
			p.AllowedOrgs[j] = expandEnv(p.AllowedOrgs[j])
		}
		for j := range p.AllowedGroups {
			p.AllowedGroups[j] = expandEnv(p.AllowedGroups[j])
		}
		// Apply per-type defaults.
		if p.BaseURL == "" {
			p.BaseURL = defaultBaseURL[p.Type]
		}
		if p.DisplayName == "" {
			p.DisplayName = defaultDisplayName[p.Type]
		}
		if p.GroupMatch == "" {
			p.GroupMatch = GroupMatchExact
		}
	}

	if cfg.CookieKeyRaw != "" {
		key, err := decodeCookieKey(cfg.CookieKeyRaw)
		if err != nil {
			return nil, err
		}
		cfg.CookieKey = key
	}

	return &cfg, nil
}

// decodeCookieKey decodes a hex or base64 string into a 32-byte key.
func decodeCookieKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// Try hex first (a 64-char hex string is unambiguous).
	if key, err := hex.DecodeString(s); err == nil && len(key) == cookieKeyLen {
		return key, nil
	}
	// Fall back to base64 (std and URL-safe, with/without padding).
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if key, err := enc.DecodeString(s); err == nil && len(key) == cookieKeyLen {
			return key, nil
		}
	}
	return nil, fmt.Errorf("cookieKey must decode (hex or base64) to %d bytes", cookieKeyLen)
}

// Enabled reports whether any provider is configured. With no providers the
// auth middleware is a pass-through.
func (c *Config) Enabled() bool {
	return len(c.Providers) > 0
}

// baseURLHint returns a short, human-friendly description of what a preset's
// BaseURL should contain, used to make validation errors actionable.
func baseURLHint(t string) string {
	switch t {
	case TypeOkta:
		return "Okta org issuer URL"
	case TypeKeycloak:
		return "Keycloak realm issuer URL"
	case TypeEntra:
		return "Entra tenant id or issuer URL"
	default:
		return "issuer URL"
	}
}

// Validate checks an enabled config for consistency. A disabled (no-provider)
// config is always valid.
func (c *Config) Validate() error {
	if !c.Enabled() {
		return nil
	}
	// RedirectURL is optional: empty selects host-derived callback mode, where
	// the redirect_uri is computed per request from the incoming host (see
	// Config.RedirectURL). A non-empty value pins one fixed callback.
	if len(c.CookieKey) != cookieKeyLen {
		return fmt.Errorf("auth: cookieKey must decode to %d bytes", cookieKeyLen)
	}
	switch c.CookieSecure {
	case "", cookieSecureAuto, cookieSecureAlways, cookieSecureNever:
		// ok (empty == auto)
	default:
		return fmt.Errorf("auth: cookieSecure must be %q, %q or %q", cookieSecureAuto, cookieSecureAlways, cookieSecureNever)
	}
	seen := make(map[string]bool, len(c.Providers))
	for _, p := range c.Providers {
		if p.ID == "" {
			return fmt.Errorf("auth: provider id must not be empty")
		}
		if seen[p.ID] {
			return fmt.Errorf("auth: duplicate provider id %q", p.ID)
		}
		seen[p.ID] = true
		switch p.Type {
		case TypeGitHub, TypeGitLab, TypeGoogle:
			// github is OAuth2+REST; gitlab and google have built-in default
			// issuers (gitlab.com / accounts.google.com), so BaseURL is optional.
			// Google's hostedDomain (hd) is optional.
		case TypeOkta, TypeKeycloak, TypeEntra:
			// These presets have no default issuer: it is fully
			// deployment-specific (Okta org, Keycloak realm, Entra tenant) and
			// is derived from BaseURL, so BaseURL must be set.
			if p.BaseURL == "" {
				return fmt.Errorf("auth: provider %q (type %s) requires baseURL (the %s)", p.ID, p.Type, baseURLHint(p.Type))
			}
		case TypeOIDC:
			if p.Issuer == "" {
				return fmt.Errorf("auth: provider %q (type oidc) requires an issuer", p.ID)
			}
		default:
			return fmt.Errorf("auth: provider %q has unknown type %q", p.ID, p.Type)
		}
		if p.ClientID == "" {
			return fmt.Errorf("auth: provider %q missing clientID", p.ID)
		}
		if p.ClientSecret == "" {
			return fmt.Errorf("auth: provider %q missing clientSecret", p.ID)
		}
		switch p.GroupMatch {
		case "", GroupMatchExact, GroupMatchSubtree:
			// ok (empty is accepted for programmatic configs and behaves like exact)
		default:
			return fmt.Errorf("auth: provider %q has unknown groupMatch %q", p.ID, p.GroupMatch)
		}
	}
	return nil
}
