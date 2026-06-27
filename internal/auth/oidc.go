package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// oidcProvider is a generic, standards-compliant OpenID Connect provider. It
// drives the authorization-code flow against any issuer that exposes OIDC
// discovery (Keycloak, Authentik, Dex, Zitadel, Okta, Auth0, Microsoft Entra ID,
// Google Workspace, GitLab, ...). Vendor differences are expressed purely as
// configuration: the issuer URL, the requested scopes, and which id_token claims
// carry the username and groups. The named presets (gitlab, google, entra, okta,
// keycloak) are thin sugar that fill these fields with per-vendor defaults.
type oidcProvider struct {
	id            string
	displayName   string
	typ           string // configured type ("oidc" or a preset name), returned by Type()
	oauth         *oauth2.Config
	verifier      *oidc.IDTokenVerifier
	usernameClaim string
	groupsClaim   string
	hostedDomain  string // optional Google `hd` restriction (enforced by the google preset)
}

// newOIDCProvider builds a generic OIDC provider from pc. It performs OIDC
// discovery against pc.Issuer to learn the authorization, token and JWKS
// endpoints. ctx governs the discovery request only. Claim names and scopes fall
// back to standard defaults when pc leaves them empty.
func newOIDCProvider(ctx context.Context, pc ProviderConfig, redirectURL string) (*oidcProvider, error) {
	issuer := strings.TrimRight(pc.Issuer, "/")
	if issuer == "" {
		return nil, fmt.Errorf("auth: oidc provider %q requires an issuer", pc.ID)
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("auth: oidc discovery for %q: %w", issuer, err)
	}

	scopes := pc.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	usernameClaim := pc.UsernameClaim
	if usernameClaim == "" {
		usernameClaim = defaultUsernameClaim
	}
	groupsClaim := pc.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = defaultGroupsClaim
	}

	typ := pc.Type
	if typ == "" {
		typ = TypeOIDC
	}

	return &oidcProvider{
		id:          pc.ID,
		displayName: pc.DisplayName,
		typ:         typ,
		oauth: &oauth2.Config{
			ClientID:     pc.ClientID,
			ClientSecret: pc.ClientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: pc.ClientID}),
		usernameClaim: usernameClaim,
		groupsClaim:   groupsClaim,
		hostedDomain:  pc.HostedDomain,
	}, nil
}

func (p *oidcProvider) ID() string          { return p.id }
func (p *oidcProvider) DisplayName() string { return p.displayName }
func (p *oidcProvider) Type() string        { return p.typ }

// AuthCodeURL returns the provider authorization URL, binding the OIDC nonce so
// it can be checked against the returned id_token in Exchange.
func (p *oidcProvider) AuthCodeURL(state, nonce string) string {
	return p.oauth.AuthCodeURL(state, oidc.Nonce(nonce))
}

// Exchange swaps the authorization code for a token, verifies the id_token
// (signature, audience, expiry) and its nonce, then maps the OIDC claims into an
// Identity using the configured username and groups claims.
func (p *oidcProvider) Exchange(ctx context.Context, code, nonce string) (Identity, error) {
	tok, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: oidc token exchange: %w", err)
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, fmt.Errorf("auth: oidc response missing id_token")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: oidc verify id_token: %w", err)
	}
	if idToken.Nonce != nonce {
		return Identity{}, fmt.Errorf("auth: oidc id_token nonce mismatch")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("auth: oidc parse claims: %w", err)
	}

	login := claimString(claims, p.usernameClaim)
	if login == "" {
		login = claimString(claims, "sub")
	}
	if login == "" {
		return Identity{}, fmt.Errorf("auth: oidc returned empty login")
	}

	return Identity{
		Login:  login,
		Name:   claimString(claims, "name"),
		Groups: claimStrings(claims, p.groupsClaim),
	}, nil
}

// claimString returns the string value of claim key, or "" if absent or not a
// string.
func claimString(claims map[string]any, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// claimStrings returns claim key as a []string. JSON decoding yields []any, so
// each element is coerced; non-string elements are skipped. A plain string claim
// is treated as a single-element list.
func claimStrings(claims map[string]any, key string) []string {
	switch v := claims[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}
