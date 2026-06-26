package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// gitlabProvider implements Provider against gitlab.com or a self-hosted GitLab
// instance using OpenID Connect (authorization-code flow with an id_token).
type gitlabProvider struct {
	id          string
	displayName string
	oauth       *oauth2.Config
	verifier    *oidc.IDTokenVerifier
}

// newGitLabProvider builds a GitLab OIDC provider from a ProviderConfig. It
// performs OIDC discovery against the issuer (BaseURL, defaulting to
// gitlab.com) to learn the authorization, token and JWKS endpoints. ctx governs
// the discovery request only.
func newGitLabProvider(ctx context.Context, pc ProviderConfig, redirectURL string) (*gitlabProvider, error) {
	issuer := strings.TrimRight(pc.BaseURL, "/")
	if issuer == "" {
		issuer = defaultBaseURL[TypeGitLab]
	}

	oidcProvider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("auth: gitlab oidc discovery for %q: %w", issuer, err)
	}

	return &gitlabProvider{
		id:          pc.ID,
		displayName: pc.DisplayName,
		oauth: &oauth2.Config{
			ClientID:     pc.ClientID,
			ClientSecret: pc.ClientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     oidcProvider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: oidcProvider.Verifier(&oidc.Config{ClientID: pc.ClientID}),
	}, nil
}

func (p *gitlabProvider) ID() string          { return p.id }
func (p *gitlabProvider) DisplayName() string { return p.displayName }
func (p *gitlabProvider) Type() string        { return TypeGitLab }

// AuthCodeURL returns the GitLab authorization URL, binding the OIDC nonce so it
// can be checked against the returned id_token in Exchange.
func (p *gitlabProvider) AuthCodeURL(state, nonce string) string {
	return p.oauth.AuthCodeURL(state, oidc.Nonce(nonce))
}

// Exchange swaps the authorization code for a token, verifies the id_token
// (signature, audience, expiry) and its nonce, then maps the OIDC claims into an
// Identity (Groups = GitLab group paths).
func (p *gitlabProvider) Exchange(ctx context.Context, code, nonce string) (Identity, error) {
	tok, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: gitlab token exchange: %w", err)
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, fmt.Errorf("auth: gitlab response missing id_token")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: gitlab verify id_token: %w", err)
	}
	if idToken.Nonce != nonce {
		return Identity{}, fmt.Errorf("auth: gitlab id_token nonce mismatch")
	}

	var claims struct {
		PreferredUsername string   `json:"preferred_username"`
		Sub               string   `json:"sub"`
		Name              string   `json:"name"`
		Groups            []string `json:"groups"`
		GroupsDirect      []string `json:"groups_direct"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("auth: gitlab parse claims: %w", err)
	}

	login := claims.PreferredUsername
	if login == "" {
		login = claims.Sub
	}
	if login == "" {
		return Identity{}, fmt.Errorf("auth: gitlab returned empty login")
	}

	groups := claims.Groups
	if len(groups) == 0 {
		groups = claims.GroupsDirect
	}

	return Identity{Login: login, Name: claims.Name, Groups: groups}, nil
}
