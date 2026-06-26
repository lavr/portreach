package auth

import "context"

// Identity is the normalized result of a successful provider login. Groups holds
// the user's GitHub org logins or GitLab group paths, used for allowlist checks.
type Identity struct {
	Login  string
	Name   string
	Groups []string
}

// Provider is one configured SSO backend (a GitHub or GitLab instance). It owns
// the authorization-code flow: it builds the redirect URL and exchanges the
// returned code for a normalized Identity.
type Provider interface {
	// ID is the unique provider id from the config.
	ID() string
	// DisplayName is the human-facing label for the login button.
	DisplayName() string
	// Type is the provider type ("github" or "gitlab").
	Type() string
	// AuthCodeURL returns the provider's authorization URL for the given
	// opaque state value. nonce is the OIDC nonce bound to the request; it is
	// used by OIDC providers (GitLab) and ignored by others (GitHub).
	AuthCodeURL(state, nonce string) string
	// Exchange swaps an authorization code for the authenticated Identity.
	// nonce is verified against the OIDC id_token by providers that issue one
	// (GitLab); it is ignored by others (GitHub).
	Exchange(ctx context.Context, code, nonce string) (Identity, error)
}
