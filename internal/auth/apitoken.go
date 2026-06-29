package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// bearerVerifyTimeout bounds the per-request access-token verification. The
// incoming request context carries no deadline, and an unknown JWKS key id forces
// go-oidc to refetch the issuer's keys, so a stalled IdP would otherwise pin the
// handler goroutine. Verified keys are cached, so the common path makes no
// network call.
const bearerVerifyTimeout = 15 * time.Second

// apiEntry is one configured bearer-token issuer with its built JWT verifier and
// resolved claim mapping. A presented access token is matched to an entry by
// (issuer, audience) — implemented as "the verifier whose iss/aud the token
// satisfies" — and the entry's id becomes Session.Provider.
type apiEntry struct {
	cfg            APIEntry
	verifier       *oidc.IDTokenVerifier
	usernameClaim  string
	groupsClaim    string
	groupsFallback string // optional secondary groups claim (e.g. GitLab groups_direct)
}

// resolveAPIClaims derives the username/groups claim names and optional groups
// fallback for an API entry. Defaults mirror the browser OIDC path; a named Type
// pulls its preset's claim defaults and groups fallback unless overridden.
func resolveAPIClaims(e APIEntry) (username, groups, groupsFallback string) {
	username, groups = e.UsernameClaim, e.GroupsClaim
	if ps, ok := presets[e.Type]; ok {
		if username == "" {
			username = ps.usernameClaim
		}
		if groups == "" {
			groups = ps.groupsClaim
		}
		// Apply the preset's groups fallback only when the deployment did not pin
		// its own groups claim, matching newPresetProvider's browser behaviour.
		if e.GroupsClaim == "" {
			groupsFallback = ps.groupsFallback
		}
	}
	if username == "" {
		username = defaultUsernameClaim
	}
	if groups == "" {
		groups = defaultGroupsClaim
	}
	return username, groups, groupsFallback
}

// newAPIEntry builds the JWT verifier for an API entry. It runs OIDC discovery
// against the issuer (to learn the JWKS endpoint) and pins the audience as the
// expected `aud`. ctx governs the discovery request only.
func newAPIEntry(ctx context.Context, e APIEntry) (*apiEntry, error) {
	// Pass the issuer through verbatim (only trimming whitespace): OIDC discovery
	// does an exact string comparison against the discovery document's `issuer`,
	// so a stray trailing slash would break verification for IdPs whose canonical
	// issuer has none (and vice versa, e.g. Auth0).
	provider, err := oidc.NewProvider(ctx, strings.TrimSpace(e.Issuer))
	if err != nil {
		return nil, err
	}
	username, groups, groupsFallback := resolveAPIClaims(e)
	return &apiEntry{
		cfg:            e,
		verifier:       provider.Verifier(&oidc.Config{ClientID: e.Audience}),
		usernameClaim:  username,
		groupsClaim:    groups,
		groupsFallback: groupsFallback,
	}, nil
}

// bearerToken extracts the token from an `Authorization: Bearer <token>` header,
// or "" when absent/malformed. The scheme match is case-insensitive per RFC 6750.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// authenticateBearer verifies a bearer access token against every configured API
// entry and, on the first that validates (signature + iss + aud + exp), maps its
// claims into a Session whose Provider is that entry's id. ok is false when no
// entry accepts the token — a forged, expired, wrong-audience or unmatched-issuer
// token — so the caller returns 401 and never attaches an identity.
func (a *Authenticator) authenticateBearer(ctx context.Context, token string) (Session, bool) {
	ctx, cancel := context.WithTimeout(ctx, bearerVerifyTimeout)
	defer cancel()

	for _, e := range a.apiEntries {
		idToken, err := e.verifier.Verify(ctx, token)
		if err != nil {
			continue // wrong issuer/audience/signature/expiry for this entry
		}
		var claims map[string]any
		if err := idToken.Claims(&claims); err != nil {
			continue
		}

		login := claimString(claims, e.usernameClaim)
		// When the identity is sourced from the email claim, require the IdP to
		// have verified it: an unverified, self-asserted email is attacker
		// controllable and is matched verbatim against AllowedUsers. Only an
		// explicit email_verified:false is rejected (the claim is optional).
		if login != "" && e.usernameClaim == "email" {
			if verified, ok := claimBool(claims, "email_verified"); ok && !verified {
				continue
			}
		}
		if login == "" {
			login = claimString(claims, "sub")
		}
		if login == "" {
			continue // no attributable subject; treat as no match
		}

		groups := claimStrings(claims, e.groupsClaim)
		if len(groups) == 0 && e.groupsFallback != "" {
			groups = claimStrings(claims, e.groupsFallback)
		}

		return Session{
			User:     login,
			Name:     claimString(claims, "name"),
			Provider: e.cfg.ID,
			Groups:   groups,
			Expiry:   idToken.Expiry.Unix(),
		}, true
	}
	return Session{}, false
}
