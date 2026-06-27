package auth

import (
	"context"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// preset captures the per-vendor defaults that turn a named provider type
// (gitlab, okta, keycloak, entra, ...) into a generic OIDC provider. A preset
// only supplies defaults: any field set explicitly on the ProviderConfig always
// wins, so a deployment can point a preset at a custom issuer or remap claims.
type preset struct {
	displayName    string
	scopes         []string
	usernameClaim  string
	groupsClaim    string
	groupsFallback string                         // optional secondary groups claim
	issuer         func(pc ProviderConfig) string // derives the issuer URL from config
}

// oidcScopes is the default scope set shared by most presets.
var oidcScopes = []string{oidc.ScopeOpenID, "profile", "email"}

// googleScopes is the scope set for the Google Workspace preset. Google has no
// groups claim, so access control relies on AllowedUsers (emails) and/or the
// hosted-domain (hd) restriction rather than group membership.
var googleScopes = []string{oidc.ScopeOpenID, "email", "profile"}

// googleIssuer is Google's fixed OIDC issuer; it is independent of any BaseURL.
func googleIssuer(ProviderConfig) string { return "https://accounts.google.com" }

// baseURLIssuer treats the configured BaseURL as the issuer verbatim. Used by
// presets whose issuer is fully deployment-specific (Okta org, Keycloak realm).
func baseURLIssuer(pc ProviderConfig) string { return pc.BaseURL }

// gitlabIssuer defaults to gitlab.com when no self-hosted BaseURL is given. A
// trailing slash on the configured BaseURL is trimmed: GitLab's canonical issuer
// has no trailing slash, and OIDC discovery compares the configured issuer
// against the discovery document verbatim, so a slash-suffixed BaseURL would
// fail discovery. This mirrors the old dedicated GitLab provider, keeping
// existing self-hosted configs working. (Explicit oidc `issuer` values are still
// passed through verbatim by newOIDCProvider, for IdPs like Auth0 whose
// canonical issuer ends in `/`.)
func gitlabIssuer(pc ProviderConfig) string {
	if base := strings.TrimRight(strings.TrimSpace(pc.BaseURL), "/"); base != "" {
		return base
	}
	return "https://gitlab.com"
}

// entraIssuer builds the Microsoft Entra ID (Azure AD) v2.0 issuer. BaseURL may
// be either a bare tenant id/domain (the common case) or an already-complete
// issuer URL, which is passed through unchanged.
func entraIssuer(pc ProviderConfig) string {
	tenant := strings.TrimSpace(pc.BaseURL)
	if tenant == "" {
		return ""
	}
	if strings.HasPrefix(tenant, "http://") || strings.HasPrefix(tenant, "https://") {
		return tenant
	}
	return "https://login.microsoftonline.com/" + tenant + "/v2.0"
}

// presets maps each named preset type to its defaults. github and oidc are
// deliberately absent: github is not OIDC, and oidc is the generic provider with
// no preset defaults. google is added by the Google Workspace preset.
var presets = map[string]preset{
	TypeGitLab: {
		displayName:    "GitLab",
		scopes:         oidcScopes,
		usernameClaim:  "preferred_username",
		groupsClaim:    "groups",
		groupsFallback: "groups_direct",
		issuer:         gitlabIssuer,
	},
	TypeOkta: {
		displayName:   "Okta",
		scopes:        oidcScopes,
		usernameClaim: "preferred_username",
		groupsClaim:   "groups",
		issuer:        baseURLIssuer,
	},
	TypeKeycloak: {
		displayName:   "Keycloak",
		scopes:        oidcScopes,
		usernameClaim: "preferred_username",
		groupsClaim:   "groups",
		issuer:        baseURLIssuer,
	},
	TypeEntra: {
		displayName:   "Microsoft",
		scopes:        oidcScopes,
		usernameClaim: "preferred_username",
		groupsClaim:   "groups",
		issuer:        entraIssuer,
	},
	TypeGoogle: {
		displayName: "Google",
		scopes:      googleScopes,
		// Google identifies users by email and emits no groups claim; access is
		// gated by AllowedUsers and/or the optional HostedDomain (hd).
		usernameClaim: "email",
		groupsClaim:   "",
		issuer:        googleIssuer,
	},
}

// isPreset reports whether t names a preset that expands into an OIDC provider.
func isPreset(t string) bool {
	_, ok := presets[t]
	return ok
}

// applyPreset fills the OIDC fields of pc from the matching preset's defaults,
// leaving any explicitly-set field untouched. A type with no preset (oidc, or an
// unknown type) is returned unchanged.
func applyPreset(pc ProviderConfig) ProviderConfig {
	ps, ok := presets[pc.Type]
	if !ok {
		return pc
	}
	if pc.Issuer == "" && ps.issuer != nil {
		pc.Issuer = ps.issuer(pc)
	}
	if len(pc.Scopes) == 0 {
		pc.Scopes = ps.scopes
	}
	if pc.UsernameClaim == "" {
		pc.UsernameClaim = ps.usernameClaim
	}
	if pc.GroupsClaim == "" {
		pc.GroupsClaim = ps.groupsClaim
	}
	if pc.DisplayName == "" {
		pc.DisplayName = ps.displayName
	}
	return pc
}

// newPresetProvider builds an OIDC provider for a preset or the generic oidc
// type. It expands preset defaults into the config, runs OIDC discovery, and
// wires any preset-specific groups fallback (applied only when the deployment
// did not override the groups claim).
func newPresetProvider(ctx context.Context, pc ProviderConfig, redirectURL string) (*oidcProvider, error) {
	ps, ok := presets[pc.Type]
	overrodeGroups := pc.GroupsClaim != ""

	p, err := newOIDCProvider(ctx, applyPreset(pc), redirectURL)
	if err != nil {
		return nil, err
	}
	if ok && !overrodeGroups {
		p.groupsFallback = ps.groupsFallback
	}
	return p, nil
}
