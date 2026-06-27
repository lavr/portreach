# Generic OIDC provider + presets (Keycloak / Okta / Auth0 / Entra ID / Google)

## Overview
- Generalize SSO auth from the fixed `github` + `gitlab` set to a **generic
  `type: oidc` provider** plus thin **named presets**, so any standards-compliant
  corporate IdP works in the first release without per-vendor code.
- `type: oidc` takes a configurable `issuer` and claim mapping and reuses the
  existing go-oidc code path. One type covers Keycloak, Authentik, Dex, Zitadel,
  Okta, Auth0, Microsoft Entra ID (Azure AD), Google Workspace.
- **Presets** are sugar over `oidc` (default issuer + claim mapping + scopes):
  `gitlab`, `google`, `entra`, `okta`, `keycloak`. `github` stays special (OAuth2
  + REST — it has no OIDC login).
- **Google Workspace**: optional `hostedDomain` (`hd`) restriction so only a
  given Google Workspace domain can sign in.
- Backward compatible with the SSO plan: existing `type: gitlab` configs keep
  working (gitlab becomes a preset that expands to the same behaviour).

## Dependency
- **Builds on** `docs/plans/2026-06-27-ui-sso-auth.md` (multi-provider auth +
  i18n). That plan introduces `internal/auth` (`Config`, `ProviderConfig`,
  `Provider` interface, the go-oidc GitLab provider, allowlist, audit log).
- **Start this plan only after that one is merged.** This plan refactors the
  GitLab provider into a shared generic OIDC provider and extends config.

## Context (from discovery / SSO plan)
- `internal/auth/provider.go`: `Provider` interface (`ID`, `DisplayName`, `Type`,
  `AuthCodeURL`, `Exchange`) and `Identity{Login, Name, Groups}`.
- `internal/auth/gitlab.go`: go-oidc provider (discovery by issuer, id_token
  verify + nonce, `groups` claim → `Identity.Groups`). This is the seed of the
  generic OIDC provider.
- `internal/auth/config.go`: `ProviderConfig{ID, Type, DisplayName, BaseURL,
  ClientID, ClientSecret, AllowedOrgs, AllowedGroups}` + `Validate()`.
- Allowlist + audit logging are provider-agnostic — no change needed there.
- Tests live next to code as `*_test.go` using `httptest` (hermetic).

## Development Approach
- **Testing approach**: Regular (implement, then unit tests within the same task).
- Complete each task fully before the next; small focused changes.
- **CRITICAL: every task MUST include new/updated tests** (success + error paths).
- **CRITICAL: all tests must pass before starting the next task.**
- **CRITICAL: keep this plan in sync** if scope changes.
- Run `go build ./...`, `go vet ./...`, `go test ./...` after each change.
- Maintain backward compatibility — existing `gitlab`/`github` configs unchanged.

## Testing Strategy
- **Unit tests** every task. Fake the OIDC discovery document + token + JWKS with
  `httptest` (hermetic, no real network); reuse the GitLab test fixtures style.
- Cover: generic OIDC discovery + claim mapping, custom `groupsClaim`/
  `usernameClaim`, each preset's expanded defaults, Google `hd` enforcement,
  Entra ID group-claim handling, config validation for `oidc` + presets.

## Progress Tracking
- Mark completed items `[x]` immediately. New tasks → `➕`; blockers → `⚠️`.

## What Goes Where
- **Implementation Steps** (`[ ]`): code, tests, helm, docs — all in-repo.
- **Post-Completion** (no checkboxes): registering apps with each IdP, real-IdP
  login verification.

## Implementation Steps

### Task 1: Generic OIDC provider (`type: oidc`)
- [x] extend `ProviderConfig` with OIDC fields: `Issuer`, `Scopes []string`,
      `UsernameClaim`, `GroupsClaim`, `HostedDomain` (all optional with defaults)
- [x] refactor `internal/auth/gitlab.go` into `internal/auth/oidc.go`: a generic
      `oidcProvider` built from `oidc.NewProvider(ctx, Issuer)`, configurable
      scopes (default `openid profile email`), id_token verify + nonce, and claim
      mapping driven by `UsernameClaim` (default `preferred_username`→`sub`) and
      `GroupsClaim` (default `groups`)
- [x] wire `type: oidc` in the provider registry (`auth.New`) to build `oidcProvider`
- [x] write tests with a fake OIDC issuer (discovery + JWKS + token via `httptest`):
      identity + groups mapping, custom claim names, nonce mismatch rejected
- [x] run tests — must pass before Task 2

### Task 2: Named presets (gitlab, google, entra, okta, keycloak)
- [x] add a preset table mapping `Type` → default `{Issuer template, Scopes,
      UsernameClaim, GroupsClaim, DisplayName}`; presets expand into an
      `oidcProvider` (explicit config fields always override preset defaults)
- [x] `gitlab`: issuer `BaseURL` or `https://gitlab.com`, groups claim `groups`
      (keeps SSO-plan behaviour — backward compatible)
- [x] `okta` / `keycloak`: issuer = `BaseURL` (required), groups claim `groups`
- [x] `entra`: issuer `https://login.microsoftonline.com/<tenant>/v2.0`
      (`tenant` from BaseURL/field), groups claim `groups`; document that group
      claims are object IDs and may need an app-registration "groups" claim
- [x] write tests: each preset expands to the expected issuer/claims; explicit
      config overrides preset defaults
- [x] run tests — must pass before Task 3

### Task 3: Google Workspace preset + hosted-domain restriction
- [x] `google` preset: issuer `https://accounts.google.com`, scopes
      `openid email profile`, username claim `email`
- [x] enforce optional `HostedDomain` (`hd`): pass `hd` as an auth param and
      verify the `hd` claim in the id_token on callback; reject mismatches (403)
- [x] note: Google has no group claim — access control via `AllowedUsers` (emails)
      and/or `HostedDomain`; document this
- [x] write tests: `hd` enforced (match allow, mismatch 403), email→Login mapping
- [x] run tests — must pass before Task 4

### Task 4: Config validation for oidc + presets
- [x] `Config.Validate()`: `oidc` requires `Issuer`; `okta`/`keycloak`/`entra`
      require `BaseURL`/tenant; `google` `hd` optional; unknown type still rejected
- [x] friendly errors naming the offending provider `id`
- [x] write tests: valid oidc, missing issuer, preset missing BaseURL, unknown
      type, google with/without hd
- [x] run tests — must pass before Task 5

### Task 5: Helm + docs
- [x] `charts/portreach/values.yaml`: document the new provider `type`s and OIDC
      fields (`issuer`, `scopes`, `usernameClaim`, `groupsClaim`, `hostedDomain`)
      in the `ui.auth.providers` examples
- [x] `docs/configuration.md`: generic OIDC reference + a short setup snippet per
      IdP (Keycloak, Okta, Auth0, Entra ID, Google), claim-mapping notes, Google
      `hd` and Entra group-claim caveats
- [x] `README.md`: update the auth section to say "GitHub + any OIDC IdP
      (Keycloak, Okta, Auth0, Entra ID, Google, GitLab)"
- [x] extend the helm render assertion with an `oidc`/`google` provider example;
      run `helm lint`
- [x] run `go test ./...` — no regression

### Task 6: Verify acceptance criteria
- [ ] verify generic `oidc` works end-to-end against a fake issuer; each preset
      expands correctly; google `hd` enforced; gitlab/github unchanged
- [ ] verify edge cases: custom claims, missing issuer, hd mismatch, unknown type
- [ ] run full unit suite `go test ./... -v`; `go vet ./...`; `helm lint`
- [ ] verify `internal/auth` coverage ≥ 80%

### Task 7: [Final] Knowledge + docs polish
- [ ] re-read docs for accuracy; note the generic-OIDC model and preset table
- [ ] confirm `go.mod`/`go.sum` unchanged (go-oidc/oauth2 already present)

*Note: ralphex automatically moves completed plans to `docs/plans/completed/`.*

## Technical Details
- **Provider types**: `github` (OAuth2+REST), `oidc` (generic), and presets
  `gitlab|google|entra|okta|keycloak` that expand to `oidc` with defaults.
- **Preset = defaults only**: any explicit `ProviderConfig` field overrides the
  preset; presets set `{Issuer, Scopes, UsernameClaim, GroupsClaim, DisplayName}`.
- **Claim mapping**: `UsernameClaim` default `preferred_username` then `sub`;
  `GroupsClaim` default `groups`. Google uses `email`; no groups → rely on
  `AllowedUsers` / `HostedDomain`.
- **Config example**:
  ```yaml
  providers:
    - id: keycloak
      type: oidc
      displayName: "Corporate SSO"
      issuer: https://keycloak.corp/realms/main
      clientID: portreach
      clientSecret: ${KC_SECRET}
      groupsClaim: groups
      allowedGroups: [sre, infra]
    - id: google
      type: google
      displayName: "Google"
      clientID: ...
      clientSecret: ${GOOGLE_SECRET}
      hostedDomain: corp.com
      allowedUsers: [alice@corp.com]
    - id: entra
      type: entra
      displayName: "Microsoft"
      baseURL: <tenant-id>            # → login.microsoftonline.com/<tenant>/v2.0
      clientID: ...
      clientSecret: ${ENTRA_SECRET}
      allowedGroups: ["<group-object-id>"]
  ```
- **Not in scope** (deferred): SAML, LDAP, basic-auth/local users — different
  protocols/paradigms, candidates for a later plan.

## Post-Completion
*Items requiring manual intervention or external systems — informational only.*

**Manual verification:**
- Register an OIDC app in at least one real IdP (Keycloak/Okta/Entra/Google) and
  complete a real-browser login through the chooser button.
- Verify group-based allowlist with that IdP's group claim (and Entra's object-ID
  groups); verify Google `hd` blocks foreign domains.

**External system updates:**
- For Entra ID, configure the app registration to emit the `groups` claim.
- For Google, the OAuth consent screen / Workspace domain must permit the app.
