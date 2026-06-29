# GitLab group restriction: subgroup matching + minimum access level

## Overview
A per-provider group allowlist **already exists** (`allowedGroups`, exact-string
match in `Authenticator.allowed()`). It is too naive for real GitLab, where groups
are **hierarchical paths** (`acme/backend/team-a`) and membership carries a **role**.
This plan adds the two things GitLab deployments actually need, both opt-in and
backward compatible:

- **Subtree (hierarchical) matching** — allowing `acme/backend` also admits members
  of any subgroup (`acme/backend/team-a`). Today exact-match rejects them. New
  per-provider `groupMatch: exact | subtree` (default `exact` = current behaviour).
- **Minimum access level** — restrict not just *membership* but *role*: e.g. only
  `maintainer`+ of a group. GitLab's OIDC exposes role-scoped claims
  (`https://gitlab.org/claims/groups/{owner,maintainer,developer}`), each listing the
  group paths where the user is a **direct member with that specific role**. We compose
  "min maintainer" ourselves by taking the union of the `maintainer` and `owner` claims.
  New per-provider `minAccessLevel` (unset = any membership = current behaviour).
  **GitLab preset only** (see Open Questions / Validation).

  ⚠️ **Claim locations (GitLab OIDC docs):** the **id_token carries only
  `groups_direct`**; **`groups` and the role claims are returned only by the UserInfo
  endpoint.** The current code reads claims *exclusively* from the verified id_token
  (`oidc.go:148`), so:
  - `groupMatch: subtree` **without** `minAccessLevel` does **no** UserInfo fetch and
    therefore matches against **`groups_direct` (direct memberships)** only — a user who
    inherits membership in `acme/backend` via a parent group is not visible. Documented
    limitation; a fuller `groups` source would need UserInfo (out of scope here).
  - `minAccessLevel` **requires** a UserInfo fetch (Task 2).
  ⚠️ **Direct-membership limitation of role claims:** the role arrays list groups where
  the user holds the role **directly**. A role *inherited* from a parent group (e.g.
  Maintainer on `acme` inherited into `acme/backend`) may **not** appear in the
  `acme/backend` entry, so `minAccessLevel`+`subtree` admits only direct-role holders of
  the matched subgroup. Verify on a live instance (Post-Completion).

  GitLab documents claims for `owner`/`maintainer`/`developer`; `reporter`/`guest` are
  **not** documented as role claims, so the `minAccessLevel` enum is limited to the
  three sourceable roles.

Result: an operator can say "only maintainers of `acme/backend` (and its subgroups)
may sign in", configured on the GitLab provider. **`minAccessLevel` is not a
standalone restriction**: it narrows *which* groups land in `Identity.Groups`, but
those still have to match a non-empty `allowedGroups`/`allowedOrgs` to gate access
(`allowed()` is open when no allowlist is set — `auth.go:393`). `Validate()` therefore
requires `minAccessLevel` to be paired with a non-empty group allowlist.

## Context (from discovery)
- `internal/auth/auth.go` `allowed(providerID, id)` (≈ line 387): union of
  `AllowedOrgs`+`AllowedGroups`, returns true if any `id.Groups` element **==** an
  allowlist entry (exact match). This is where subtree matching plugs in.
- `internal/auth/oidc.go` (`Exchange`, claim mapping ≈ line 180): `groups =
  claimStrings(claims, p.groupsClaim)` with fallback `p.groupsFallback`
  (GitLab `groups_direct`). Claims come **only from the verified id_token**
  (`idToken.Claims(&claims)`, line 148) — there is no UserInfo fetch today. Since the
  GitLab id_token carries **`groups_direct` but not `groups`**, the default
  `groupsClaim="groups"` resolves to nothing and the code falls back to `groups_direct`
  — i.e. today's (and subtree's) source is direct memberships.
- Role claims require a UserInfo call (`oidc.Provider.UserInfo(ctx, tokenSource)`).
  **The `*oidc.Provider` is NOT currently stored** — `oidcProvider` holds oauth/verifier/
  claim names only, and the provider is a local in `newOIDCProvider` (`oidc.go:26/56`).
  Task 2 must add a field to keep `*oidc.Provider` on the struct.
- `internal/auth/config.go`: `ProviderConfig` (`AllowedGroups`, `GroupsClaim`,
  `Type`, …) + `Validate()`/env-expansion; `defaultGroupsClaim = "groups"`.
- `internal/auth/presets.go`: the `gitlab` preset (issuer/scopes/claims defaults).
- Helm: `values.yaml`/`values.schema.json` (`ui.auth.providers[]`) **and
  `charts/portreach/templates/configmap-ui-auth.yaml`** (≈ lines 25-33), which copies
  each provider field into `auth.yaml` one-by-one — new fields must be added there too
  or they never reach the app. `internal/charttest`.
- go-oidc already vendored — **no new dependencies**.

## Development Approach
- **Testing approach**: Regular (implement, then unit tests in the same task).
- Each task ends with tests (success + error) and must pass before the next.
- **Backward compatible**: `groupMatch` defaults to `exact`; `minAccessLevel` unset →
  plain membership. Existing `allowedGroups` configs behave identically.
- `go build/vet/test ./...` + `helm lint` after each change; `gofmt` clean.

## Testing Strategy
- Hermetic, modelling GitLab's real claim split: the fake issuer puts **only
  `groups_direct` in the id_token**, and serves a **UserInfo endpoint** carrying
  **`groups` + the `https://gitlab.org/claims/groups/<role>` arrays**. Role-claim and
  full-`groups` tests must hit the UserInfo path (an id_token-only fixture would pass
  while prod fails — the High finding). Confirm the test OIDC harness can serve
  `/userinfo`, and that UserInfo's `sub` matches the id_token's.
- Cover: exact still exact; subtree admits a subgroup, rejects sibling/parent-as-child
  edge cases (`acme/backend` must NOT match `acme/backend-ops`); subtree-without-
  minAccessLevel matches against `groups_direct` (direct memberships) from the id_token;
  minAccessLevel admits only members at/above the level using the **supported** roles
  `developer < maintainer < owner`; membership-only when unset; combined subtree +
  minAccessLevel; **UserInfo `sub` ≠ id_token `sub` → auth failure**.

## Progress Tracking
- Mark `[x]` immediately. New tasks → `➕`; blockers → `⚠️`.

## What Goes Where
- **Implementation Steps** (`[ ]`): code, tests, helm, docs.
- **Post-Completion** (no checkboxes): verify against a real GitLab (claims present),
  confirm the required scope.

## Implementation Steps

### Task 1: Subtree (hierarchical) group matching
- [x] `config.go`: add `ProviderConfig.GroupMatch string` (`exact` default | `subtree`);
      env-expand if needed; `Validate()` rejects unknown values
- [x] `auth.go` `allowed()`: when the provider's `GroupMatch == "subtree"`, a user
      group `have` satisfies an allowlist entry `want` if `have == want` **or**
      `strings.HasPrefix(have, want+"/")` (descendant); keep exact otherwise.
      Guard the boundary so `acme/backend` does not match `acme/backend-ops`
- [x] write tests: exact unchanged; subtree admits `acme/backend/team-a`, rejects
      `acme/backend-ops` and bare parent mismatch
- [x] run tests — must pass before Task 2

### Task 2: GitLab minimum access level (role-scoped claims)
- [ ] define the role order for the **sourceable** GitLab roles:
      `developer < maintainer < owner` (the only roles GitLab documents as
      `https://gitlab.org/claims/groups/<role>` claims; `reporter`/`guest` excluded —
      no claim to read them from)
- [ ] `oidc.go`: **store `*oidc.Provider` on the `oidcProvider` struct** (it is only a
      local in `newOIDCProvider` today, `oidc.go:26/56`) so UserInfo can be called later
- [ ] `oidc.go`: add a UserInfo fetch — when `MinAccessLevel` is set, call
      `p.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))`, decode its claims, and
      build `Identity.Groups` from the **union** of the role claims for every role **at
      or above** the minimum (we compose the cumulative set — GitLab emits one array per
      exact role). Unset → keep today's id_token `groupsClaim`/`groupsFallback` path, no
      UserInfo call. Handle a missing/empty role claim as "no groups at that level"
      (fail-closed), and surface a clear error if the UserInfo request itself fails
- [ ] **verify `userInfo.Subject == idToken.Subject`** — go-oidc does not bind UserInfo
      to the id_token automatically; a mismatch must be an auth failure (token/userinfo
      from different subjects must never be trusted for group authz)
- [ ] ensure the gitlab preset requests a scope that yields these claims (document the
      required scope; verify which scope GitLab needs for the role claims — do **not**
      assume default `openid` includes them)
- [ ] write tests (driving a **fake UserInfo endpoint**, not just an id_token):
      maintainer-min admits a maintainer/owner of the group, rejects a developer;
      unset = membership; combined with subtree from Task 1; **UserInfo `sub` mismatch →
      auth failure**; UserInfo request error → clear failure
- [ ] run tests — must pass before Task 3

### Task 3: Config validation + plumbing
- [ ] `config.go`: add `ProviderConfig.MinAccessLevel string` (empty = any, else one
      of `developer`/`maintainer`/`owner`)
- [ ] surface friendly `Validate()` errors naming the provider `id`:
      - unknown `groupMatch` value
      - bad/unknown `minAccessLevel` value
      - `minAccessLevel` set on a **non-`gitlab`** provider (GitHub/generic-OIDC have
        no equivalent claim) — reject
      - `minAccessLevel` set **without** a non-empty `allowedGroups`/`allowedOrgs`
        (otherwise it's a no-op on an open provider — the High finding): reject with a
        message telling the operator to add a group allowlist
- [ ] confirm env-expansion / defaults applied for the new fields
- [ ] write tests: valid combos, each invalid case (incl. `minAccessLevel` with empty
      allowlist, and on a non-gitlab provider)
- [ ] run tests — must pass before Task 4

### Task 4: Helm + docs
- [ ] `charts/portreach/templates/configmap-ui-auth.yaml`: add
      `{{- with .groupMatch }}` and `{{- with .minAccessLevel }}` copy lines alongside
      the existing per-field block (≈ lines 25-33) — **without this the values never
      reach `auth.yaml`** (the Medium finding)
- [ ] `values.yaml` + `values.schema.json`: add `groupMatch` (enum
      `exact|subtree`) and `minAccessLevel` (enum `developer|maintainer|owner`) to the
      provider schema, with comments
- [ ] `docs/configuration.md`: GitLab group restriction — full group paths, subgroup
      (`subtree`) behaviour, the role claims + `minAccessLevel`, that it is
      **gitlab-only and must be paired with `allowedGroups`/`allowedOrgs`**, the role
      claims live in UserInfo, and the required scope/claim notes; a worked example
      ("maintainers of `acme/backend`")
- [ ] extend `internal/charttest` with a provider example using the new fields and
      assert they render into `auth.yaml`; `helm lint`
- [ ] run `go test ./...` — no regression

### Task 5: Verify acceptance criteria
- [ ] exact (default) unchanged; subtree admits subgroups with correct boundary;
      minAccessLevel enforces role; combined works; all invalid configs rejected
- [ ] `go test ./... -v`, `go vet ./...`, `helm lint` clean; `internal/auth` ≥ 80%

### Task 6: [Final] Knowledge
- [ ] note GitLab subgroup + access-level restriction in README/AGENTS.md/docs

*Note: ralphex auto-moves completed plans to `docs/plans/completed/`.*

## Technical Details
- **Subtree match**: `have == want || strings.HasPrefix(have, want+"/")`. The
  trailing slash prevents `acme/backend` matching `acme/backend-ops`. Applies to both
  `AllowedGroups` and (for symmetry) `AllowedOrgs` only when `groupMatch: subtree`.
- **Claim locations**: id_token = `groups_direct` only; `groups` + the role claims =
  **UserInfo only**. So the default/subtree path (no `minAccessLevel`) sees direct
  memberships from the id_token, and `minAccessLevel` requires a UserInfo fetch.
- **Role claims**: GitLab emits one `https://gitlab.org/claims/groups/<role>` array
  **per exact role**, listing groups where the user is a **direct member with that
  role**, only for `owner`/`maintainer`/`developer`. *We* compose the "at least <role>"
  set as the union of the claims for every role ≥ the minimum (cumulative semantics are
  ours, not GitLab's). The union becomes `Identity.Groups`, then matched (exact/subtree)
  by `allowed()`. ⚠️ A role **inherited** from a parent group may not appear in a
  subgroup's role array, so `minAccessLevel` gates on *direct* role only. After the
  UserInfo fetch, `userInfo.Subject` must equal the id_token `sub` or auth fails.
  Without `minAccessLevel`, behaviour is today's id_token membership claim — no
  UserInfo call.
- **`minAccessLevel` is not standalone**: `allowed()` is open when no allowlist is
  configured. `minAccessLevel` only *filters* the groups; it gates nothing on its own.
  `Validate()` rejects it unless `allowedGroups`/`allowedOrgs` is non-empty.
- **Scope**: `minAccessLevel` is **gitlab-preset only**; `Validate()` rejects it for
  GitHub and generic OIDC providers (no equivalent claim / claim location not
  guaranteed). `groupMatch` is generic (applies to any provider's group allowlist).
- **No new dependencies.**

## Resolved decisions
- **Scope of `minAccessLevel`**: gitlab preset only (decided 2026-06-28). Generic
  OIDC is rejected — the role claims and their UserInfo location are GitLab-specific
  and not guaranteed elsewhere. Revisit only if a generic-OIDC user with
  GitLab-compatible claims appears.

## Post-Completion
*Manual / external — no checkboxes.*
- Verify against a real GitLab instance which endpoint actually carries the role
  claims (id_token vs **UserInfo**) and under which **scope**; the plan assumes
  UserInfo + an explicit scope — adjust the requested scope if a claim is missing.
- Confirm GitLab really exposes only `owner`/`maintainer`/`developer` role claims (no
  `reporter`/`guest`); widen the enum only if live claims prove otherwise.
- Confirm the **inherited-role** behaviour on a live instance: does a user with
  Maintainer on a parent group appear in the role claim for a subgroup, or only direct
  role holders? Adjust the docs (and, if needed, the data source) to match reality.
- Confirm a user removed from the group (or downgraded below `minAccessLevel`) is
  denied on next login.
