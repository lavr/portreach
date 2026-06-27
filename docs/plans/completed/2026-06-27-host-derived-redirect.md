# Host-derived OAuth redirect URL (one deploy, many hostnames)

## Overview
- Today `auth.redirectURL` is a **single required value** baked into each provider's
  `oauth2.Config.RedirectURL` at construction. So one deployment authenticates on
  exactly **one** hostname. Operators running the same portreach behind several
  ingress names (e.g. a per-cluster `portreach.cluster-one.k8s` **and** a
  shared `portreach.shared.k8s`) cannot make login work on all of them.
- Add a **dynamic mode**: when `auth.redirectURL` is **empty**, derive the OAuth
  `redirect_uri` **per request** from the incoming host —
  `https://<X-Forwarded-Host>/auth/callback` (scheme from `X-Forwarded-Proto`,
  falling back to `r.Host` + TLS state). One deploy then works across every
  hostname the operator points at it; no per-cluster auth config.
- **Backward compatible**: a non-empty `redirectURL` keeps today's fixed behaviour
  exactly. Dynamic mode is opt-in by leaving it empty.
- **Safe by construction**: the IdP only honours `redirect_uri`s **registered** for
  the OAuth app, so a spoofed/unknown host is rejected by the IdP, not redirected
  to. The derived callback is pinned in the sealed state cookie at login and reused
  at callback, so it cannot be swapped mid-flow. An optional allowlist adds
  defence-in-depth for setups where the proxy does not strip client-supplied
  `X-Forwarded-*`.

## Context (from discovery)
- `internal/auth/provider.go`: `Provider` interface — `AuthCodeURL(state, nonce string) string`
  and `Exchange(ctx, code, nonce string)`.
- `internal/auth/oidc.go`: `oidcProvider.oauth oauth2.Config` (`RedirectURL` set at
  `:87`); `AuthCodeURL` → `p.oauth.AuthCodeURL(...)` (`:107`); `Exchange` →
  `p.oauth.Exchange(...)` (`:119`). `github.go` mirrors this (`:50`).
- `internal/auth/auth.go`: `handleLogin` (`:139`) → `p.AuthCodeURL(state, nonce)`
  (`:168`); `handleCallback` (`:203`) → `p.Exchange(ctx, code, st.Nonce)` (`:232`).
  Sealed state cookie already bridges login↔callback (carries CSRF state, OIDC
  nonce, chosen provider id) — the natural place to also pin the derived callback.
- `internal/auth/config.go`: `RedirectURL` (`:79`), `expandEnv` (`:119`),
  **required non-empty** at `:211`.
- `oauth2` allows a per-call `redirect_uri` override via
  `oauth2.SetAuthURLParam("redirect_uri", url)` on **both** `AuthCodeURL` and
  `Exchange` — no need to mutate the shared `oauth2.Config`.

## Development Approach
- **Testing approach**: Regular (implement, then unit tests within the same task).
- Small focused changes; keep each task green (`go build/vet/test`) before the next.
- **CRITICAL: every task adds/updates tests** (success + error paths).
- **CRITICAL: keep this plan in sync** if scope changes.
- Backward compatibility: fixed `redirectURL` renders/behaves identically.

## Testing Strategy
- Unit tests via `httptest`:
  - derive `https://h/auth/callback` from `X-Forwarded-Host: h` + `X-Forwarded-Proto: https`;
  - fallback to `r.Host` + TLS (`r.TLS != nil` → https, else http) when no forwarded headers;
  - **login↔callback consistency**: the redirect_uri in the auth request equals the
    one used at Exchange (pinned via state cookie) even if the callback request's
    headers differ;
  - fixed `redirectURL` set → per-request override is NOT applied (today's behaviour);
  - optional allowlist: derived host not in `allowedRedirectHosts` → 400, no IdP hit.
- Provider-level: `AuthCodeURL`/`Exchange` emit the passed `redirect_uri` param.
- `go test ./...` green; no Go-resolver/network dependence in tests.

## Progress Tracking
- Mark completed items `[x]` immediately. New tasks → `➕`; blockers → `⚠️`.

## What Goes Where
- **Implementation Steps** (`[ ]`): Go code, tests, chart values, docs.
- **Post-Completion** (no checkboxes): republish chart/image; register all per-host
  callbacks in the IdP app; simplify the deploy wrapper (drop per-cluster
  `redirectURL`, keep one empty/default).

## Implementation Steps

### Task 1: Per-request redirect_uri in the Provider interface
- [x] `provider.go`: extend to `AuthCodeURL(state, nonce, redirectURL string)` and
      `Exchange(ctx, code, nonce, redirectURL string)` (empty `redirectURL` = use the
      provider's configured default — today's behaviour)
- [x] `oidc.go` / `github.go`: when `redirectURL != ""`, append
      `oauth2.SetAuthURLParam("redirect_uri", redirectURL)` to both `AuthCodeURL` and
      `Exchange`; otherwise unchanged
- [x] write tests: param present when passed, absent when empty (both providers)
- [x] run `go build ./... && go vet ./... && go test ./...`

### Task 2: Derive + pin the callback per request
- [x] `config.go`: add `auth.forwardedHostHeader` (default `X-Forwarded-Host`) and
      `auth.forwardedProtoHeader` (default `X-Forwarded-Proto`) — the header **names**
      are configurable so non-standard proxies (`Forwarded`, `X-Original-Host`, a
      cluster-specific header) can be used without code changes
- [x] `auth.go`: add `callbackURL(r)` — `redirectURL` if configured non-empty, else
      `<proto>://<host>/auth/callback` reading the **configured** host/proto headers
      (fallback `r.TLS`/`r.Host`)
- [x] `handleLogin`: compute it, **store it in the sealed state cookie**, pass to
      `AuthCodeURL`
- [x] `handleCallback`: read the pinned callback from the state cookie, pass to
      `Exchange` (guarantees login==callback redirect_uri)
- [x] `config.go`: make `RedirectURL` optional (drop the `:211` hard error); document
      empty = host-derived
- [x] write tests: derivation via default and **overridden** header names, fallback,
      state-cookie round-trip, fixed-redirectURL unchanged
- [x] run tests

### Task 3: Optional redirect-host allowlist (defence-in-depth)
- [x] `config.go`: add `auth.allowedRedirectHosts []string` (default empty = any;
      relies on the IdP's registered-callback enforcement)
- [x] `handleLogin`: in dynamic mode, if the list is non-empty and the derived host is
      not in it → `400` before contacting the IdP
- [x] write tests: allow / deny / empty-list-allows-any
- [x] run tests

### Task 4: Chart + values
- [x] `charts/portreach/values.yaml`: document `ui.auth.redirectURL: ""` = host-derived;
      add `ui.auth.allowedRedirectHosts: []`, `ui.auth.forwardedHostHeader: ""`,
      `ui.auth.forwardedProtoHeader: ""` (empty = chart/app defaults)
- [x] `configmap-ui-auth.yaml`: emit `redirectURL`, `allowedRedirectHosts`,
      `forwardedHostHeader`, `forwardedProtoHeader` only when set
- [x] verify `helm template`: empty redirectURL → config has no `redirectURL` (or empty);
      set → unchanged
- [x] `helm lint` clean

### Task 5: Docs
- [x] `docs/configuration.md` (auth): document dynamic mode, the `X-Forwarded-*`
      trust requirement, the allowlist, and the multi-hostname use case
- [x] `charts/portreach/README.md`: short note + example

### Task 6: Verify acceptance criteria
- [x] all modes pass; `go build/vet/test` green; `golangci-lint` clean
- [x] `helm lint` + `helm template` clean; chart bumped to `0.4.0` in `Chart.yaml`

## Technical Details
- Trust model: derive only from the configured forwarded headers (default
  `X-Forwarded-Host`/`X-Forwarded-Proto`, overridable via
  `auth.forwardedHostHeader`/`forwardedProtoHeader` for non-standard proxies) set by
  the ingress; document that direct (proxy-less) exposure should set a fixed
  `redirectURL` or an `allowedRedirectHosts` allowlist. Never derive from
  user-controllable fields beyond the configured forwarded headers.
- Pinning the derived callback in the sealed state cookie makes login and callback
  use the identical `redirect_uri` (OAuth requires the two to match) and blocks
  mid-flow host swapping.
- The IdP (e.g. a self-hosted GitLab) rejects any `redirect_uri` not registered for the
  app, so the worst a spoofed host can do is get rejected — never an open redirect.

## Post-Completion
*Manual / external — no checkboxes.*

- Republish chart `oci://ghcr.io/lavr/charts/portreach:0.4.0` (+ matching image).
- Register every per-host callback in the IdP OAuth app (one per cluster/vanity host).
- Deploy wrapper: drop per-cluster `redirectURL`; leave `ui.auth.redirectURL`
  empty so one shared `values.yaml` works on every cluster and hostname. List all
  ingress hosts (shared `shared.k8s` + per-cluster `<cluster>.k8s`) in
  `ui.ingress.hosts`.

## Related
- `docs/plans/2026-06-27-chart-inline-auth-secret.md` (chart-created auth Secret).
- Rollout context: per-cluster hostnames + this feature remove the last
  per-cluster auth value.
- Auth core: `docs/plans/completed/2026-06-27-ui-sso-auth.md`.
