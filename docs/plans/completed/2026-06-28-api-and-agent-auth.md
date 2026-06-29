# API bearer auth (IdP/JWKS) + agent token auth

## Overview
Make portreach safely usable by hundreds of developers/CI and lock down the agent
plane. Two boundaries, both backward compatible (unset → today's behaviour):

- **Boundary A — dev/CI → UI `/api/*`**: accept `Authorization: Bearer <token>` in
  addition to the browser session cookie. The token is an **OIDC access token (JWT)
  from a configured OIDC provider**, validated by JWKS (issuer + audience + signature
  + expiry). Browser and token requests resolve to the same `auth.Session`/`Identity`,
  so RBAC (group allowlist), audit, and rate-limit stay uniform. CI uses an IdP
  **service account** (client-credentials).
- **Boundary B — UI → agent `/check`**: a shared **bearer token** (k8s Secret) is the
  **primary trust boundary**. When configured, the agent requires
  `Authorization: Bearer <agent-token>` on `/check`; the UI sends it on every call.
  NetworkPolicy is a *best-effort, optional* second layer only (see finding #1).
- **Model**: agents are internal; developers only ever talk to the UI API. The agent
  token also protects a standalone agent (VM, no UI) called directly.

## Review findings addressed (2026-06-28)
1. **Agent token is the primary boundary, not NetworkPolicy.** The agent runs
   `hostNetwork: true` + `hostPort` by default (`values.yaml:160`,
   `daemonset-agent.yaml:33`), where NetworkPolicy is CNI-dependent and often *not*
   enforced; `networkPolicy.enabled` is `false` by default. Plan now treats the token
   as mandatory-for-isolation and NP as optional defence-in-depth, and adds an opt-in
   non-hostNetwork agent mode for environments that want NP-enforced isolation
   (Task 5), with the vantage-point trade-off documented.
2. **Bearer identity cannot bypass a provider allowlist.** A bearer token is matched
   to a *specific configured provider* (by issuer+audience); `Session.Provider` is set
   to that provider's `id` so `allowed()` (`auth.go:387`) reads the right allowlist.
   A token whose issuer/audience matches no configured provider → **401** (never a
   pass with empty groups). Fail-closed deny test required (Task 2).
3. **No false "instant revocation" claim.** JWKS-only cannot see IdP deactivation
   before `exp`. The "deactivated user denied" item is removed from acceptance and
   replaced by a documented short-TTL recommendation; optional userinfo re-check is
   an explicit out-of-scope future option (Technical Details).
4. **Scope is explicit.** API bearer v1 = OIDC/preset providers with **JWT** access
   tokens only. GitHub (OAuth2+REST, `config.go:18`) and **opaque** access tokens are
   out of scope (documented), and a GitHub-only deployment simply has no bearer path.
8. **Agent token rotation is realistic.** Adds `tokenSecretKey`, a config-checksum pod
   annotation so a chart-managed Secret change triggers a rollout, and docs that an
   external/`existingSecret` rotation needs a manual rollout (Task 5).

### Open questions — decisions baked in
- **Bearer without browser SSO is allowed.** API bearer and browser SSO are
  *independent* toggles: configuring an API entry (issuer+audience) enables bearer; configuring
  `providers` enables browser login. `Config.Enabled()` / the UI handler enable
  whichever is present (so a CI-only, headless deployment is valid). (Task 1)
- **Agent `/metrics` is gated by default under hostNetwork.** Because hostNetwork
  exposes it on the node, `/metrics` requires the agent token by default; an opt-out
  (`--metrics-public` / bind metrics to a separate address) is provided for Prometheus
  scraping, documented. (Task 3)

## Review findings addressed (round 2, 2026-06-28)
- **#R1 (bearer-only config is fully specified).** Today `Config.Enabled()`/`Validate()`
  are provider+cookie based: no providers → disabled; enabled requires `cookieKey`; each
  provider requires `clientSecret` (`config.go:230/253/300`). Task 1 now **splits browser
  config from API config**: a dedicated `api` block (`issuer` + `audience`, verifier
  built from the issuer's JWKS). In **bearer-only** mode `providers` and `cookieKey` are
  **not** required, and `clientSecret` is **not** required for the API path (JWKS
  verification needs neither). `Validate()` enforces per-mode required fields.
- **#R2 (Helm renders auth for either mode).** The chart renders/mounts auth config only
  when `ui.auth.enabled` (`configmap-ui-auth.yaml:1`, `deployment-ui.yaml:60`,
  `values.yaml:57`). Task 5 adds a **`portreach.auth.enabled` helper** =
  `ui.auth.browser.enabled` OR `ui.auth.api.enabled`, **honouring the legacy
  `ui.auth.enabled`** for back-compat, gating the ConfigMap/mount on it, and not
  iterating providers when there are none (API-only). The API config is a
  **`ui.auth.api.entries[]` list** matching the Go multi-entry model (High #2), and
  charttest covers API-only + multi-entry + legacy rendering.
- **#R3 (/metrics — single-listener scope for v1).** The agent runs one `http.Server`
  (`agent.go:124/253`); a second metrics listener would change shutdown/errors/tests/Helm
  ports+probes. **v1 scope = `--metrics-public` only** (gate `/metrics` behind the agent
  token by default, or open it with one flag); a separate metrics listener is explicitly
  deferred (not in this plan).
- **Open question — issuer+audience uniqueness.** Multiple API entries are allowed but the
  **(issuer, audience) pair must be unique** and is the key used to match a token to a
  provider/allowlist; `Validate()` rejects duplicates. (Task 1)

## Context (from discovery)
- `internal/auth`: `Authenticator` (`auth.New(cfg, opts...)`), `Config`+`LoadConfig`,
  `Config.Enabled()`/`Validate()` (provider+cookie based today: `config.go:230/253/300`),
  `(*Authenticator).Middleware` (sets `WithIdentity`, today cookie-only),
  `Session`/`Identity`, `AuditCheck`, `WithLogger`, `allowed(providerID,id)`
  (`auth.go:387`). OIDC providers build an `oidc.IDTokenVerifier` (`oidc.go`).
- `internal/cmd/ui.go` `runUI`: wraps `ui.New(disc,timeout).Handler()` as
  `authn.Middleware(auth.AuditCheck(logger, handler))`.
- `internal/ui/aggregator.go` `checkOne`: builds `GET http://<addr>/check?…` — the one
  place to add the agent `Authorization` header.
- `internal/agent/agent.go`: `New(nodeName, *Policy)`, `Handler()` (`/check`,
  `/healthz`, `/metrics`), `handleCheck`. `internal/cmd/agent.go`: `--listen/--allow/--deny`.
- Helm: `networkpolicy.yaml` (default off), `secret-ui-auth.yaml`, `deployment-ui.yaml`,
  `daemonset-agent.yaml` (`hostNetwork: true`, `hostPort`), `values.yaml:160`,
  `values.schema.json`, `internal/charttest`.
- go-oidc / x/oauth2 already vendored — **no new deps** expected.

## Development Approach
- **Testing approach**: Regular (implement, then unit tests in the same task).
- Each task ends with tests (success + error) and must pass before the next.
- **Backward compatible**: no API audience → bearer disabled (cookie only); no agent
  token → agent open (today's behaviour).
- Run `go build/vet/test ./...` + `helm lint` after each change. `gofmt` clean.

## Testing Strategy
- Hermetic `httptest`: fake an OIDC issuer (discovery + JWKS) to mint/validate JWT
  access tokens; never hit a real IdP. Reuse existing oidc/gitlab fixtures.
- Cover: valid bearer → authenticated; bad signature / wrong issuer / **wrong/absent
  audience** / expired → 401; **token whose issuer matches no configured provider →
  401 (not open)**; cookie path still works; allowlist (group) deny → 403; agent
  rejects missing/wrong token (401), accepts the right one; `/healthz` open;
  `/metrics` gated unless `--metrics-public`; UI attaches the agent token; both
  disabled paths = open (compat).

## Progress Tracking
- Mark `[x]` immediately. New tasks → `➕`; blockers → `⚠️`.

## What Goes Where
- **Implementation Steps** (`[ ]`): code, tests, helm, docs.
- **Post-Completion** (no checkboxes): IdP app/service-account registration, real
  token verification, Secret provisioning, NP verification.

## Implementation Steps

### Task 1: Accept IdP bearer tokens on the UI API (independent of browser SSO)
- [x] **split browser vs API config (#R1)**: add an `api` block to `auth.Config` — a
      list of entries `{id, issuer, audience, allowedGroups/allowedUsers}` **plus claim
      mapping**: `type`/preset (for fallbacks like GitLab `groups_direct`),
      `usernameClaim`, `groupsClaim` (defaults mirror the browser OIDC path —
      `config.go:84`, `presets.go:70`); without these, bearer RBAC breaks on access
      tokens whose group/username claims differ from the defaults (Medium #2). Required
      fields: `issuer`+`audience` only (no `clientSecret`, no `cookieKey`)
- [x] **id + pair uniqueness (High #1)**: enforce **globally unique `id`** across API
      entries **and** browser `providers` (the combined registry in Task 2 is keyed by
      `id`; a collision would bind allowlist/audit to the wrong entry), extending the
      browser-only uniqueness check (`config.go:269`); also enforce unique
      `(issuer, audience)` across API entries
- [x] redefine `Config.Enabled()` = browser-enabled **OR** api-enabled; `Validate()`
      applies browser rules (providers+cookieKey+clientSecret) only when browser is
      configured, and api rules (issuer+audience, unique pair) only when api is
      configured — so **bearer-only is valid** with no providers and no cookieKey
- [x] build an access-token verifier per API entry from its issuer
      (`oidc.NewProvider(issuer).Verifier(&oidc.Config{ClientID: audience})`, checking
      `aud`/`iss`/`exp`/sig); map claims → `Session` (username + groups) **with
      `Session.Provider` = the matched API entry's `id`** (finding #2), matched by
      `(iss, aud)`
- [x] **explicit route semantics (High #1)** in `Middleware` (`middleware.go:13` today
      redirects every non-`/auth/*`, non-`/healthz` path to the login page):
      - `/api/*`: accept bearer (if api configured) **or** cookie (if browser configured);
        on failure **401 JSON, never a redirect** (it's an API).
      - browser paths (`/`, …): accept cookie (if browser configured) or bearer (if api
        configured). On failure → **redirect to login only when browser auth is
        configured**; in **API-only mode (no browser providers) there is no login page,
        so return 401** instead of redirecting to an empty login page.
      - `/healthz`, `/auth/*`: unchanged. A token matching no configured api entry → 401
        (never `WithIdentity`).
- [x] `runUI`/handler builder: enable the bearer path whenever an API entry is
      configured, even with no browser providers
- [x] **env expansion (Low #5)**: route the new API-entry fields (`issuer`, `audience`,
      `usernameClaim`, `groupsClaim`, `allowedGroups`, `allowedUsers`) through the same
      `${ENV}` expansion the loader already does for provider fields/allowlists
      (`config.go:160`)
- [x] write tests: valid token authenticates with the right provider id; bad
      sig/issuer/audience/expired → 401; unmatched-issuer token → 401 (fail-closed);
      cookie still works; bearer disabled when unconfigured; bearer-only (no SSO) works;
      **API-only route tests**: `/api/check` without token → 401 JSON, with token → 200;
      **`/` in API-only mode → 401 (not a redirect to an empty login page)**; env-expanded
      issuer/audience/claims resolved
- [x] run tests — must pass before Task 2

### Task 2: Uniform RBAC + audit for token identities (fail-closed)
- [x] **unified allowlist lookup (High #1)**: today `allowed()` reads only
      `a.pcs[providerID]` (`auth.go:387`) — an **API-entry id is not in `a.pcs`**, so a
      bearer identity would hit an empty allowlist and, with empty global `AllowedUsers`,
      **fail open**. Refactor the lookup to resolve the allowlist for a `Session.Provider`
      from a **combined registry** (browser `pcs` **+** API entries) keyed by id; an id
      present in **neither** → **deny** (fail-closed), never default-allow
- [x] enforce that resolved group/user allowlist for bearer identities identically to
      cookie sessions (deny → 403)
- [x] `AuditCheck` emits `user`/`provider` for token calls (provider = matched id);
      add a cheap `auth_method=cookie|bearer` field
- [x] write tests: allowlisted group passes; **API-only non-member → 403** (regression
      guard for #1); token for a non-configured issuer/audience → 401 (finding #2);
      unknown `Session.Provider` id → deny; audit carries the token identity + method
- [x] run tests — must pass before Task 3

### Task 3: Agent bearer-token auth (+ /metrics gating, single listener)
- [x] `internal/cmd/agent.go`: `--auth-token`/`PORTREACH_AGENT_TOKEN`,
      `--metrics-public` (default false). **No second listener in v1 (#R3)** — keep the
      single `http.Server` (`agent.go:124`); a separate metrics bind is deferred
- [x] `internal/agent`: token set → require `Authorization: Bearer <token>` (constant-
      time compare) on `/check` **and `/metrics`** → 401 on missing/wrong; `/healthz`
      always open; `--metrics-public` re-opens `/metrics` (only) for Prometheus,
      documented as a deliberate choice
- [x] empty token → no check (backward compatible)
- [x] write tests: `/check` + `/metrics` 401 without token, 200 with; `/healthz` open;
      `--metrics-public` opens `/metrics` but `/check` stays gated; disabled = open
- [x] run tests — must pass before Task 4

### Task 4: UI sends the agent token
- [x] `internal/cmd/ui.go`: read agent token (`--agent-token`/`PORTREACH_AGENT_TOKEN`),
      thread into `ui.Server`/aggregator
- [x] `internal/ui/aggregator.go` `checkOne`: set `Authorization: Bearer <token>` when
      configured; empty → no header (compat)
- [x] write tests: aggregator attaches the header; empty token → no header
- [x] run tests — must pass before Task 5

### Task 5: Helm wiring (Secret + rotation + optional strict isolation)
- [x] **chart auth model + toggle migration (#R2 + High #2 + Medium toggle)**: add a
      named template **`portreach.auth.enabled`** = `ui.auth.browser.enabled` OR
      `ui.auth.api.enabled`, **honouring the legacy `ui.auth.enabled`** value (treat a
      bare `ui.auth.enabled: true` as browser-enabled for back-compat,
      `values.yaml:57`). Gate the auth ConfigMap (`configmap-ui-auth.yaml:1`) + mount
      (`deployment-ui.yaml:60`) on this helper, and make the ConfigMap **not iterate
      providers when there are none** (API-only must not break rendering)
- [x] **API config is a list, matching Go (High #2 + Medium schema-lag)**:
      `ui.auth.api.entries[]` of `{id, issuer, audience, type, usernameClaim, groupsClaim,
      allowedGroups, allowedUsers}` — **the same claim-mapping fields Task 1 added to the
      Go config** (without them chart users can't configure the mapping the feature
      exists for); mirror the multi-entry model with unique `(issuer,audience)`; emit each
      field into `auth.yaml` (same per-field copy pattern as the browser providers)
- [x] `values.yaml`+`values.schema.json`: the `ui.auth.api.entries[]` schema (array
      incl. `type`/`usernameClaim`/`groupsClaim`),
      `agent.auth.token` / `agent.auth.existingSecret` +
      **`agent.auth.tokenSecretKey`** (default e.g. `agent-token`); `agent.metricsPublic`
- [x] render a Secret (or reference `existingSecret`); inject `PORTREACH_AGENT_TOKEN`
      into **both** the agent DaemonSet and UI Deployment via `secretKeyRef`; add a
      **checksum/sha annotation** on both pod templates for the chart-managed Secret so
      a token change triggers a rollout (external Secret → manual rollout, documented)
- [x] **NetworkPolicy is optional/best-effort**: keep `networkPolicy.enabled` opt-in;
      document it is unreliable while `agent.network.hostNetwork: true` (the real chart
      path — `values.yaml:160`). For NP-enforced isolation, use the existing
      `agent.network.hostNetwork: false` + `agent.network.hostPort.enabled: false`,
      documenting the changed egress vantage point (pod network vs node egress)
      (kept opt-in; full prose documentation lands in Task 6)
- [x] extend `internal/charttest`: **API-only auth renders** (`portreach.auth.enabled`
      via `ui.auth.api` with browser off → ConfigMap+mount present, no provider
      iteration); **multiple `api.entries[]` render** into `auth.yaml`; legacy
      `ui.auth.enabled: true` still renders browser auth; token wired to both workloads
      with `tokenSecretKey`; checksum annotation present; NP selector when enabled;
      `helm lint`
- [x] run tests — must pass before Task 6

### Task 6: Documentation
- [x] `docs/configuration.md`: API bearer (obtain a JWT access token; CI
      client-credentials; required `aud`); **explicitly: OIDC/JWT only, GitHub &
      opaque tokens unsupported**; agent token + `tokenSecretKey`; the
      "agents internal, UI is the front door" model; `/metrics` gating + opt-out;
      **revocation/TTL note** (deactivation visible only at token expiry → use short
      access-token TTL; optional userinfo re-check is future work)
- [x] `docs/deployment.md`: Helm example wiring the shared Secret; NetworkPolicy as
      best-effort under hostNetwork + the strict non-hostNetwork mode + rollout-on-
      rotation note
- [x] `README.md`: short "API access (tokens)" note
- [x] run `go test ./...` — no regression

### Task 7: Verify acceptance criteria
- [x] both boundaries enforced; both default-off paths backward compatible
- [x] edge cases: expired/forged token, wrong/absent audience, **unmatched-issuer →
      401**, missing agent token, `/metrics` gated, `/healthz` open
- [x] `go test ./... -v`, `go vet ./...`, `helm lint` clean; `internal/auth` ≥ 80%

### Task 8: [Final] Knowledge
- [x] note the dual cookie-or-bearer model, agent token, and `/metrics`/NP caveats in
      README/AGENTS.md

*Note: ralphex auto-moves completed plans to `docs/plans/completed/`.*

## Technical Details
- **Access-token validation**: JWT via the provider JWKS, checking `iss`, `aud`
  (= configured API audience), `exp`, signature. JWT access tokens (Keycloak/Entra/
  GitLab) work directly. **Opaque** tokens need introspection — out of scope v1.
  GitHub has no OIDC/JWKS path — no bearer for GitHub-only setups (documented).
- **Provider binding (finding #2)**: a bearer is bound to a single configured provider
  by `iss`+`aud`; `Session.Provider` = that id so `allowed()` uses the correct
  allowlist; an unmatched token is rejected, never default-allowed.
- **Revocation (finding #3)**: JWKS validation is offline → IdP deactivation is
  invisible until `exp`. Mitigate with short access-token TTL. An optional per-call
  userinfo/introspection re-check (adds latency + IdP dependency) is a future option,
  not v1.
- **Isolation (finding #1)**: the agent token is the enforced boundary. NetworkPolicy
  is best-effort and frequently bypassed for `hostNetwork` pods; offered only as an
  optional layer, with a non-hostNetwork agent mode for strict NP isolation.
- **Agent token (finding #8)**: shared secret, constant-time compare; same value to UI
  + agents from one Secret keyed by `tokenSecretKey`; checksum annotation rolls pods on
  change; external Secret rotation = manual rollout.
- **No new dependencies** (reuse go-oidc/oauth2).

## Post-Completion
*Manual / external — no checkboxes.*
- Register an IdP API client + CI service account (client-credentials) with the
  expected `aud`; verify a real JWT authenticates. (Note: deactivation only takes
  effect at token expiry — set a short TTL.)
- Provision the agent-token Secret (`openssl rand -hex 32`) under `tokenSecretKey`.
- If relying on NetworkPolicy, verify it is actually enforced for the agent in your
  CNI (often not, under hostNetwork) — otherwise rely on the token.
