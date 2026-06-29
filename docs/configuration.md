# Configuration

`portreach` is a single binary with two subcommands. Each is configured by
flags; the UI also reads a few environment variables (flags win over env).

```
portreach <command> [flags]

Commands:
  agent      run the probe HTTP server (one per point)
  ui         run the aggregator + web form
  version    print the version
  help       show this help
```

## `portreach agent`

The probe server. Run one per point you want to check from.

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8732` | address to listen on |
| `--allow` | *(empty)* | comma-separated allow CIDR list (empty = allow all) |
| `--deny` | *(empty)* | comma-separated deny CIDR list (takes precedence over allow) |
| `--auth-token` | *(empty)* | shared bearer token required on `/check` and `/metrics`; empty = open |
| `--metrics-public` | `false` | leave `/metrics` open even when a token is set (`/check` stays gated) |

Environment:

| Variable | Description |
|----------|-------------|
| `NODE_NAME` | point name reported in `/check` responses; falls back to the OS hostname |
| `PORTREACH_AGENT_TOKEN` | default for `--auth-token` |
| `PORTREACH_AGENT_METRICS_PUBLIC` | default for `--metrics-public` |

Endpoints:

- `GET /check?host=&port=&proto=tcp&timeout=5s` → JSON probe result with a
  `node` field. Returns `200` even when `tcp.ok` is `false` (the probe ran),
  `400` on bad input, `403` when the target is denied by policy.
- `GET /healthz` → `{"status":"ok","node":"..."}`.
- `GET /metrics` → Prometheus text: `portreach_checks_total{result="ok|fail|denied|bad_request"}`.

`proto` is `tcp` only for now; `timeout` is a Go duration (default `5s`, capped
at `30s` — larger values are silently clamped; non-positive values fall back to
the default).

### Target policy (SSRF mitigation)

The agent dials arbitrary hosts on request, so it can be used as an SSRF proxy.
Restrict it with CIDR lists:

```sh
# only allow probing the internal /8, but never the metadata endpoint
portreach agent --allow 10.0.0.0/8 --deny 169.254.169.254/32
```

- Empty `--allow` means allow-all (subject to `--deny`).
- `--deny` always wins over `--allow`.
- When a policy is set, the host is resolved **once** and **every** resolved IP
  must pass, or the request is denied with `403`. The probe then dials that
  vetted IP directly rather than re-resolving the name, so a DNS-rebinding
  attacker cannot swing the dial to an internal address after the check.
- With a policy set, a host that fails to resolve is denied (`403`, fail closed),
  since its dial target cannot be verified.
- In policy mode the DNS report contains only the vetted resolved IPs (the exact
  addresses dialed); `cname` is not reported, since capturing it would require a
  second lookup that could disagree with the vetted set.

### Agent token (Boundary B — the primary isolation boundary)

Agents are **internal**: developers only ever talk to the UI, and the UI fans
out to the agents (see ["agents internal, UI is the front door"](#api-bearer-tokens-boundary-a)).
Because the chart runs the agent on `hostNetwork: true` with a `hostPort` by
default, its `/check` endpoint is reachable on the node IP, where NetworkPolicy
is CNI-dependent and frequently **not** enforced. A shared bearer token — not
NetworkPolicy — is therefore the enforced trust boundary.

Set `--auth-token` (or `PORTREACH_AGENT_TOKEN`) on the agent and the matching
`--agent-token`/`PORTREACH_AGENT_TOKEN` on the UI:

```sh
TOKEN=$(openssl rand -hex 32)
portreach agent --listen :8732 --auth-token "$TOKEN"
portreach ui --agents agent-a:8732 --agent-token "$TOKEN"
```

- When set, the agent requires `Authorization: Bearer <token>` on `/check`
  (and `/metrics`, see below) — missing/wrong → `401`. The compare is
  constant-time. The UI attaches the header on every probe.
- **Empty token → open** (today's behaviour, backward compatible). Both sides
  must carry the same value; a mismatch fails closed with `401`.
- The same token also protects a **standalone agent** (a VM with no UI) called
  directly.

#### `/metrics` gating

Because `hostNetwork` exposes `/metrics` on the node, it is gated behind the
agent token **by default** (same `401` as `/check`). For Prometheus scraping,
either give the scraper the token, or re-open `/metrics` (only) with
`--metrics-public` / `PORTREACH_AGENT_METRICS_PUBLIC=true` — a deliberate
opt-out that leaves `/check` gated. `/healthz` is always open so liveness/
readiness probes keep working.

## `portreach ui`

The aggregator and web form. Discovers agents, fans out one target check to all
of them, and renders a per-point table. By default the check reaches every
discovered agent; `--max-agents-per-check` optionally bounds the blast radius,
and the `/api/check` response then carries explicit `discovered` / `queried` /
`dropped` counts (with `summary.total` = queried) so partial coverage is never
silent.

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--listen` | | `:8080` | address to listen on |
| `--agents` | `PORTREACH_AGENTS` | | comma-separated static agent list `host[:port]` |
| `--agents-dns` | `PORTREACH_AGENTS_DNS` | | headless service name to resolve agents from |
| `--agent-port` | `PORTREACH_AGENT_PORT` | `8732` | agent port for DNS-discovered and port-less agents |
| `--timeout` | | `8s` | overall fan-out budget per check |
| `--agent-token` | `PORTREACH_AGENT_TOKEN` | | shared bearer token sent to agents on `/check`; empty = none ([Boundary B](#agent-token-boundary-b--the-primary-isolation-boundary)) |
| `--max-agents-per-check` | `PORTREACH_MAX_AGENTS_PER_CHECK` | `0` | cap how many discovered agents one check queries; `0` = unlimited (every node). Over the cap, agents are selected deterministically by address and the rest are reported as `dropped` |
| `--max-concurrent-fanout` | `PORTREACH_MAX_CONCURRENT_FANOUT` | `0` | bound concurrent per-check agent requests; `0` = unlimited (a goroutine per agent) |
| `--auth-config` | `PORTREACH_AUTH_CONFIG` | | path to the SSO auth config YAML; empty = auth disabled |
| `--ui-title` | `PORTREACH_UI_TITLE` | localized heading | HTML page heading; explicitly empty suppresses `<h1>` |
| `--ui-description` | `PORTREACH_UI_DESCRIPTION` | | trusted HTML block under the heading |
| `--ui-footer` | `PORTREACH_UI_FOOTER` | | trusted HTML footer block |
| `--login-title` | `PORTREACH_LOGIN_TITLE` | localized login/denied title | HTML browser title for login and denied pages |
| `--login-header` | `PORTREACH_LOGIN_HEADER` | localized login/denied heading | HTML login/denied heading; explicitly empty suppresses `<h1>` |
| `--login-footer` | `PORTREACH_LOGIN_FOOTER` | | trusted HTML footer block on the login page |

Branding tri-state: unset keeps the localized default; explicitly set to `""`
suppresses headings (browser tab titles fall back to a localized non-blank
value); any non-empty value is rendered. Branding values are operator-trusted
HTML and are rendered unescaped — do not let untrusted users control them.
After flag/env precedence is resolved, branding strings expand process
environment references with shell syntax: `${VAR}` and `$VAR`; undefined vars
expand to empty, and write `$$` for a literal dollar. Expansion happens once at
startup and env values may themselves contain HTML.

Provide **either** `--agents` (static) **or** `--agents-dns` (Kubernetes
headless service); supplying both is an error. Port-less entries in `--agents`
get `--agent-port` appended.

Endpoints:

- `GET /` → HTML form; submitting it re-renders the page with the result table.
- `GET /api/check?host=&port=&proto=&timeout=` → aggregated JSON
  (`{target, agents:[...], summary:{ok,total}}`).
- `GET /healthz` → `{"status":"ok"}`.

A single slow or unreachable agent does not fail the whole request: its row
carries an `error` and the rest still report. The per-check budget is bounded by
`--timeout`. The `timeout` query param is clamped to stay safely under the
budget (roughly `--timeout − 1s`) so each agent reports its own per-node timeout
result instead of a generic UI transport error.

## Discovery examples

Static list (Docker / VMs):

```sh
portreach ui --agents agent1:8732,agent2:8732,agent3
# or
PORTREACH_AGENTS=agent1:8732,agent2:8732 portreach ui
```

DNS (Kubernetes headless service):

```sh
portreach ui --agents-dns portreach-agent.default.svc.cluster.local --agent-port 8732
```

The UI resolves the A-records of the service name and probes each `ip:agent-port`.
The point name comes from each agent's own `/check` response (`NODE_NAME`), not
from DNS.

On clusters whose DNS domain is **not** `cluster.local`, an absolute name like
`portreach-agent.default.svc.cluster.local` resolves to NXDOMAIN. Prefer a
search-domain-relative name (`portreach-agent.default.svc`, 2 dots < `ndots:5`)
so the Go resolver appends the cluster's real search domains. The Helm chart
builds this for you via `ui.agentDiscovery.mode` (default `relative`) — see
[`deployment.md`](deployment.md#agent-discovery-cluster-domain-portability).

## Authentication (optional SSO)

The UI can be put behind corporate single sign-on with **multiple providers at
once** — GitHub (github.com / GitHub Enterprise) plus **any standards-compliant
OpenID Connect IdP**, either through the generic `oidc` type or a named preset
(`gitlab`, `google`, `entra`, `okta`, `keycloak`). It is **disabled by default**:
with no config (or a config with no providers) the UI behaves exactly as before —
no login, fully backward compatible.

Provider `type`s:

| `type` | Protocol | Notes |
| --- | --- | --- |
| `github` | OAuth2 + REST | github.com / Enterprise; orgs via `/user/orgs`. No OIDC login. |
| `oidc` | OpenID Connect | Generic — set `issuer`; works with Keycloak, Authentik, Dex, Zitadel, Okta, Auth0, Entra, Google, … |
| `gitlab` | OIDC preset | Issuer `baseURL` or `https://gitlab.com`; groups claim `groups`. |
| `google` | OIDC preset | Issuer `https://accounts.google.com`; username claim `email`; optional `hostedDomain`. |
| `entra` | OIDC preset | Issuer `https://login.microsoftonline.com/<tenant>/v2.0` from `baseURL`. |
| `okta` | OIDC preset | Issuer = `baseURL` (org issuer URL). |
| `keycloak` | OIDC preset | Issuer = `baseURL` (realm issuer URL). |

A **preset is just defaults** (issuer template, scopes, claim mapping, display
name) layered over the generic `oidc` provider; any explicit field below
overrides the preset.

Enable it by pointing `--auth-config` (or `PORTREACH_AUTH_CONFIG`) at a YAML
file:

```yaml
auth:
  # OAuth callback URL — must match each provider's registered callback. Leave
  # empty for host-derived mode (one deploy, many hostnames — see below).
  redirectURL: https://portreach.corp/auth/callback
  # AES-256 session-cookie key: 32 bytes, hex or base64. Never hardcode it —
  # reference an env var so it stays out of the file (see ${ENV} below).
  cookieKey: ${PORTREACH_AUTH_COOKIE_KEY}
  # Optional global user-login allowlist. Empty = any authenticated user.
  allowedUsers: []
  providers:
    - id: corp-gitlab            # unique, non-empty; used in the callback URL
      type: gitlab               # github | oidc | gitlab|google|entra|okta|keycloak
      displayName: "Corporate GitLab"   # optional; button label, defaults per type
      baseURL: https://gitlab.corp      # optional; self-hosted/Enterprise base
      clientID: abc
      clientSecret: ${GITLAB_SECRET}    # reference an env var, never inline
      allowedGroups: [infra, sre]       # OIDC groups claim; empty = any
    - id: github
      type: github
      displayName: "GitHub"
      clientID: def
      clientSecret: ${GITHUB_SECRET}
      allowedOrgs: [myorg]              # GitHub org logins; empty = any
```

What gets protected:

- **Protected**: `/` (the form) and `/api/check`.
- **Public**: `/healthz` (so Kubernetes probes keep working).
- **Auth endpoints**: `GET /auth/login[?provider=<id>]`, `GET /auth/callback`,
  `GET|POST /auth/logout`.

Login UX: the login page **always lists one button per provider** — even with a
single provider there is no silent auto-redirect. The button label is the
provider `displayName`, or a localized `Sign in with <type>` when unset.

Flow: standard OAuth authorization-code. A short-lived sealed cookie
(`portreach_oauth_state`) carries the CSRF `state`, the OIDC `nonce` and the
chosen provider id; on callback the session is stored in a sealed
(AES-256-GCM) cookie (`portreach_session`, `HttpOnly; Secure; SameSite=Lax`)
carrying the user + provider — stateless, no server-side store.

Access control (per request, after a successful exchange):

- if the provider lists no `allowedOrgs`/`allowedGroups` **and** `allowedUsers`
  is empty → any authenticated user is allowed;
- otherwise the user passes if they are in `allowedUsers`, **or** any of their
  GitHub orgs (`/user/orgs`) is in that provider's `allowedOrgs`, **or** any of
  their GitLab `groups` claim is in that provider's `allowedGroups`;
- else the callback returns a `403` denied page.

> **Security caveat — `allowedUsers` is global, matched by login name only.**
> An entry in `allowedUsers` is not bound to a specific provider, so it grants
> access to anyone presenting that login on **any** configured provider. If one
> of your providers is a public instance (`github.com`, `gitlab.com`) where
> strangers can register arbitrary usernames, do **not** rely on `allowedUsers`
> alone — an attacker who registers an allow-listed name on the public provider
> would gain access. With a public provider in the mix, gate access with the
> per-provider `allowedOrgs`/`allowedGroups` lists instead, and reserve
> `allowedUsers` for providers whose usernames you control (e.g. a private
> GitHub Enterprise / self-hosted GitLab).

### `${ENV}` interpolation

Every string field (including provider fields and `allowedUsers` entries) is
expanded for `${NAME}` references against the process environment before use —
unset vars expand to empty. Keep secrets (`cookieKey`, each `clientSecret`) out
of the file by referencing env vars, and inject those from your secret store.

### Cookie key

`cookieKey` must decode (hex **or** base64) to exactly 32 bytes (AES-256).
Generate one with:

```sh
openssl rand -hex 32        # 64 hex chars
# or
openssl rand -base64 32     # base64
```

Set it via the referenced env var (e.g. `PORTREACH_AUTH_COOKIE_KEY`). Rotating
the key invalidates all existing sessions.

### Provider base URLs (self-hosted / Enterprise)

`baseURL` defaults to `https://github.com` / `https://gitlab.com`. For
self-hosted or GitHub Enterprise, set it to the corporate base:

- GitHub Enterprise → OAuth at `<base>/login/oauth/*`, API at `<base>/api/v3`
  (github.com uses `api.github.com`). Scopes: `read:org read:user`.
- GitLab self-hosted → OIDC issuer is `<base>` (discovery at
  `<base>/.well-known/openid-configuration`). Scopes: `openid profile email`.

### Generic OIDC (`type: oidc`) and presets

The `oidc` type works with any standards-compliant OpenID Connect IdP. It
discovers endpoints from the `issuer` (`<issuer>/.well-known/openid-configuration`),
verifies the `id_token` (signature + nonce) and maps claims to a portreach
identity. OIDC fields (all optional except `issuer` for `type: oidc`):

| Field | Default | Purpose |
| --- | --- | --- |
| `issuer` | — (required for `oidc`) | Discovery base URL. Presets derive it from `baseURL`/built-in. |
| `scopes` | `[openid, profile, email]` | OAuth2 scopes requested. |
| `usernameClaim` | `preferred_username`, then `sub` | id_token claim → login. |
| `groupsClaim` | `groups` | id_token claim → groups (matched against `allowedGroups`). |
| `hostedDomain` | — | Google Workspace `hd` restriction (see Google below). |

The named presets set those defaults so a minimal config is enough:

```yaml
providers:
  # Generic OIDC — Keycloak, Authentik, Dex, Zitadel, Auth0, …
  - id: keycloak
    type: oidc
    displayName: "Corporate SSO"
    issuer: https://keycloak.corp/realms/main
    clientID: portreach
    clientSecret: ${OIDC_SECRET}
    groupsClaim: groups          # already the default; override if your IdP differs
    allowedGroups: [sre, infra]

  # Okta / Keycloak presets: issuer = baseURL
  - id: okta
    type: okta
    baseURL: https://acme.okta.com   # your Okta org issuer URL
    clientID: ${OKTA_CLIENT_ID}
    clientSecret: ${OKTA_SECRET}
    allowedGroups: [engineering]

  # Entra ID (Azure AD): issuer = login.microsoftonline.com/<tenant>/v2.0
  - id: entra
    type: entra
    baseURL: <tenant-id>          # tenant id, or a full issuer URL
    clientID: ${ENTRA_CLIENT_ID}
    clientSecret: ${ENTRA_SECRET}
    allowedGroups: ["<group-object-id>"]

  # Google Workspace
  - id: google
    type: google
    clientID: ${GOOGLE_CLIENT_ID}
    clientSecret: ${GOOGLE_SECRET}
    hostedDomain: corp.com        # only this Workspace domain may sign in
```

**Per-IdP setup notes**

- **Keycloak / Authentik / Dex / Zitadel** — use `type: oidc` with the realm/
  application issuer URL. Add a *groups* mapper to the ID token so the `groups`
  claim is emitted, then list realm/group names in `allowedGroups`.
- **Okta** — `type: okta`, `baseURL` = your org issuer (`https://<org>.okta.com`,
  or a custom authorization-server issuer). Add a `groups` claim to the ID token.
- **Auth0** — `type: oidc`, `issuer: https://<tenant>.auth0.com/`. Auth0 does not
  emit `groups` by default; add a custom claim via an Action/Rule and point
  `groupsClaim` at it.
- **Entra ID (Azure AD)** — `type: entra`, `baseURL` = your **tenant id** (the
  issuer becomes `https://login.microsoftonline.com/<tenant>/v2.0`). Entra's
  `groups` claim carries **group *object IDs***, not names — list those GUIDs in
  `allowedGroups`. The app registration must be configured to **emit the groups
  claim** (Token configuration → Add groups claim), or no groups arrive.
- **Google Workspace** — `type: google`. Google issues **no group claim**, so
  gate access with `hostedDomain` and/or the global `allowedUsers` (emails); the
  username claim is `email`. `hostedDomain` (`hd`) is sent on the auth request and
  re-verified against the `hd` claim on callback — a user from another domain is
  rejected with `403`. `allowedGroups` has no effect for Google.

### Registering the OAuth apps

- **GitHub**: `Settings → Developer settings → OAuth Apps → New`. Set the
  *Authorization callback URL* to your `redirectURL`. Copy the client ID/secret.
- **GitLab**: `Preferences → Applications` (or group/instance application). Set
  the *Redirect URI* to your `redirectURL`, scopes `openid profile email`, and
  copy the application ID (clientID) + secret.
- **OIDC IdPs (Keycloak, Okta, Auth0, Entra, Google, …)**: register a *Web /
  confidential* OAuth client, set the *Redirect URI* to your `redirectURL`,
  request scopes `openid profile email`, and copy the client ID + secret. See the
  per-IdP setup notes above for issuer/claim specifics.

The callback is the single `redirectURL` for all providers; the active provider
is recovered from the sealed state cookie, so you do not register a per-provider
callback path.

### Host-derived callback (one deploy, many hostnames)

By default `redirectURL` is a single fixed value, so one deployment can only
authenticate on one hostname. **Leave `redirectURL` empty** to switch to
*host-derived mode*: the `redirect_uri` is computed **per request** from the
incoming host — `https://<X-Forwarded-Host>/auth/callback` (scheme from
`X-Forwarded-Proto`, falling back to the request `Host` and the connection's TLS
state). One deployment then works across every ingress hostname you point at it
(e.g. a per-cluster `portreach.cluster-one.k8s` **and** a shared
`portreach.shared.k8s`) with no per-cluster auth config.

```yaml
auth:
  redirectURL: ""                 # empty → host-derived
  # Optional: restrict the derived host to a known set (defence-in-depth).
  allowedRedirectHosts: [portreach.cluster-one.k8s, portreach.shared.k8s]
  # Optional: override the trusted forwarded-header names (defaults shown).
  forwardedHostHeader: X-Forwarded-Host
  forwardedProtoHeader: X-Forwarded-Proto
```

How it stays safe:

- **The IdP only honours registered callbacks.** Register *every* per-host
  `https://<host>/auth/callback` in the OAuth app; a spoofed/unknown host is
  rejected by the IdP, never redirected to.
- **The derived callback is pinned in the sealed state cookie** at login and
  replayed at callback, so it is identical on both legs (OAuth requires the two
  `redirect_uri`s to match) and cannot be swapped mid-flow.
- **Trust the forwarded headers only.** The host/scheme are read **only** from
  the configured forwarded headers, which your ingress/reverse-proxy must set
  (and must strip from client input). If portreach is exposed **directly**
  (no proxy), set a fixed `redirectURL` or an `allowedRedirectHosts` allowlist —
  do not run host-derived mode open to the internet without one.

### Cookie `Secure` attribute (http deployments)

Browsers drop `Secure` cookies sent over plain **http**, so a hard-coded
`Secure` flag breaks the login flow on an http-only deployment (the state cookie
is never stored and the callback then fails CSRF validation). `auth.cookieSecure`
controls the attribute on both auth cookies (the OAuth state cookie and the
session cookie):

| `cookieSecure` | Behaviour |
| --- | --- |
| `auto` (default, empty = auto) | `Secure` only when the request is https. Works over **both** http and https; secure whenever it can be. |
| `always` | `Secure` unconditionally (require https). |
| `never` | never `Secure` (deliberate http-only). |

The scheme is detected exactly like the host-derived callback — from the
configured `forwardedProtoHeader` (default `X-Forwarded-Proto`), falling back to
the connection's TLS state — so the cookie's `Secure` flag and the derived
`redirect_uri` scheme always agree (http callback ⇒ non-secure cookie; https ⇒
secure).

> **Security caveat.** Over http the session cookie travels in clear text —
> acceptable on a trusted internal network, **not** on the public internet. Keep
> `auto` (or `always`) and front the service with TLS for any internet-facing
> deployment; reserve `never` for deliberately http-only, trusted setups.

### Audit logging (for security / ИБ)

When started, the UI emits structured `log/slog` **JSON** audit events to
stdout — ready to ingest into an ELK/Loki pipeline. Two event types:

```json
{"level":"INFO","msg":"audit","event":"login","user":"alice","provider":"github","result":"ok","remote":"10.0.0.7:51234"}
{"level":"INFO","msg":"audit","event":"check","user":"alice","provider":"github","target":"db:5432/tcp","remote":"10.0.0.7:51234"}
```

- `event=login` — emitted from `/auth/callback`: `user`, `provider`, `result`
  (`ok`|`denied`), `remote`.
- `event=check` — emitted for every `/api/check` and for `/` when a target is
  submitted: `user`, `provider`, `target` (`host:port/proto`), `remote`.

Check events are logged **whether or not auth is enabled**; with auth off the
actor is recorded as `user=anonymous` (empty `provider`). Token (bearer) calls
add an `auth_method=bearer` field; cookie sessions use `auth_method=cookie`.

## API bearer tokens (Boundary A)

The model is **agents internal, the UI is the front door**: humans and CI talk
only to the UI's `/api/*`, never to the agents. Browser SSO covers humans; for
**dev/CI automation** the UI also accepts an `Authorization: Bearer <token>` on
`/api/*`, where the token is an **OIDC access token (JWT)** issued by a
configured IdP. CI authenticates as an IdP **service account**
(client-credentials grant) and never needs a browser.

A bearer request and a browser session resolve to the **same** identity, so the
group allowlist (RBAC), audit log, and rate-limits apply uniformly. The bearer
path is **independent of browser SSO** and **disabled by default**: configure at
least one `api` entry to enable it; with none, `/api/*` stays cookie-only (or
fully open if no auth at all).

> **Scope — OIDC/JWT only.** v1 validates **JWT** access tokens offline via the
> issuer's JWKS. **GitHub** (OAuth2 + REST, no OIDC/JWKS) and **opaque** access
> tokens are **unsupported** — a GitHub-only deployment simply has no bearer
> path. Use an OIDC IdP (Keycloak, Entra, GitLab, Okta, Auth0, …) that issues
> JWT access tokens.

Add an `api:` list to the same auth-config YAML (it sits next to `providers:`):

```yaml
auth:
  # api entries enable the bearer path; no cookieKey / providers are required if
  # you only want bearer (a headless, CI-only deployment is valid).
  api:
    - id: ci                                  # globally unique across api + providers
      issuer: https://keycloak.corp/realms/main   # discovery base for JWKS
      audience: portreach                     # required `aud` the token must carry
      type: ""                                # optional preset (e.g. gitlab) for claim fallbacks
      usernameClaim: ""                       # default preferred_username, then sub
      groupsClaim: ""                         # default groups
      allowedGroups: [ci, sre]                # per-entry group allowlist; empty = any authenticated
      allowedUsers: []                        # per-entry user allowlist
```

How a token is validated and bound:

- The token is matched to an entry by its **`(issuer, audience)` pair** — both
  required, and the pair must be **unique** across entries. `id` must be unique
  across **both** `api` entries and browser `providers`.
- The JWT is verified against the issuer's JWKS — **signature + `iss` + `aud`
  (= `audience`) + `exp`**. Bad signature / wrong issuer / wrong-or-absent
  audience / expired → **401**.
- A token whose issuer+audience matches **no** configured entry → **401**, never
  a pass with an empty allowlist (**fail closed**).
- The matched entry's `id` becomes the session provider, so the allowlist lookup
  reads **that entry's** `allowedGroups`/`allowedUsers` (plus the global
  `allowedUsers`). A non-member → **403**, exactly like a denied browser login.
- Claims map to the identity via `usernameClaim`/`groupsClaim` (defaults mirror
  the browser OIDC path; a named `type` pulls its preset's claim fallbacks).
- All `api`-entry string fields go through the same `${ENV}` expansion as the
  rest of the config.

Route semantics: on `/api/*`, an auth failure is always a **`401` JSON**
response (never a redirect to a login page). On browser paths, a failure
redirects to the login page **only when browser SSO is configured**; in
**API-only mode** (no `providers`) there is no login page, so `/` also returns
`401`.

### Revocation and token TTL

JWKS validation is **offline**: portreach checks the signature and `exp` but
cannot see an IdP-side **deactivation** before the token expires. There is no
instant-revocation guarantee. Mitigate by configuring a **short access-token
TTL** at the IdP so a deactivated principal loses access quickly. An optional
per-call userinfo/introspection re-check (adds latency and a hard IdP
dependency) is **future work**, not in v1.

## Localization (i18n)

The whole UI — the form/results page and the auth pages (login chooser, denied)
— is localized. The interface language is chosen from the browser's
`Accept-Language` header via a `golang.org/x/text` matcher over the shipped
locales, defaulting to **English**. Missing or unknown languages fall back to
English; a key missing from the selected catalog falls back to English, then to
the key itself. The chosen language also sets `<html lang>`.

Shipped locales: **en** (default) and **ru**. No cookie or query parameter — the
language follows the browser, so an `Accept-Language: ru` (or `ru-RU`) request
renders Russian, anything else English.

### Adding a locale

Translations are embedded JSON catalogs in `internal/i18n/locales/`:

1. Copy `internal/i18n/locales/en.json` to `internal/i18n/locales/<lang>.json`
   and translate every value (keep the keys).
2. In `internal/i18n/i18n.go`, register the new tag: append it to `supported`
   (after `language.English`, which must stay first as the default) and add the
   `tag → "<lang>.json"` entry to `localeFiles`.
3. Rebuild — catalogs are embedded via `//go:embed locales/*.json`. The i18n
   tests assert every English key exists in the other catalogs, so a missing
   translation fails the test suite.
