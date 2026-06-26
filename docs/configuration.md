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

Environment:

| Variable | Description |
|----------|-------------|
| `NODE_NAME` | point name reported in `/check` responses; falls back to the OS hostname |

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

## `portreach ui`

The aggregator and web form. Discovers agents, fans out one target check to all
of them, and renders a per-point table.

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--listen` | | `:8080` | address to listen on |
| `--agents` | `PORTREACH_AGENTS` | | comma-separated static agent list `host[:port]` |
| `--agents-dns` | `PORTREACH_AGENTS_DNS` | | headless service name to resolve agents from |
| `--agent-port` | `PORTREACH_AGENT_PORT` | `8732` | agent port for DNS-discovered and port-less agents |
| `--timeout` | | `8s` | overall fan-out budget per check |
| `--auth-config` | `PORTREACH_AUTH_CONFIG` | | path to the SSO auth config YAML; empty = auth disabled |

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

## Authentication (optional SSO)

The UI can be put behind corporate single sign-on with **multiple providers at
once** — GitHub (github.com / GitHub Enterprise) and GitLab (gitlab.com /
self-hosted). It is **disabled by default**: with no config (or a config with no
providers) the UI behaves exactly as before — no login, fully backward
compatible.

Enable it by pointing `--auth-config` (or `PORTREACH_AUTH_CONFIG`) at a YAML
file:

```yaml
auth:
  # OAuth callback URL — must match each provider's registered callback.
  redirectURL: https://portreach.corp/auth/callback
  # AES-256 session-cookie key: 32 bytes, hex or base64. Never hardcode it —
  # reference an env var so it stays out of the file (see ${ENV} below).
  cookieKey: ${PORTREACH_AUTH_COOKIE_KEY}
  # Optional global user-login allowlist. Empty = any authenticated user.
  allowedUsers: []
  providers:
    - id: corp-gitlab            # unique, non-empty; used in the callback URL
      type: gitlab               # github | gitlab
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

### Registering the OAuth apps

- **GitHub**: `Settings → Developer settings → OAuth Apps → New`. Set the
  *Authorization callback URL* to your `redirectURL`. Copy the client ID/secret.
- **GitLab**: `Preferences → Applications` (or group/instance application). Set
  the *Redirect URI* to your `redirectURL`, scopes `openid profile email`, and
  copy the application ID (clientID) + secret.

The callback is the single `redirectURL` for all providers; the active provider
is recovered from the sealed state cookie, so you do not register a per-provider
callback path.

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
actor is recorded as `user=anonymous` (empty `provider`).

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
