# UI SSO Authentication (multi-provider GitHub / GitLab) + i18n

## Overview
- Add optional SSO authentication to the **UI server** (`internal/ui`) so the
  human-facing endpoints can be put behind a corporate login.
- **Multiple providers** at once: GitHub (github.com / GitHub Enterprise) and
  GitLab (gitlab.com / self-hosted), each configured independently.
- Protects `/` and `/api/check`; leaves `/healthz` open (k8s probes). Adds
  `/auth/login`, `/auth/callback`, `/auth/logout`.
- **Login page always shows a button per provider** — even with a single
  provider (no silent auto-redirect). Button label = provider `displayName` when
  set, else a localized `Sign in with <type>`.
- Authorization-code flow; session in a sealed (AES-GCM) cookie carrying
  `user` + `provider` — stateless, no server-side store.
- **Disabled by default**: no providers configured → middleware is a pass-through,
  existing deployments unaffected (backward compatible).
- Access control: optional allowlist per provider by GitHub org / GitLab group,
  plus an optional global user-login allowlist. Empty = any authenticated user.
- **Audit logging for security (ИБ)**: structured `log/slog` events for every
  login and every reachability check — `who` (user+provider) ran `what` check
  from `where` (remote addr). When auth is off, `user=anonymous`.
- **i18n across the whole UI**: interface language is chosen from the browser's
  `Accept-Language` header (default **en**), shipping **en + ru** at start. Covers
  both the auth pages (login chooser, denied) and the existing form/results page.
- The **agent** endpoints (`internal/agent`) are intentionally untouched — they
  are internal cluster traffic, not human-facing.

## Context (from discovery)
- **UI routes** in `internal/ui/server.go` `Server.Handler()`: `/` (`handleIndex`,
  server-rendered form, `internal/ui/web.go`), `/api/check` (`handleAPICheck`,
  JSON), `/healthz`. Form params: `host`, `port`, `proto`, `timeout`.
- **UI command** `internal/cmd/ui.go` `runUI`: config = flags + `PORTREACH_*` env;
  builds `ui.New(disc, timeout)`, wraps in `http.Server{ReadHeaderTimeout}` via
  `serveWithShutdown`.
- **No external deps yet** — `go.mod` pure stdlib (`go 1.25`). This plan adds the
  first deps: `golang.org/x/oauth2`, `github.com/coreos/go-oidc/v3`,
  `golang.org/x/text` (i18n), `gopkg.in/yaml.v3`.
- **UI is English-only today** (`internal/ui/web/index.html`, `lang="en"`, no
  i18n) — this plan introduces the first translation layer; all current English
  strings become catalog keys.
- **Helm**: `charts/portreach/templates/deployment-ui.yaml` runs `ui` with args +
  env, supports `.Values.ui.extraEnv`. `values.yaml` has a `ui:` block.
- **Docs**: `docs/configuration.md`, `docs/deployment.md`, `README.md`.
- Tests live next to code as `*_test.go` using `net/http/httptest` (hermetic).

## Development Approach
- **Testing approach**: Regular (implement, then unit tests within the same task).
- Complete each task fully before the next; small focused changes.
- **CRITICAL: every task MUST include new/updated tests** — required checklist
  items, success + error paths.
- **CRITICAL: all tests must pass before starting the next task.**
- **CRITICAL: keep this plan in sync** if scope changes during implementation.
- Run `go build ./...`, `go vet ./...`, `go test ./...` after each change.
- Maintain backward compatibility — auth off = behaviour identical to today
  (UI still works; only the default language label rendering changes, defaulting
  to identical English copy).

## Testing Strategy
- **Unit tests** required every task. Use `httptest` to fake provider endpoints
  (GitHub REST, GitLab OIDC discovery/userinfo) — hermetic, no real network.
- **E2E**: no browser-based e2e harness exists; Go HTTP handler tests with
  `httptest.Server` are the integration layer. No new e2e framework.
- Cover: `Accept-Language` matching (en default, ru selected, unknown → en),
  ru/en rendering of form + login pages, YAML load + `${ENV}` interpolation,
  cookie seal/open roundtrip + tamper, state/nonce CSRF rejection, per-provider
  allowlist allow/deny, login page lists every provider (incl. single provider),
  disabled pass-through, `/healthz` public, unauthenticated redirect,
  audit-log event emission.

## Progress Tracking
- Mark completed items `[x]` immediately. New tasks → `➕`; blockers → `⚠️`.
- Update plan if implementation deviates from scope.

## What Goes Where
- **Implementation Steps** (`[ ]`): code, tests, docs, helm — all in-repo.
- **Post-Completion** (no checkboxes): registering OAuth apps, real-browser login
  verification, production secret provisioning.

## Implementation Steps

### Task 1: Multi-provider auth config (YAML + env interpolation)
- [x] add deps: `go get golang.org/x/oauth2 github.com/coreos/go-oidc/v3
      golang.org/x/text gopkg.in/yaml.v3`, `go mod tidy` (first external deps —
      commit `go.sum`) — `go mod tidy` prunes deps not yet imported; oauth2/
      go-oidc/x/text get re-added in their tasks. yaml.v3 + `go.sum` committed now.
- [x] create `internal/auth/config.go`: `Config{RedirectURL, CookieKey []byte,
      AllowedUsers []string, Providers []ProviderConfig}`; `ProviderConfig{ID,
      Type (github|gitlab), DisplayName, BaseURL, ClientID, ClientSecret,
      AllowedOrgs, AllowedGroups []string}`
- [x] `LoadConfig(path)`: parse YAML, expand `${ENV}` in string fields (secrets/
      cookieKey never hardcoded), decode cookieKey (hex/base64 → 32 bytes)
- [x] `Config.Enabled()` → `len(Providers) > 0`; `Config.Validate()`: unique
      non-empty IDs, known type, ClientID/ClientSecret present, RedirectURL set,
      32-byte CookieKey; default BaseURL + DisplayName per type
- [x] add `--auth-config` flag + `PORTREACH_AUTH_CONFIG` env to `runUI`; empty
      path = auth disabled
- [x] write tests: multi-provider YAML load, `${ENV}` interpolation, cookieKey
      decode (good/bad), Validate (valid, dup id, unknown type, missing field,
      disabled-empty = valid)
- [x] run tests — must pass before Task 2

### Task 2: i18n foundation (Accept-Language, en + ru catalogs)
- [x] create `internal/i18n`: embed message catalogs (`locales/en.json`,
      `locales/ru.json`); `Bundle` with all current UI strings as keys
- [x] `Match(acceptLanguage string) language.Tag` using `golang.org/x/text`
      `language.NewMatcher([en, ru])` — default **en** for missing/unknown
- [x] `Localizer(tag)` exposing `T(key, args...) string`; missing key falls back
      to en then to the key itself
- [x] helper to pull the localizer from an `*http.Request` (`Accept-Language`),
      reusable by both `internal/ui` and `internal/auth`
- [x] write tests: matcher (en default, `ru`, `ru-RU`, unknown → en, empty → en),
      `T` lookup + fallback, all en keys present in ru (no missing translations)
- [x] run tests — must pass before Task 3

### Task 3: Sealed session cookie (stdlib AES-GCM)
- [x] create `internal/auth/session.go`: `Session{User, Name, Provider string,
      Groups []string, Expiry int64}`
- [x] `seal(key, Session)` / `open(key, string)` via `crypto/aes`+`crypto/cipher`
      GCM, random nonce, base64url; reject on auth-tag mismatch and expiry
- [x] `setSessionCookie` / `clearSessionCookie`: `HttpOnly; Secure; SameSite=Lax;
      Path=/`, bounded `MaxAge`
- [x] write tests: roundtrip, tampered ciphertext rejected, wrong key rejected,
      expired session rejected
- [x] run tests — must pass before Task 4

### Task 4: Provider abstraction + GitHub provider
- [x] `internal/auth/provider.go`: `Identity{Login, Name string, Groups []string}`;
      `Provider` interface: `ID()`, `DisplayName()`, `Type()`,
      `AuthCodeURL(state string) string`, `Exchange(ctx, code) (Identity, error)`
- [x] `internal/auth/github.go` (x/oauth2): endpoints from BaseURL (github.com →
      `login/oauth/*` + `api.github.com`; Enterprise → `<base>/login/oauth/*` +
      `<base>/api/v3`); scopes `read:org read:user`
- [x] Exchange: `GET /user` + `GET /user/orgs` → `Identity` (Groups = orgs)
- [x] write tests with `httptest` faking token + `/user` + `/user/orgs`; assert
      mapping and token/HTTP error handling
- [x] run tests — must pass before Task 5

### Task 5: GitLab provider (OIDC via go-oidc)
- [x] `internal/auth/gitlab.go` (`go-oidc/v3/oidc`): `oidc.NewProvider(ctx,
      issuer=BaseURL)`, `oauth2.Config` scopes `openid profile email`
- [x] Exchange: verify `id_token` (nonce), read claims `preferred_username`/`sub`,
      `name`, `groups`/`groups_direct` → `Identity` (Groups = GitLab groups)
- [x] thread OIDC `nonce` from auth-request into callback verification (stored in
      the state cookie from Task 6) — `Provider` interface extended to carry the
      nonce through `AuthCodeURL(state, nonce)` + `Exchange(ctx, code, nonce)`;
      GitHub ignores it. Task 6 will populate it from the state cookie.
- [x] write tests for claim→Identity mapping and nonce mismatch (hermetic fixture)
- [x] run tests — must pass before Task 6

### Task 6: Provider registry, login page (always buttons), auth handlers
- [x] `internal/auth/auth.go`: `Authenticator{cfg, providers map[string]Provider}`,
      `New(cfg) (*Authenticator, error)` building one Provider per ProviderConfig
- [x] `/auth/login`: **always render a login page** listing a button per provider
      (label = `DisplayName`, else localized `Sign in with <type>`), each linking
      `/auth/login?provider=<id>`; `?provider=<id>` → that provider's redirect.
      (Single provider still shows its one button — no auto-redirect.)
- [x] state cookie (sealed) carries random `state`, OIDC `nonce`, chosen
      `provider` id; short-lived
- [x] `/auth/callback`: validate state cookie, pick provider by stored id,
      `Exchange`, enforce per-provider org/group + global user allowlist (empty =
      allow any), set session cookie (`User`+`Provider`), redirect `/`; 403 page on
      denial
- [x] `/auth/logout`: clear session cookie, redirect `/`
- [x] add localized `login.html` + `denied.html` templates (use the i18n localizer
      from Task 2; button labels from `DisplayName`)
- [x] write tests: login page lists all providers (1 and ≥2), localized in en/ru,
      `?provider` selection, state mismatch → 400, allowlist deny → 403, happy path
      sets session and authenticates a follow-up request
- [x] run tests — must pass before Task 7

### Task 7: Localize the existing UI form/results page
- [x] refactor `internal/ui/web/index.html` to pull all visible strings via the
      i18n localizer (labels host/port/proto/timeout, `check` button, table
      headers, summary, error copy); set `<html lang>` from the chosen tag
- [x] wire the request localizer into `pageData` in `internal/ui/web.go`
      (`handleIndex`), defaulting to en
- [x] add the corresponding keys to `en.json` / `ru.json`
- [x] write tests: `handleIndex` renders ru labels with `Accept-Language: ru`, en
      by default, and check results page is localized
- [x] run tests — must pass before Task 8

### Task 8: Gating middleware + wire into the UI command
- [x] `Middleware(next http.Handler) http.Handler`: serves `/auth/*`; lets
      `/healthz` through unauthenticated; else require valid session cookie or 302
      → `/auth/login`; inject the authenticated `Identity` into the request context
      (`WithIdentity`) for downstream audit logging
- [x] `internal/cmd/ui.go`: load `auth.Config`; if `Enabled()`, `auth.New` + wrap
      `ui.New(...).Handler()`; else raw handler unchanged; invalid config →
      `ExitError{Code:2}`; one-line startup notice (provider ids, no secrets)
- [x] write tests: disabled config → working unauthenticated UI; invalid config →
      exit 2; `/healthz` reachable without auth; protected path redirects
- [x] run tests — must pass before Task 9

### Task 9: Audit logging for security (slog)
- [x] add an audit middleware in `internal/auth` (wraps the protected handler):
      reads `Identity` from context (default `anonymous` when auth off) and emits
      `log/slog` JSON events
- [x] `event=login`: `user`, `provider`, `result` (ok|denied), `remote` — from
      `/auth/callback`
- [x] `event=check`: `user`, `provider`, `target` (`host:port/proto` parsed from
      query), `remote` — for `/api/check` and for `/` when a target is submitted
- [x] make the audit logger injectable (default `slog.Default()`) for test capture;
      thread an `*slog.Logger` (stdout JSON) from `runUI` into the Authenticator
- [x] write tests asserting login + check events carry user/provider/target/remote,
      and `anonymous` when auth disabled
- [x] run tests — must pass before Task 10

### Task 10: Helm chart support
- [x] `charts/portreach/values.yaml`: `ui.auth` block (`enabled`, `redirectURL`,
      `allowedUsers`, `providers: []` mirroring ProviderConfig, `existingSecret` /
      inline refs for each `clientSecret` + `cookieKey`)
- [x] render the auth YAML into a Secret/ConfigMap and mount it; pass
      `--auth-config <mountpath>`; inject `clientSecret`s + `cookieKey` via env
      `secretKeyRef` referenced as `${ENV}` in the config
- [x] `templates/deployment-ui.yaml`: add the mount + `--auth-config` arg + env
      when `ui.auth.enabled`
- [x] write/extend a `helm template` render assertion covering auth-on (≥2
      providers) and auth-off; run `helm lint`
- [x] run tests — must pass before Task 11

### Task 11: Documentation
- [x] `docs/configuration.md`: full auth-config YAML reference (providers,
      displayName, allowlists, `${ENV}` secrets), cookie-key generation
      (`openssl rand`), GitHub/GitLab OAuth app setup, the audit-log event format
      for ИБ, and the i18n behaviour (`Accept-Language`, en default, en+ru)
- [x] `docs/deployment.md`: Helm `ui.auth` example with two providers + secret
- [x] `README.md`: short "Authentication (optional SSO)" + "Localization" sections
- [x] document how to add a new locale (drop a `locales/<lang>.json`, add to matcher)
- [x] run `go test ./...` to confirm no regression

### Task 12: Verify acceptance criteria
- [x] verify all Overview requirements: both provider types, login page always
      shows buttons (incl. single provider), self-hosted base URL, per-provider
      allowlist, disabled pass-through, `/healthz` open, audit events, i18n en+ru
      via Accept-Language (default en)
- [x] verify edge cases: expired/tampered cookie, state/nonce mismatch, allowlist
      denial, missing config fields, duplicate provider id, unknown Accept-Language
- [x] run full unit suite `go test ./... -v`
- [x] run `go vet ./...` and `helm lint charts/portreach` — clean
- [x] verify `internal/auth` + `internal/i18n` coverage ≥ 80% (auth 83.9%, i18n 93.8%)

### Task 13: [Final] Knowledge + deps
- [ ] re-read README/docs for accuracy; note the new `internal/auth` +
      `internal/i18n` packages, multi-provider model, and locale-add procedure
- [ ] confirm `go.mod`/`go.sum` committed with the new deps

*Note: ralphex automatically moves completed plans to `docs/plans/completed/`.*

## Technical Details
- **New packages**: `internal/auth` (`config.go`, `session.go`, `provider.go`,
  `github.go`, `gitlab.go`, `auth.go`, `audit.go`, embedded `login.html` /
  `denied.html`) and `internal/i18n` (`i18n.go`, embedded `locales/en.json`,
  `locales/ru.json`).
- **Deps** (first external): `golang.org/x/oauth2`, `github.com/coreos/go-oidc/v3`,
  `golang.org/x/text`, `gopkg.in/yaml.v3`; `go.sum` introduced.
- **Config file** (`--auth-config` / `PORTREACH_AUTH_CONFIG`):
  ```yaml
  auth:
    redirectURL: https://portreach.corp/auth/callback
    cookieKey: ${PORTREACH_AUTH_COOKIE_KEY}   # hex/base64 → 32 bytes
    allowedUsers: []
    providers:
      - id: corp-gitlab
        type: gitlab
        displayName: "Corporate GitLab"
        baseURL: https://gitlab.corp
        clientID: abc
        clientSecret: ${GITLAB_SECRET}
        allowedGroups: [infra, sre]
      - id: github
        type: github
        displayName: "GitHub"
        clientID: def
        clientSecret: ${GITHUB_SECRET}
        allowedOrgs: [myorg]
  ```
- **Routes**: `GET /auth/login[?provider=<id>]`, `GET /auth/callback`,
  `GET|POST /auth/logout`. Public: `/healthz`. Protected: `/`, `/api/check`.
- **Login UX**: 0 providers → disabled; ≥1 → login page **always** lists a button
  per provider (no auto-redirect). Label = `displayName`, else localized
  `Sign in with <type>`.
- **i18n**: language from `Accept-Language` via `x/text` matcher over `[en, ru]`,
  default en; localizer injected into both ui and auth templates; new locales add
  a `locales/<lang>.json` + matcher entry.
- **Session cookie**: AES-256-GCM sealed JSON `{user, name, provider, groups,
  exp}`, name `portreach_session`, `HttpOnly; Secure; SameSite=Lax`. Short-lived
  `portreach_oauth_state` cookie holds `state` + `nonce` + chosen `provider`.
- **Identity → Groups**: GitHub = org logins (`/user/orgs`); GitLab = OIDC
  `groups` claim. Allowlist passes if no lists configured, OR user ∈ AllowedUsers,
  OR any group ∈ that provider's AllowedOrgs/AllowedGroups; else 403.
- **Audit (slog JSON, stdout)**: `event=login user= provider= result= remote=` and
  `event=check user= provider= target=host:port/proto remote=`; `user=anonymous`
  when auth disabled. Identity flows handler→context→audit middleware.
- **BaseURL defaults**: github → `https://github.com`; gitlab → `https://gitlab.com`.

## Post-Completion
*Items requiring manual intervention or external systems — informational only.*

**Manual verification:**
- Register OAuth apps: GitHub (`Settings → Developer settings → OAuth Apps`,
  callback `<redirect-url>`) and GitLab (`Applications`, scopes
  `openid profile email`); for Enterprise/self-hosted use the corporate base URL.
- Real-browser login with **two** providers: login page shows both buttons → each
  completes login → redirected back authenticated; logout clears session.
- Switch browser language to ru → UI and login page render in Russian; default/
  unknown → English.
- Verify allowlist denial → 403 for a user outside the configured org/group.
- Confirm audit log lines appear in stdout with the right user/provider/target and
  are ingestible by the ИБ log pipeline (ELK/Loki).
- Confirm cookies are `Secure` behind TLS/ingress and the flow works through the
  ingress redirect URL.

**External system updates:**
- Provision the Kubernetes Secret with each provider `clientSecret` + `cookieKey`
  (`openssl rand -hex 32`) in the deployment namespace.
- Ensure ingress terminates TLS so `Secure` cookies work.
- Point the ИБ logging pipeline at the UI pod stdout for the audit events.
