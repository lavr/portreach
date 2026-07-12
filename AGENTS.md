# AGENTS.md

Guidance for AI coding agents working in this repository. Humans: see `README.md`
and `docs/`.

## What this is

**portreach** — a distributed network reachability checker. You enter `host:port`;
the check runs **from many points at once** (in Kubernetes, from each node's egress
via a `hostNetwork` agent DaemonSet) and the per-point DNS / TCP / latency results
are aggregated in a web UI. Single Go binary, three subcommands.

## Layout

- `main.go` — entrypoint; sets `version` (via ldflags) and dispatches to `internal/cmd`.
- `internal/cmd` — CLI dispatch + per-subcommand flag/env wiring (`agent`, `ui`, `version`).
- `internal/checkapi` — the shared UI↔agent JSON wire contract (`TCPCheckRequest`,
  `PostgresCheckRequest`, `Credentials`, `TLSOptions`, `AuthResult` + its stable code
  set), the `EnabledChecks` allowlist type, and the size-limited-body constant. No
  response-shaped type carries a password (enforced by a reflection test).
- `internal/agent` — the probe HTTP server. Per-protocol **`POST` endpoints**
  `/api/check/tcp` and `/api/check/postgres` (registered only when in `--enabled-checks`;
  a disabled or removed route 404s — the old `GET /check` is gone), plus `/healthz` and
  `/metrics`. Installs the default-on cloud-metadata connect guard (link-local
  `169.254.0.0/16` + IPv6 `fd00:ec2::254`, off with `--allow-metadata`; operator `--deny`
  is independent and wins).
- `internal/probe` — TCP + DNS + latency probing. A shared dial layer (`dial.go`) resolves
  and races candidates and returns the winning open conn; `Run` (TCP) closes it, and
  `RunPostgres` runs the auth prober on it. The metadata guard is a connect-time
  `net.Dialer.Control` check (not policy pre-resolve), surfaced as `Result.Denied`.
- `internal/probe/pgauth` — the PostgreSQL auth prober: `jackc/pgx`'s low-level `pgconn`
  (connect + auth + `Exec("SELECT 1")`) behind a fakeable interface, given a **guarded
  `DialFunc`** so the metadata guard applies to the auth dial too. `Fallbacks=nil` (no
  silent TLS downgrade); maps pgconn errors to `AuthResult` codes; never logs the password.
- `internal/discovery` — agent discovery (static CSV list + DNS A-records).
- `internal/ratelimit` — optional reservation-based token-bucket limiter (per-user,
  per-target, global; atomic multi-bucket reserve + rollback) used by UI and agent.
- `internal/ui` — UI fan-out aggregator, per-protocol `POST /api/check/{tcp,postgres}`
  JSON API, server-rendered web form (`web/index.html`) that POSTs (credentials never in
  a URL) and shows the Postgres fields only when enabled. The aggregator's per-check
  fan-out is optionally bounded (`maxAgentsPerCheck` / `maxConcurrentFanout`, both `0` =
  unlimited = today's every-node behaviour; drops are reported via explicit
  `discovered`/`queried`/`dropped` counts, never silent).
- `internal/auth` — optional UI auth, off unless configured. Two independent paths
  resolving to the same `Session`/RBAC: browser SSO (GitHub OAuth2 + generic OIDC
  presets, sealed-cookie session) and **API bearer** (OIDC/JWT access tokens validated
  offline by JWKS — `iss`+`aud`+`exp`+sig — for dev/CI; GitHub & opaque tokens
  unsupported). Allowlist + slog audit log (`auth_method=cookie|bearer`) apply to both.
- `internal/i18n` — `Accept-Language` localization (en + ru) for the UI and auth pages.
- `internal/version` — version string holder.
- `internal/charttest` — `helm template` render assertions for the Helm chart.
- `charts/portreach` — the Helm chart (UI Deployment + agent DaemonSet).
- `docs/` — user docs. `docs/plans/` — implementation plans (see below).
- `scripts/` — `chart-smoke.sh` + `kind-portreach.yaml` (local chart smoke test).
- `release.sh` — release tagging helper.

## Build / test / lint

Use the Makefile targets — they encode the canonical flags:

- `make build` — build `dist/portreach` with version ldflags.
- `make test` — `go test -coverprofile ./...` + prints total coverage.
- `make vet` — `go vet ./...`.
- `make lint` — `golangci-lint run`.
- `make fmt` — `goimports -w` (excludes `.ralphex/`).
- `make race` — `go test -race`.
- `make run [ARGS=...]` — run the UI locally against `127.0.0.1:8732` by default.

Before finishing any change: `go build ./...`, `go vet ./...`, `go test ./...` must
pass, and code must be `gofmt`/`goimports`-clean. For chart edits also run
`helm lint charts/portreach`.

Go version: see `go.mod` (currently `go 1.25`).

## Running locally

```sh
go run . agent --listen :8732          # a probe agent
go run . ui --agents 127.0.0.1:8732    # the UI, pointed at that agent
```

UI env mirrors flags: `PORTREACH_AGENTS`, `PORTREACH_AGENTS_DNS`,
`PORTREACH_AGENT_PORT`. Auth is configured via a YAML file (`--auth-config` /
`PORTREACH_AUTH_CONFIG`); see `docs/configuration.md`.

## Conventions

- **Match the surrounding code.** This codebase favors small, well-commented
  functions; comments explain *why* (especially around timeouts, deadlines, and
  security trade-offs), not *what*. Keep that density.
- **Go conventions**: define interfaces in the package that consumes them, not
  beside their implementation; put `context.Context` first in every blocking or
  cancellable function; defer cleanup immediately after acquiring files,
  connections, contexts, or locks; keep changes focused — don't mix unrelated
  cleanup or general improvements into a feature.
- **Tests live next to code** as `*_test.go` and are **hermetic** — fake servers
  with `net/http/httptest`, never real network. New/changed behavior needs tests
  (success + error paths). Target ≥ 80% coverage on touched packages.
- **Test isolation.** Tests never read or modify the real environment: filesystem
  tests use `t.TempDir()`, environment variables are set via `t.Setenv`, and
  nothing talks to a live cluster or external service. Test helpers call
  `t.Helper()`.
- **Dependencies are intentionally minimal.** The core started stdlib-only; the
  external deps (`golang.org/x/oauth2`, `github.com/coreos/go-oidc/v3`,
  `golang.org/x/text`, `gopkg.in/yaml.v3`, `golang.org/x/time/rate` for the rate
  limiter, and `github.com/jackc/pgx/v5` — only `pgconn` — for the PostgreSQL check)
  were each added for a specific feature: SSO/OIDC, i18n, abuse controls, and the
  credentialed postgres probe. `pgx` was chosen over a hand-rolled wire protocol so
  PostgreSQL protocol/CVE tracking is the driver's job, not ours (decision 2026-07-12).
  Don't add new deps casually — prefer stdlib; if a dep is warranted, justify it.
- **Security-sensitive surfaces**: the UI triggers outbound connections from every
  node (SSRF surface) and `internal/auth` handles cookies/tokens/allowlists. Treat
  changes there carefully; preserve the fail-closed behavior and the existing
  timeout/deadline clamps.
- **Abuse controls** (all backward-compatible defaults — see `docs/configuration.md`):
  - *Rate limiter* (`internal/ratelimit`, off by default): reservations are taken from
    every applicable bucket and **all cancelled** if any denies, so a rejected request
    burns no unrelated tokens; over limit → `429` + `Retry-After` from the reservation
    delay. Identity key = authed user > proxy-trusted forwarded IP > `RemoteAddr`; a
    forwarded header is trusted only when `RemoteAddr` ∈ `--trusted-proxies`.
  - *Bounded fan-out* (`maxAgentsPerCheck` / `maxConcurrentFanout`, both `0` = unlimited):
    when capped, agents are sorted by `Addr` for **deterministic** selection and drops
    are reported (`discovered`/`queried`/`dropped`); never spawn a zero-worker pool.
  - *Metadata guard* (default **on**): a connect-time `net.Dialer.Control` check that a
    denied IP is never connected to — **not** policy pre-resolve, so CNAME/DNS-error
    reporting for normal targets is unchanged. A mixed RRset whose allowed sibling
    connects first may still return OK; only a name resolving **solely** to denied IP(s)
    yields `Result.Denied`. Guard-hit uses an `atomic.Bool` (the dial path is concurrent
    — run `-race`). `--allow-metadata` removes only this built-in set; `--deny` wins.
- **Two auth boundaries** (both backward-compatible — unset → today's open behaviour):
  - *UI API*: a request to `/api/*` is authenticated by **either** a browser session
    cookie **or** `Authorization: Bearer <JWT>` (see `internal/auth` above). API-only
    (bearer, no browser providers) is a valid headless/CI config; failures return 401
    JSON, not a login redirect.
  - *UI → agent*: agent endpoints (`internal/agent`) are internal cluster traffic.
    They carry **no SSO** — instead an optional shared bearer token
    (`--auth-token` / `PORTREACH_AGENT_TOKEN`, constant-time compare) is the primary
    isolation boundary; the UI sends it on every `/api/check/*` (`--agent-token`). The
    same token gates `/metrics` by default (`--metrics-public` opts it back open for
    Prometheus); `/healthz` is always open. NetworkPolicy is best-effort only and
    frequently unenforced under `hostNetwork` — don't rely on it instead of the token.
    Don't put OIDC/SSO on the agent; the shared token is the design.
- **Enabled-checks allowlist** (`--enabled-checks`, default `tcp`; env
  `PORTREACH_ENABLED_CHECKS`): selects which per-protocol endpoints each binary serves;
  a disabled check's route is never registered (404). `tcp` may be disabled; a blank set
  is a startup error; `/healthz` and `/metrics` are never gated by it.
- **PostgreSQL check** (`postgres`, off by default): a credentialed probe (per-request
  username/password/database + TLS), SCRAM/MD5 via `pgconn`, TLS-verified to the DB by
  default, ending in `SELECT 1`. **Fail-closed**: enabling it *requires* the agent token
  (agent `--auth-token`, UI `--agent-token`) or the process exits at startup; the Helm
  chart enforces the same at render time. The password is read only from the size-limited
  JSON body / POST form and never reaches a URL, log, error, `Result`, response, or the
  rendered HTML (reflection + redaction tests guard this). A dedicated postgres rate
  limiter is auto-on (disable via `--disable-postgres-rate-limit`) and every request is
  audited (`postgres_check` event, no password). The SSRF metadata guard runs before any
  handshake **and** on the prober's own dial. ⚠️ The UI→agent hop is plain HTTP in this
  release — the token authorizes but does not encrypt, so the password crosses it in
  cleartext; native agent TLS is a separate plan
  (`docs/superpowers/specs/2026-07-12-agent-tls-design.md`).
- **Commits**: no `Co-Authored-By` trailer and no AI-attribution lines in commit
  messages or PR descriptions.

## Helm chart

- Image and discovery-DNS logic live in `charts/portreach/templates/_helpers.tpl`
  (`portreach.image`, `portreach.agent.dnsName`). Both UI and agent share the image
  helper — change once.
- `image.tag` is the single source of truth: empty → `.Chart.AppVersion`; set →
  verbatim. Discovery name: `ui.agentsDnsName` override → `ui.discovery.mode`
  (`relative` default / `fqdn` / `bare`) → `clusterDomain` (fqdn only).
- `ui.enabledChecks` / `agent.enabledChecks` (default `[tcp]`) render `--enabled-checks`;
  `portreach.validateChecks` (`templates/_helpers.tpl`, run via `templates/validate.yaml`)
  fails the render when the UI offers a check the agent doesn't serve, or when `postgres`
  is enabled without an agent token — the same fail-closed rules the binaries enforce.
- Verify chart changes with `internal/charttest` (`go test ./internal/charttest/`),
  `helm lint`, and for DNS/discovery behavior the `scripts/chart-smoke.sh` kind harness.

## Releases

Use `release.sh` (interactive — run it from a terminal on `main`):

- `./release.sh app` — tag an app release (`X.Y.Z`).
- `./release.sh chart` — bump `Chart.yaml` version + tag `chart-X.Y.Z`.
- `./release.sh both` — app tag + bump `Chart.yaml` (version **and** appVersion) + chart tag.
- `./release.sh status` — show current versions/tags.

Tags drive CI: `X.Y.Z` → binaries + Docker images (`alpine` + `rootless`, multi-arch)
+ Homebrew; `chart-X.Y.Z` → Helm chart pushed to `oci://ghcr.io/lavr/charts`. Keep
the chart `appVersion` aligned with the app release so the default image tag matches.

## Planning workflow

Larger work is planned in `docs/plans/YYYY-MM-DD-<slug>.md` and executed with the
ralphex CLI; completed plans move to `docs/plans/completed/`. When implementing from
a plan, keep its checkboxes in sync and finish each task (with tests) before the next.
`.ralphex/` is tooling state — ignore it; it's gitignored.
