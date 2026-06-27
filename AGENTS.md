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
- `internal/agent` — the probe HTTP server (`/check`, `/healthz`, `/metrics`).
- `internal/probe` — TCP + DNS + latency probing.
- `internal/discovery` — agent discovery (static CSV list + DNS A-records).
- `internal/ui` — UI fan-out aggregator, JSON API, server-rendered web form (`web/index.html`).
- `internal/auth` — optional SSO (GitHub OAuth2 + generic OIDC presets), sealed-cookie
  session, allowlist, slog audit log. Off unless configured.
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
- **Tests live next to code** as `*_test.go` and are **hermetic** — fake servers
  with `net/http/httptest`, never real network. New/changed behavior needs tests
  (success + error paths). Target ≥ 80% coverage on touched packages.
- **Dependencies are intentionally minimal.** The core started stdlib-only; the
  only external deps (`golang.org/x/oauth2`, `github.com/coreos/go-oidc/v3`,
  `golang.org/x/text`, `gopkg.in/yaml.v3`) were added for SSO/OIDC/i18n. Don't add
  new deps casually — prefer stdlib; if a dep is warranted, justify it.
- **Security-sensitive surfaces**: the UI triggers outbound connections from every
  node (SSRF surface) and `internal/auth` handles cookies/tokens/allowlists. Treat
  changes there carefully; preserve the fail-closed behavior and the existing
  timeout/deadline clamps.
- Agent endpoints (`internal/agent`) are internal cluster traffic — not behind auth
  by design. Don't add auth there.

## Helm chart

- Image and discovery-DNS logic live in `charts/portreach/templates/_helpers.tpl`
  (`portreach.image`, `portreach.agent.dnsName`). Both UI and agent share the image
  helper — change once.
- `image.tag` is the single source of truth: empty → `.Chart.AppVersion`; set →
  verbatim. Discovery name: `ui.agentsDnsName` override → `ui.discovery.mode`
  (`relative` default / `fqdn` / `bare`) → `clusterDomain` (fqdn only).
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
