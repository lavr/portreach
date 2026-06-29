# portreach

[![GitHub](https://img.shields.io/github/v/release/lavr/portreach)](https://github.com/lavr/portreach/releases/latest)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

Distributed network reachability checker. You enter `host:port`, the check runs
**from many points at once** (in Kubernetes — from each node's egress via a
DaemonSet on `hostNetwork`), and the result is summed up in a web form:
`point → DNS / TCP / latency`.

It answers the everyday question *"does the cluster have access to
`DWH-ClickHouse-pre:8123`?"* — checked from every node, not just from your
laptop. (Operators can optionally cap the fan-out with
`--max-agents-per-check` to bound the blast radius on large clusters; the
default `0` keeps the every-node behaviour, and any dropped agents are reported.)

## Why

| Tool | Per-node probe | Ad-hoc web UI | Probes from *your* nodes | Alive |
|------|:---:|:---:|:---:|:---:|
| Mirantis k8s-netchecker | ✅ (in-cluster only) | ❌ | ✅ | ❌ |
| sudo-Penguin / netcheck | ❌ | ✅ | ❌ (external Globalping) | ✅ |
| Goldpinger | static targets | partial | ✅ | ✅ |
| **portreach** | ✅ arbitrary target | ✅ | ✅ | ✅ |

- **k8s-netchecker** only measures in-cluster connectivity and is unmaintained.
- **sudo-Penguin/netcheck** has a nice web UI but probes from external
  Globalping, not from your nodes.
- **Goldpinger** monitors static targets, not ad-hoc `host:port` checks.

## How it works

One binary, two subcommands:

- **`portreach agent`** — probe HTTP server. Runs on every point (in k8s a
  DaemonSet with `hostNetwork: true`, so egress uses the real node IP).
- **`portreach ui`** — aggregator + web form. Discovers agents (static list or
  headless-service DNS), fans out the check to all of them with a timeout, and
  renders a per-point table.

Environment-agnostic: the same binary works outside Kubernetes (agents on
VMs/in Docker, UI reads a static list). Kubernetes is the flagship deploy path,
not the only one.

## Image variants

| Tag | Base | Description |
|-----|------|-------------|
| `latest`, `<version>` | Alpine 3.21 | Default image |
| `latest-rootless`, `<version>-rootless` | scratch | Minimal image, runs as non-root (UID 65534) |

Both variants are built for `linux/amd64` and `linux/arm64`.

## Quick start

### Docker (agent + UI)

```sh
# one or more agents
docker run -d --name pr-agent --network host ghcr.io/lavr/portreach agent --listen :8732

# the UI pointed at a static agent list
docker run -d --name pr-ui -p 8080:8080 \
  -e PORTREACH_AGENTS=127.0.0.1:8732 \
  ghcr.io/lavr/portreach ui --listen :8080
```

Open <http://localhost:8080/> and enter a `host:port`. A full multi-agent
example is in [`examples/docker-compose/`](examples/docker-compose/).

### Kubernetes (Helm)

```sh
helm install portreach oci://ghcr.io/lavr/charts/portreach
kubectl port-forward svc/portreach-ui 8080:80
# browse to http://localhost:8080/
```

The chart deploys an agent DaemonSet on `hostNetwork` (one probe per node, with
tolerations for all taints), a headless Service for DNS discovery, and the UI
Deployment + Service (optional Ingress). See
[`charts/portreach/README.md`](charts/portreach/README.md).

### Binary (Homebrew / releases)

```sh
brew install lavr/tap/portreach
```

Prebuilt binaries for linux/darwin/windows (amd64/arm64) are attached to every
[GitHub release](https://github.com/lavr/portreach/releases); run them directly
or via the [systemd unit](examples/systemd/).

## API

Agent `GET /check?host=&port=&proto=tcp&timeout=5s`:

```json
{"node":"node-w03","src_ip":"10.0.92.137","host":"db01","port":8123,
 "proto":"tcp",
 "dns":{"resolved":["10.0.8.68"],"cname":"db01.corp.example.","ms":2.1},
 "tcp":{"ok":false,"ms":5002.0,"error":"i/o timeout"}}
```

UI `GET /api/check?host=&port=&proto=&timeout=`:

```json
{"target":{"host":"...","port":8123,"proto":"tcp"},
 "agents":[{"agent":"10.0.0.1:8732","node":"node-a", "...": "...probe fields..."}],
 "summary":{"ok":3,"total":5}}
```

Both also expose `GET /healthz`; the agent exposes `GET /metrics`
(Prometheus `portreach_checks_total{result=}`).

## Configuration

`portreach agent`:

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8732` | listen address |
| `--allow` | *(empty)* | comma-separated allow CIDR list (empty = allow all) |
| `--deny` | *(empty)* | comma-separated deny CIDR list (wins over allow) |
| `--auth-token` | *(empty)* | bearer token required on `/check` + `/metrics` (env `PORTREACH_AGENT_TOKEN`) |
| `--metrics-public` | `false` | keep `/metrics` open when a token is set (`/check` stays gated) |
| `--allow-metadata` | `false` | remove the default-on metadata/link-local connect guard (`--deny` still wins) |
| `--rate-limit` | `false` | optional `/check` rate limiter (`--rate-target-*` / `--rate-global-*`); off = unlimited |

`NODE_NAME` (env) sets the point name reported by the agent; it falls back to
the hostname.

`portreach ui`:

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--listen` | | `:8080` | listen address |
| `--agents` | `PORTREACH_AGENTS` | | static `host[:port]` CSV |
| `--agents-dns` | `PORTREACH_AGENTS_DNS` | | headless service name to resolve agents from |
| `--agent-port` | `PORTREACH_AGENT_PORT` | `8732` | port for DNS-discovered / port-less agents |
| `--timeout` | | `8s` | overall fan-out budget per check |
| `--agent-token` | `PORTREACH_AGENT_TOKEN` | | bearer token sent to agents on `/check`; empty = none |
| `--max-agents-per-check` | `PORTREACH_MAX_AGENTS_PER_CHECK` | `0` | cap agents queried per check; `0` = unlimited (every node) |
| `--max-concurrent-fanout` | `PORTREACH_MAX_CONCURRENT_FANOUT` | `0` | bound concurrent per-check agent requests; `0` = unlimited |
| `--rate-limit` | `PORTREACH_RATE_LIMIT` | `false` | API rate limiter (`--rate-user-*` / `--rate-target-*` / `--rate-global-*`); off = unlimited |
| `--trusted-proxies` | `PORTREACH_TRUSTED_PROXIES` | | proxy CIDRs/IPs trusted for forwarded-header client-IP keying |
| `--auth-config` | `PORTREACH_AUTH_CONFIG` | | SSO auth config YAML; empty = auth disabled |
| `--ui-title` / `--ui-description` / `--ui-footer` | `PORTREACH_UI_*` | | trusted HTML branding for the main page |
| `--login-title` / `--login-header` / `--login-footer` | `PORTREACH_LOGIN_*` | | trusted HTML branding for login/denied pages |

Branding supports unset/set-empty/set tri-state semantics and `${VAR}`/`$VAR`
env expansion for per-cluster labels. Use `--agents` **or** `--agents-dns`, not both. Full reference:
[`docs/configuration.md`](docs/configuration.md).

## Security

The agent makes outbound TCP connections on request — an SSRF vector. Mitigate:

- expose the UI only on an internal network or behind authentication;
- optionally restrict agent targets with `--allow` / `--deny` CIDR lists;
- **cloud metadata is denied by default** — the agent refuses connects to the
  link-local range (`169.254.0.0/16`, incl. IMDS `169.254.169.254`) and IPv6
  `fd00:ec2::254` at connect time; opt back in with `--allow-metadata` (operator
  `--deny` still wins);
- **bound the abuse surface** with the optional rate limiter (`--rate-limit`,
  per-user/per-target/global → `429` + `Retry-After`) and `--max-agents-per-check`
  to cap the per-check fan-out; behind an Ingress set `--trusted-proxies` so
  per-IP keying is correct (or enable auth for per-user keys). Both are off
  (unlimited) by default.

A denied target resolves to HTTP 403. See
[`docs/configuration.md`](docs/configuration.md) for details.

## Authentication (optional SSO)

The UI can be put behind corporate single sign-on, with **multiple providers at
once** — GitHub (github.com / Enterprise) plus **any OpenID Connect IdP** via a
generic `oidc` type or a named preset: Keycloak, Okta, Auth0, Entra ID (Azure
AD), Google Workspace and GitLab (gitlab.com / self-hosted). It is **disabled by
default**: with no config the UI runs exactly as before.

Point `--auth-config` (or `PORTREACH_AUTH_CONFIG`) at a YAML file listing your
providers and an `allowedUsers`/per-provider org/group allowlist. The login page
always shows one button per provider; the session lives in a sealed
(AES-256-GCM) cookie. `/healthz` stays public; `/` and `/api/check` are gated.

Every login and reachability check is emitted as a structured `log/slog` JSON
audit event on stdout (`who` ran `what` from `where`) for security pipelines;
with auth off the actor is `anonymous`. Full reference, OAuth-app setup and the
audit event format: [`docs/configuration.md`](docs/configuration.md#authentication-optional-sso).

### API access (tokens)

For dev/CI automation, the UI's `/api/*` also accepts an
`Authorization: Bearer <JWT>` — an OIDC **access token** from a configured IdP,
validated offline by JWKS (`iss` + `aud` + `exp` + signature). Token and browser
requests share one identity, so the same group allowlist and audit apply. CI
uses an IdP **service account** (client-credentials); no browser needed.
OIDC/JWT only — GitHub and opaque tokens are unsupported. Independent of browser
SSO and off until you add an `api:` entry.

The **agent** plane is internal and locked down by a shared bearer token
(`--auth-token` / `PORTREACH_AGENT_TOKEN`); the UI sends it on every probe
(`--agent-token`). It is the primary isolation boundary (NetworkPolicy is
best-effort under `hostNetwork`), and it also gates `/metrics`. See
[`docs/configuration.md`](docs/configuration.md#api-bearer-tokens-boundary-a)
and [`docs/deployment.md`](docs/deployment.md#agent-token-shared-secret).

## Localization

The UI (form, results and auth pages) is localized from the browser's
`Accept-Language` header, defaulting to English. **en** and **ru** ship in the
box; add a locale by dropping `internal/i18n/locales/<lang>.json` and
registering its tag — see
[`docs/configuration.md`](docs/configuration.md#localization-i18n).

## Build

```sh
make build           # ./dist/portreach
make test            # go test ./...
make docker-build    # docker image (alpine variant; the rootless image is built by CI)
```

The core probe/UI is standard-library only; the optional SSO auth + i18n layer
adds a small set of well-known deps (`golang.org/x/oauth2`,
`github.com/coreos/go-oidc/v3`, `golang.org/x/text`, `gopkg.in/yaml.v3`).

## License

[MIT](LICENSE) © 2026 Sergey Lavrinenko
