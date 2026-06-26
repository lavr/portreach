# portreach

[![GitHub](https://img.shields.io/github/v/release/lavr/portreach)](https://github.com/lavr/portreach/releases/latest)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

Distributed network reachability checker. You enter `host:port`, the check runs
**from many points at once** (in Kubernetes — from each node's egress via a
DaemonSet on `hostNetwork`), and the result is summed up in a web form:
`point → DNS / TCP / latency`.

It answers the everyday question *"does the cluster have access to
`DWH-ClickHouse-pre:8123`?"* — checked from every node, not just from your
laptop.

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
docker run -d --name pr-agent --network host lavr/portreach agent --listen :8732

# the UI pointed at a static agent list
docker run -d --name pr-ui -p 8080:8080 \
  -e PORTREACH_AGENTS=127.0.0.1:8732 \
  lavr/portreach ui --listen :8080
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
{"node":"sv-ku01w03","src_ip":"172.17.92.137","host":"sv-chpr01","port":8123,
 "proto":"tcp",
 "dns":{"resolved":["172.17.8.68"],"cname":"sv-chpr01.invitro.ru.","ms":2.1},
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
| `--auth-config` | `PORTREACH_AUTH_CONFIG` | | SSO auth config YAML; empty = auth disabled |

Use `--agents` **or** `--agents-dns`, not both. Full reference:
[`docs/configuration.md`](docs/configuration.md).

## Security

The agent makes outbound TCP connections on request — an SSRF vector. Mitigate:

- expose the UI only on an internal network or behind authentication;
- optionally restrict agent targets with `--allow` / `--deny` CIDR lists;

A denied target resolves to HTTP 403. See
[`docs/configuration.md`](docs/configuration.md) for details.

## Authentication (optional SSO)

The UI can be put behind corporate single sign-on, with **multiple providers at
once** — GitHub (github.com / Enterprise) and GitLab (gitlab.com / self-hosted).
It is **disabled by default**: with no config the UI runs exactly as before.

Point `--auth-config` (or `PORTREACH_AUTH_CONFIG`) at a YAML file listing your
providers and an `allowedUsers`/per-provider org/group allowlist. The login page
always shows one button per provider; the session lives in a sealed
(AES-256-GCM) cookie. `/healthz` stays public; `/` and `/api/check` are gated.

Every login and reachability check is emitted as a structured `log/slog` JSON
audit event on stdout (`who` ran `what` from `where`) for security pipelines;
with auth off the actor is `anonymous`. Full reference, OAuth-app setup and the
audit event format: [`docs/configuration.md`](docs/configuration.md#authentication-optional-sso).

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
