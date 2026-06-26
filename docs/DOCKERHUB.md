# portreach

[![GitHub](https://img.shields.io/github/v/release/lavr/portreach)](https://github.com/lavr/portreach/releases/latest)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

Distributed network reachability checker. You enter `host:port`, the check runs
**from many points at once** (in Kubernetes — from each node's egress via a
DaemonSet on `hostNetwork`), and the result is summed up in a web form:
`point → DNS / TCP / latency`.

One binary, two subcommands:

- `portreach agent` — probe HTTP server, runs on each point.
- `portreach ui` — aggregator + web form, fans out checks to all agents.

## Image variants

| Tag | Base | Description |
|-----|------|-------------|
| `latest`, `<version>` | Alpine 3.21 | Default image |
| `latest-rootless`, `<version>-rootless` | scratch | Minimal image, runs as non-root (UID 65534) |

Both variants are built for `linux/amd64` and `linux/arm64`.

## Quick start

```bash
# one or more agents (host networking → real egress IP)
docker run -d --name pr-agent --network host \
  lavr/portreach agent --listen :8732

# the UI pointed at a static agent list
docker run -d --name pr-ui -p 8080:8080 \
  -e PORTREACH_AGENTS=127.0.0.1:8732 \
  lavr/portreach ui --listen :8080
```

Open <http://localhost:8080/> and enter a `host:port`.

## Configuration

`agent`: `--listen :8732`, `--allow`/`--deny` CIDR lists (SSRF policy);
`NODE_NAME` env sets the reported point name.

`ui`: `--listen :8080`, `--agents`/`PORTREACH_AGENTS` (static list),
`--agents-dns`/`PORTREACH_AGENTS_DNS` (k8s headless service),
`--agent-port`/`PORTREACH_AGENT_PORT` (default 8732), `--timeout` (default 8s).

## Security

The agent makes outbound TCP connections on request — an SSRF vector. Expose the
UI only on an internal network or behind authentication, and restrict targets
with the agent `--allow` / `--deny` CIDR lists.

## Links

- Source & full docs: <https://github.com/lavr/portreach>
- Helm chart: `oci://ghcr.io/lavr/charts/portreach`
- License: MIT
