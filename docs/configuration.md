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
