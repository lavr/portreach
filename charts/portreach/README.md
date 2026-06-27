# portreach Helm chart

Deploys [portreach](https://github.com/lavr/portreach) — a distributed network
reachability checker — into Kubernetes:

- an **agent** DaemonSet that runs one probe per node on `hostNetwork`, so each
  check egresses from the real node IP;
- a headless **Service** the UI uses to discover agents via DNS;
- a **UI** Deployment + Service (+ optional Ingress) that fans out checks to
  every agent and renders a per-node table.

## Install

```sh
helm install portreach oci://ghcr.io/lavr/charts/portreach
```

Then open the web form:

```sh
kubectl port-forward svc/portreach-ui 8080:80
# browse to http://localhost:8080/
```

## Security

The UI lets anyone trigger outgoing TCP connections from every node — an SSRF
surface. Expose it only on an internal network or behind authentication, and
optionally restrict targets with `agent.allow` / `agent.deny` CIDR lists.

### Authentication (optional SSO)

Set `ui.auth.enabled=true` to put the UI behind multi-provider SSO (GitHub /
GitHub Enterprise, GitLab / self-hosted). Create a Secret out of band holding the
AES-256 session `cookieKey` plus each provider's client secret; the chart injects
those as env vars and references them as `${ENV}` placeholders, so no secret is
ever written into the rendered ConfigMap. `/healthz` stays public. Terminate TLS
at the ingress — session cookies are `Secure`, so plain HTTP breaks the flow. See
[`docs/configuration.md`](../../docs/configuration.md) for the full provider
schema and allowlist semantics.

## Agent discovery (DNS portability)

The UI finds agents by resolving the headless Service name passed as
`PORTREACH_AGENTS_DNS`. How that name is built is fully configurable so the chart
works on **any** cluster DNS domain out of the box — not just `cluster.local`.

Resolution priority:

1. **`ui.agentsDnsName`** — if non-empty, used **verbatim**. The escape hatch for
   any FQDN, bare name, cross-namespace service, or external DNS name.
2. **`ui.discovery.mode`** — when no override, picks how the default is built:
   - `relative` → `<svc>.<ns>.svc` — **default**. A 2-dot name is below the pod's
     `ndots:5`, so the resolver appends the search domains and matches under
     whatever `<clusterDomain>` the cluster actually uses. Portable everywhere.
   - `fqdn` → `<svc>.<ns>.svc.<clusterDomain>` — pins the cluster domain
     explicitly (the historical behaviour). Set `clusterDomain` to match.
   - `bare` → `<svc>` — shortest; resolves via the first search suffix, so
     same-namespace only.

Why `relative` is the default: on clusters whose DNS domain is **not**
`cluster.local`, a hard-coded `…svc.cluster.local` resolves to NXDOMAIN and the
UI finds zero agents. `relative` avoids pinning the domain at all, so the chart
is portable without the operator knowing the cluster's DNS domain. It still
resolves correctly on `cluster.local`. Switch to `fqdn` + `clusterDomain` only if
your environment needs an absolute name.

```yaml
ui:
  # portable default — works on any cluster domain
  discovery:
    mode: relative

  # OR override the whole name (cross-namespace, external, etc.)
  # agentsDnsName: portreach-agent.monitoring.svc.cluster.local

  # OR pin the domain explicitly:
  # discovery:
  #   mode: fqdn

# clusterDomain is TOP-LEVEL (not under ui:); used only in discovery.mode: fqdn
# clusterDomain: kubeprodone.example.ru
```

## Image tag

`image.tag` is the single source of truth for the image reference, shared by the
UI Deployment and the agent DaemonSet (they never drift):

- **empty** (default) → `<appVersion>` — the plain image (alpine-based, ships a
  shell, handy for in-pod network diagnostics);
- **set** → used **verbatim**: `0.1.0`, `sha-abc123`, `latest`, etc.

The scratch-based **rootless** image is opt-in — set the full tag yourself:

```yaml
image:
  tag: "0.1.0-rootless"
```

> Behaviour change in 0.1.1: the implicit default flavour moved from `rootless`
> (scratch) to the plain `<appVersion>` image. Pin `image.tag: "<ver>-rootless"`
> to keep the scratch image.

## Values

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/lavr/portreach` | Image repository. |
| `image.tag` | `""` | Single source of truth. Empty → `<appVersion>` (plain image); set → used verbatim (`0.1.0`, `sha-abc123`, `latest`, or `<ver>-rootless` for the scratch image). |
| `clusterDomain` | `cluster.local` | Cluster DNS domain. Used **only** when `ui.discovery.mode: fqdn`; ignored otherwise. |
| `ui.replicaCount` | `1` | UI replicas. |
| `ui.agentsDnsName` | `""` | Raw override for the agent discovery DNS name (used verbatim when non-empty). Empty → built from `ui.discovery.mode`. |
| `ui.discovery.mode` | `relative` | How the discovery name is built: `relative` (`<svc>.<ns>.svc`, portable default), `fqdn` (`<svc>.<ns>.svc.<clusterDomain>`), or `bare` (`<svc>`, same-namespace only). |
| `ui.timeout` | `8s` | Overall fan-out budget per check. |
| `ui.service.type` | `ClusterIP` | UI service type. |
| `ui.service.port` | `80` | UI service port. |
| `ui.ingress.enabled` | `false` | Enable the UI Ingress. |
| `ui.auth.enabled` | `false` | Put the UI behind multi-provider SSO. Off = no login. |
| `ui.auth.redirectURL` | `""` | OAuth callback URL; must match each provider's registered callback. |
| `ui.auth.allowedUsers` | `[]` | Global user-login allowlist. Empty = any authenticated user. |
| `ui.auth.existingSecret` | `""` | Secret holding `cookieKey` + each provider's client secret. Defaults to `<ui-fullname>-auth`. |
| `ui.auth.cookieKeyEnv` | `PORTREACH_AUTH_COOKIE_KEY` | Env var injected with the AES-256 session cookie key. |
| `ui.auth.cookieKeySecretKey` | `cookieKey` | Secret key holding the cookie key. |
| `ui.auth.providers` | `[]` | Providers: `id`, `type`, `displayName`, `baseURL`, `clientID`, `clientSecretEnv`, `clientSecretKey`, `allowedOrgs`, `allowedGroups`. |
| `agent.hostNetwork` | `true` | Run agents on host network (real node egress). |
| `agent.port` | `8732` | Agent listen + hostPort. |
| `agent.allow` | `""` | Allow-CIDR list (empty = allow all). |
| `agent.deny` | `""` | Deny-CIDR list (takes precedence). |
| `agent.tolerations` | `[{operator: Exists}]` | Run on every node, incl. tainted. |
| `serviceAccount.create` | `true` | Create a ServiceAccount. |
