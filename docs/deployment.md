# Deployment

`portreach` runs anywhere the binary runs. Three common topologies:

1. [Kubernetes (Helm)](#kubernetes-helm) — flagship, per-node DaemonSet.
2. [Docker / static list](#docker--static-list) — agents in containers.
3. [systemd / bare VMs](#systemd--bare-vms) — agents as system services.

In every case: run an **agent** on each point you want to probe from, and one
**UI** that knows how to find those agents.

## Kubernetes (Helm)

```sh
helm install portreach oci://ghcr.io/lavr/charts/portreach
kubectl port-forward svc/portreach-ui 8080:80
# browse to http://localhost:8080/
```

The chart deploys:

- an **agent DaemonSet** with `hostNetwork: true` (so each probe egresses from
  the real node IP), optional `hostPort` 8732, `NODE_NAME` via the downward API,
  and `tolerations: [{operator: Exists}]` so an agent lands on every node
  including tainted nodes;
- a **headless Service** (`clusterIP: None`) the UI uses for DNS discovery;
- the **UI Deployment + Service**, wired to the headless service via
  `PORTREACH_AGENTS_DNS` and `PORTREACH_AGENT_PORT`;
- optional **Ingress**, SSO auth, NetworkPolicies, extra Secrets and extra
  manifests.

Key `values.yaml` knobs:

```yaml
image:
  repository: ghcr.io/lavr/portreach
  tag: ""            # empty => <appVersion> (plain image); set verbatim,
                     # e.g. "0.1.0-rootless" for the scratch image (opt-in)

ui:
  replicas: 2
  timeout: 8s
  agentDiscovery:
    dnsName: ""      # raw override; empty => built from mode
    mode: relative   # relative | fqdn | bare (see "Agent discovery" below)
  ingress:
    enabled: false   # enable + set hosts to expose externally
  branding:
    title: '<span style="color:#b62324">PROD — ${CLUSTER_NAME}</span>'
    description: null
    footer: null
  loginBranding:
    title: 'PROD login — ${CLUSTER_NAME}'
    header: '<span style="color:#b62324">PROD — ${CLUSTER_NAME}</span>'
    footer: 'Use your corporate SSO account.'
  extraEnv:
    - name: CLUSTER_NAME
      valueFrom:
        fieldRef:
          fieldPath: metadata.namespace

# clusterDomain: cluster.local   # used ONLY in discovery.mode: fqdn

agent:
  port: 8732
  targetPolicy:
    allow: ""        # SSRF policy CIDRs (see configuration.md)
    deny: ""
  network:
    hostNetwork: true
    hostPort:
      enabled: true
  tolerations:
    - operator: Exists
```

Render without installing to review the manifests:

```sh
helm template portreach charts/portreach
helm lint charts/portreach
```

See [`charts/portreach/README.md`](../charts/portreach/README.md) for the full
values reference. Branding values are optional (`null` means unset/localized
default; `""` means explicitly empty) and may contain trusted HTML plus
`${VAR}`/`$VAR` placeholders expanded from the UI container environment, so one
values file can render distinct titles per cluster via `extraEnv`.

### Agent discovery (cluster-domain portability)

The UI resolves the headless agent Service by DNS, via the name the chart puts in
`PORTREACH_AGENTS_DNS`. The chart builds that name portably so it works on any
cluster DNS domain — **not just `cluster.local`**:

- `ui.agentDiscovery.mode: relative` (**default**) → `<svc>.<ns>.svc`. A 2-dot
  name is below the pod's `ndots:5`, so the Go resolver appends the cluster
  search domains and matches under whatever DNS domain the cluster actually uses.
- `ui.agentDiscovery.mode: fqdn` → `<svc>.<ns>.svc.<clusterDomain>`. Pins the
  domain; set `clusterDomain` to match.
- `ui.agentDiscovery.mode: bare` → `<svc>` (same-namespace only).
- `ui.agentDiscovery.dnsName: <name>` → used verbatim, overriding the modes above
  (cross-namespace or external names).

> **Non-`cluster.local` caveat:** an absolute `…svc.cluster.local` resolves to
> NXDOMAIN on clusters whose domain differs (e.g. `kubeprodone.example.ru`),
> leaving the UI with zero agents (`/api/check` → 502). The default `relative`
> mode avoids pinning the domain, so the chart is portable out of the box; use
> for `fqdn` + `clusterDomain` only when you need an absolute name.

### Authentication (optional SSO)

The chart can put the UI behind SSO via `ui.auth` — disabled by default. It
renders auth config into a ConfigMap, mounts it at
`/etc/portreach/auth/auth.yaml`, passes `--auth-config`, and injects secrets via
env vars. The ConfigMap contains only `${ENV}` placeholders.

Inline mode creates `<ui>-auth` from values:

```yaml
ui:
  auth:
    enabled: true
    redirectURL: https://portreach.corp/auth/callback
    cookieKey: "<32-byte hex/base64>"
    providers:
      - id: github
        type: github
        clientID: "abc"
        clientSecret: "github-secret"
        allowedOrgs: [myorg]
      - id: corp-gitlab
        type: gitlab
        baseURL: https://gitlab.corp
        clientID: "def"
        clientSecret: "gitlab-secret"
        allowedGroups: [infra, sre]
```

For external secret management, set `ui.auth.existingSecret` and omit inline
`cookieKey` / `clientSecret`. Provider secret env/key names are derived from the
provider `id` unless `clientSecretEnv` / `clientSecretKey` are set explicitly.

Browser SSO and the **API bearer path** are independent toggles. The chart
gates the auth ConfigMap on `portreach.auth.enabled` =
`ui.auth.browser.enabled` **OR** `ui.auth.api.enabled` (the legacy
`ui.auth.enabled: true` still means browser-enabled). API bearer entries are a
list mirroring the Go config — enable a headless, CI-only deployment with no
browser providers:

```yaml
ui:
  auth:
    browser:
      enabled: false        # no browser login
    api:
      enabled: true
      entries:
        - id: ci
          issuer: https://keycloak.corp/realms/main
          audience: portreach
          allowedGroups: [ci, sre]
```

`/healthz` stays public so the liveness/readiness probes keep working. Terminate
TLS at the ingress so the `Secure` session cookie is sent. See the auth-config
reference in [`configuration.md`](configuration.md#authentication-optional-sso)
and the [API bearer model](configuration.md#api-bearer-tokens-boundary-a).

### Agent token (shared Secret)

The agent is the **primary** isolation boundary, enforced by a shared bearer
token (not NetworkPolicy — see below). Set `agent.auth.token`; the chart renders
a Secret and injects `PORTREACH_AGENT_TOKEN` into **both** the agent DaemonSet
and the UI Deployment, so the UI sends exactly what the agent requires:

```yaml
agent:
  auth:
    token: "<openssl rand -hex 32>"   # chart-managed Secret
    # existingSecret: my-agent-token  # or reference an out-of-band Secret
    tokenSecretKey: agent-token       # key the token lives under
  metricsPublic: false                # /metrics gated behind the token (default)
```

- **Rotation.** For the chart-managed `token`, a checksum annotation on both pod
  templates means a value change triggers a rollout automatically. With
  `existingSecret`, rotating the Secret value needs a **manual rollout**
  (`kubectl rollout restart`) of both workloads — the annotation only tracks
  chart-rendered values.
- **`existingSecret` is mutually exclusive with `token`.** Store the token under
  `tokenSecretKey` (default `agent-token`).
- `agent.metricsPublic: true` re-opens `/metrics` for Prometheus while keeping
  `/check` gated (see [/metrics gating](configuration.md#metrics-gating)).

### NetworkPolicy (best-effort) and strict isolation

`networkPolicy.enabled` is **opt-in** and, on the default `hostNetwork: true`
agent, **best-effort only**: NetworkPolicy is CNI-dependent and frequently
**not** enforced for host-networked pods. Treat the **agent token** as the real
boundary; NetworkPolicy is defence-in-depth at most.

For NP-**enforced** isolation, move the agent onto the pod network:

```yaml
agent:
  network:
    hostNetwork: false
    hostPort:
      enabled: false
networkPolicy:
  enabled: true
```

> **Trade-off — egress vantage point.** On the pod network the probe egresses
> from the **pod** IP (via the CNI/SNAT path), not the **node** IP. The
> reachability results then reflect pod-network egress, which may differ from
> what a workload sees from the node. Use the default `hostNetwork: true` when
> you need true per-node egress; opt into the pod-network mode only when
> NP-enforced isolation matters more than the node vantage point.

## Docker / static list

Run agents with host networking so the probe egress is the host's real IP, and
point the UI at them with `PORTREACH_AGENTS`:

```sh
docker run -d --name pr-agent --network host \
  lavr/portreach agent --listen :8732

docker run -d --name pr-ui -p 8080:8080 \
  -e PORTREACH_AGENTS=host-a:8732,host-b:8732 \
  lavr/portreach ui --listen :8080
```

A ready-to-run multi-agent compose stack is in
[`examples/docker-compose/`](../examples/docker-compose/).

## systemd / bare VMs

Install the binary on each VM and run the agent as a service. An example unit is
in [`examples/systemd/portreach-agent.service`](../examples/systemd/portreach-agent.service):

```sh
sudo install -m 0755 ./dist/portreach /usr/local/bin/portreach
sudo cp examples/systemd/portreach-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now portreach-agent
```

Then run the UI on one host with the static list of agent VMs:

```sh
portreach ui --agents vm-a:8732,vm-b:8732,vm-c:8732
```

## Security note

The UI lets anyone trigger outgoing TCP connections from every point — an SSRF
surface. Expose it only on an internal network or behind authentication, and
restrict targets with the agent `--allow` / `--deny` CIDR lists where
appropriate. See [`configuration.md`](configuration.md#target-policy-ssrf-mitigation).
