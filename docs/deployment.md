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
  the real node IP), `hostPort` 8732, `NODE_NAME` via the downward API, and
  `tolerations: [{operator: Exists}]` so an agent lands on every node including
  tainted control-plane nodes;
- a **headless Service** (`clusterIP: None`) the UI uses for DNS discovery;
- the **UI Deployment + Service**, wired to the headless service via
  `PORTREACH_AGENTS_DNS` and `PORTREACH_AGENT_PORT`;
- an optional **Ingress** (`ui.ingress.enabled`).

Key `values.yaml` knobs:

```yaml
image:
  repository: ghcr.io/lavr/portreach
  tag: ""            # empty => <appVersion> (plain image); set verbatim,
                     # e.g. "0.1.0-rootless" for the scratch image (opt-in)

ui:
  replicaCount: 1
  timeout: 8s
  agentsDnsName: ""  # raw override; empty => built from discovery.mode
  discovery:
    mode: relative   # relative | fqdn | bare (see "Agent discovery" below)
  ingress:
    enabled: false   # enable + set hosts to expose externally

# clusterDomain: cluster.local   # used ONLY in discovery.mode: fqdn

agent:
  hostNetwork: true
  port: 8732
  allow: ""          # SSRF policy CIDRs (see configuration.md)
  deny: ""
  tolerations:
    - operator: Exists
```

Render without installing to review the manifests:

```sh
helm template portreach charts/portreach
helm lint charts/portreach
```

See [`charts/portreach/README.md`](../charts/portreach/README.md) for the full
values reference.

### Agent discovery (cluster-domain portability)

The UI resolves the headless agent Service by DNS, via the name the chart puts in
`PORTREACH_AGENTS_DNS`. The chart builds that name portably so it works on any
cluster DNS domain — **not just `cluster.local`**:

- `ui.discovery.mode: relative` (**default**) → `<svc>.<ns>.svc`. A 2-dot name is
  below the pod's `ndots:5`, so the Go resolver appends the cluster search domains
  and matches under whatever DNS domain the cluster actually uses.
- `ui.discovery.mode: fqdn` → `<svc>.<ns>.svc.<clusterDomain>`. Pins the domain;
  set `clusterDomain` to match (the historical behaviour).
- `ui.discovery.mode: bare` → `<svc>` (same-namespace only).
- `ui.agentsDnsName: <name>` → used verbatim, overriding the modes above
  (cross-namespace or external names).

> **Non-`cluster.local` caveat:** an absolute `…svc.cluster.local` resolves to
> NXDOMAIN on clusters whose domain differs (e.g. `kubeprodone.example.ru`),
> leaving the UI with zero agents (`/api/check` → 502). The default `relative`
> mode avoids pinning the domain, so the chart is portable out of the box; reach
> for `fqdn` + `clusterDomain` only when you need an absolute name.

### Authentication (optional SSO)

The chart can put the UI behind SSO via `ui.auth` — disabled by default. When
enabled it renders the auth config into a ConfigMap, mounts it at
`/etc/portreach/auth/auth.yaml`, passes `--auth-config`, and injects the cookie
key + each provider's client secret from a Kubernetes Secret as env vars (the
config references them as `${ENV}`, so secrets never land in the ConfigMap).

Create the Secret out-of-band (cookie key + one client secret per provider):

```sh
kubectl create secret generic portreach-ui-auth \
  --from-literal=cookieKey="$(openssl rand -hex 32)" \
  --from-literal=githubClientSecret=... \
  --from-literal=gitlabClientSecret=...
```

Then enable two providers in `values.yaml`:

```yaml
ui:
  auth:
    enabled: true
    redirectURL: https://portreach.corp/auth/callback
    allowedUsers: []                 # empty = any authenticated user
    existingSecret: portreach-ui-auth   # defaults to <ui-fullname>-auth
    cookieKeyEnv: PORTREACH_AUTH_COOKIE_KEY
    cookieKeySecretKey: cookieKey
    providers:
      - id: github
        type: github
        displayName: GitHub
        clientID: "abc"
        clientSecretEnv: GITHUB_CLIENT_SECRET
        clientSecretKey: githubClientSecret   # key within existingSecret
        allowedOrgs: [myorg]
      - id: corp-gitlab
        type: gitlab
        displayName: "Corporate GitLab"
        baseURL: https://gitlab.corp
        clientID: "def"
        clientSecretEnv: GITLAB_CLIENT_SECRET
        clientSecretKey: gitlabClientSecret
        allowedGroups: [infra, sre]
```

`/healthz` stays public so the liveness/readiness probes keep working. Terminate
TLS at the ingress so the `Secure` session cookie is sent. See the auth-config
reference in [`configuration.md`](configuration.md#authentication-optional-sso).

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
