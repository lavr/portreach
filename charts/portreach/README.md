# portreach Helm chart

Deploys [portreach](https://github.com/lavr/portreach) into Kubernetes:

- an agent DaemonSet, normally on `hostNetwork`, one probe per node;
- a headless agent Service for UI DNS discovery;
- a UI Deployment, Service, optional Ingress, optional SSO auth;
- optional chart-managed Secrets and arbitrary extra manifests.

## Install

```sh
helm install portreach oci://ghcr.io/lavr/charts/portreach
kubectl port-forward svc/portreach-ui 8080:80
```

Open `http://localhost:8080/`.

## Values Shape

The chart has a new values API starting with chart `0.3.0`; compatibility with
the pre-`0.3.0` API is intentionally not preserved.

```yaml
image:
  repository: ghcr.io/lavr/portreach
  tag: ""                  # empty => chart appVersion

serviceAccounts:
  ui:
    create: true
  agent:
    create: true

ui:
  replicas: 2
  timeout: 8s
  agentDiscovery:
    mode: relative         # relative | fqdn | bare
    dnsName: ""            # raw override
  service:
    type: ClusterIP
    port: 80
  ingress:
    enabled: false
  auth:
    enabled: false

agent:
  port: 8732
  targetPolicy:
    allow: ""
    deny: ""
  network:
    hostNetwork: true
    hostPort:
      enabled: true
```

## Auth

SSO is disabled by default. Enabling it requires at least one provider. The
ConfigMap always contains `${ENV}` placeholders; client secrets and the cookie
key are injected from a Secret.

`redirectURL` is optional. Set it to pin a single fixed OAuth callback (one
hostname). **Leave it empty for host-derived mode**: the `redirect_uri` is
derived per request from `X-Forwarded-Host`/`X-Forwarded-Proto`, so one release
authenticates across every ingress hostname (register each callback in the IdP).
Optionally restrict the derived host with `allowedRedirectHosts` and override the
trusted header names with `forwardedHostHeader`/`forwardedProtoHeader`:

```yaml
ui:
  auth:
    enabled: true
    redirectURL: ""                 # empty → host-derived (many hostnames)
    allowedRedirectHosts: [portreach.cluster-one.k8s, portreach.shared.k8s]
    existingSecret: portreach-ui-auth
    providers:
      - id: github
        type: github
        clientID: "abc"
  ingress:
    enabled: true
    hosts:
      - host: portreach.cluster-one.k8s
      - host: portreach.shared.k8s
```

See `docs/configuration.md` (Host-derived callback) for the trust model.

For **http** deployments set `ui.auth.cookieSecure` to `auto` (default — `Secure`
only over https, so login works on both) or `never` (deliberate http-only);
`always` requires https. Browsers drop `Secure` cookies over http, so leaving the
default `auto` is what lets login work without TLS. See `docs/configuration.md`
(Cookie `Secure` attribute).

Inline mode, where the chart creates `<ui>-auth`:

```yaml
ui:
  auth:
    enabled: true
    redirectURL: https://portreach.example.com/auth/callback
    cookieKey: "<32-byte hex/base64 key>"
    providers:
      - id: github
        type: github
        clientID: "abc"
        clientSecret: "github-secret"
```

External Secret mode:

```yaml
ui:
  auth:
    enabled: true
    redirectURL: https://portreach.example.com/auth/callback
    existingSecret: portreach-ui-auth
    providers:
      - id: corp-gitlab
        type: gitlab
        baseURL: https://gitlab.example.com
        clientID: "abc"
```

Provider secret env/key names are derived from `id` unless explicitly set:

- env: `PORTREACH_AUTH_<ID>_CLIENT_SECRET`
- key: `<id>ClientSecret`

For `id: corp-gitlab`, this becomes
`PORTREACH_AUTH_CORP_GITLAB_CLIENT_SECRET` and `corp-gitlabClientSecret`.

## Extra Secrets

Use `extraSecrets` for chart-managed Secret resources:

```yaml
extraSecrets:
  - name: portreach-extra
    type: Opaque
    stringData:
      token: "secret"
```

Values in `data` and `stringData` pass through `tpl`, so release/chart values can
be referenced.

## Extra Manifests

Use `extraManifests` for resources that do not deserve first-class chart knobs:

```yaml
extraManifests:
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: "{{ include \"portreach.fullname\" . }}-extra"
    data:
      release: "{{ .Release.Name }}"
```

Entries may be YAML objects or raw YAML strings; both pass through `tpl`.

## Security Notes

The UI can trigger TCP checks from every agent node. Expose it only on trusted
networks or enable SSO and `agent.targetPolicy.allow` / `deny`.

The agent defaults to `hostNetwork: true` and `hostPort.enabled: true` so probes
egress from the node network. That is an intentional Pod Security Standards
exception; disable both for restricted namespaces:

```yaml
agent:
  network:
    hostNetwork: false
    hostPort:
      enabled: false
```

`networkPolicy.enabled` is off by default. If enabled, UI ingress is denied until
`networkPolicy.ui.ingress` is set; UI egress is limited to DNS, agents, and
`networkPolicy.ui.extraEgress`. Some CNIs do not enforce NetworkPolicy for
`hostNetwork` pods.

## Validation

```sh
helm lint charts/portreach
helm template portreach charts/portreach
helm template portreach charts/portreach | kubeconform -kubernetes-version 1.25.0 -strict
```
