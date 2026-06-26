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

## Values

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `lavr/portreach` | Image repository. |
| `image.tag` | `""` | Defaults to `<appVersion>-rootless`. |
| `clusterDomain` | `cluster.local` | DNS domain for the headless service FQDN. |
| `ui.replicaCount` | `1` | UI replicas. |
| `ui.timeout` | `8s` | Overall fan-out budget per check. |
| `ui.service.type` | `ClusterIP` | UI service type. |
| `ui.service.port` | `80` | UI service port. |
| `ui.ingress.enabled` | `false` | Enable the UI Ingress. |
| `agent.hostNetwork` | `true` | Run agents on host network (real node egress). |
| `agent.port` | `8732` | Agent listen + hostPort. |
| `agent.allow` | `""` | Allow-CIDR list (empty = allow all). |
| `agent.deny` | `""` | Deny-CIDR list (takes precedence). |
| `agent.tolerations` | `[{operator: Exists}]` | Run on every node, incl. tainted. |
| `serviceAccount.create` | `true` | Create a ServiceAccount. |
