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
  repository: lavr/portreach
  tag: ""            # defaults to <appVersion>-rootless

ui:
  replicaCount: 1
  timeout: 8s
  ingress:
    enabled: false   # enable + set hosts to expose externally

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
