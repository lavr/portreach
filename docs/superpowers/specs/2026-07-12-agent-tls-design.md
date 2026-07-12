# Agent TLS Design

## Summary

Add optional TLS to the UI-to-agent hop without removing or changing the
existing HTTP listener. An agent may listen on HTTP and HTTPS at the same time.
HTTP remains the backward-compatible default; the UI uses one globally
configured transport (`http` or `https`) for all discovered agents.

In Kubernetes, portreach does not issue certificates. An external controller
such as cert-manager creates and rotates a Secret containing the server
certificate and private key. The chart mounts that Secret into every agent, and
the agent adopts a valid replacement certificate without a process restart.

## Goals

- Keep the existing HTTP agent listener and all current defaults unchanged.
- Add an optional HTTPS listener on a distinct address/port.
- Let HTTP and HTTPS serve the same handler concurrently.
- Reload a rotated server certificate without restarting the agent.
- Verify agent certificates by default, including when discovery connects to
  pod IP addresses from a headless Service.
- Support a private CA from a file or Kubernetes Secret.
- Provide an explicit insecure certificate-verification escape hatch for
  development and self-signed deployments.
- Keep the implementation in the Go standard library.

## Non-goals

- Issuing certificates or creating cert-manager resources in the chart.
- Replacing the existing shared bearer token with mTLS client authentication.
- Supporting per-agent mixtures of HTTP and HTTPS within one UI process.
- Disabling the existing HTTP agent listener.
- Hot-reloading the UI trust bundle; changing the root CA requires a UI rollout.
- Adding a TLS proxy sidecar or a new file-watching dependency.

## CLI contract

### Agent server

The existing `--listen` flag continues to configure the HTTP listener and
defaults to `:8732`. TLS is disabled when `--tls-listen` is empty.

The agent adds:

- `--tls-listen` / `PORTREACH_AGENT_TLS_LISTEN`: optional HTTPS listen address.
- `--tls-cert-file` / `PORTREACH_AGENT_TLS_CERT_FILE`: PEM certificate chain.
- `--tls-key-file` / `PORTREACH_AGENT_TLS_KEY_FILE`: PEM private key.

When `--tls-listen` is non-empty, both certificate paths are required. Supplying
only one certificate path, supplying certificate paths without a TLS listener,
or configuring the same effective HTTP and HTTPS listen address is a startup
configuration error with exit code 2.

The HTTP and HTTPS `http.Server` instances share the same handler and security
configuration. Consequently `/check`, `/healthz`, `/metrics`, bearer-token
authentication, rate limiting, metadata protection, and target policy behave
identically on both transports.

### UI client

The UI adds:

- `--agent-scheme` / `PORTREACH_AGENT_SCHEME`: `http` or `https`; default
  `http`.
- `--agent-tls-ca-file` / `PORTREACH_AGENT_TLS_CA_FILE`: optional PEM trust
  bundle. Empty uses the system trust store.
- `--agent-tls-server-name` / `PORTREACH_AGENT_TLS_SERVER_NAME`: optional TLS
  name override.
- `--agent-tls-insecure-skip-verify` /
  `PORTREACH_AGENT_TLS_INSECURE_SKIP_VERIFY`: disable chain and hostname
  verification; default `false`.

The UI continues to discover individual agents as `ip:port`. In HTTPS mode it
builds `https://ip:port/check` URLs. `serverName` supplies the certificate name
and SNI value, so the UI still reaches each pod directly rather than sending
requests through Service load balancing.

TLS-specific client flags are rejected when `agent-scheme=http`; this prevents
configuration that appears protective but has no effect. An invalid scheme,
missing CA file, or CA file with no valid certificates is also a startup
configuration error with exit code 2.

When insecure verification is enabled, portreach writes a prominent startup
warning to stderr. The option disables both certificate-chain and hostname
verification and is documented as a development/emergency mode, not a normal
way to trust a private issuer.

## Server certificate reload

The agent loads and validates the initial certificate/key pair before opening
either listener. A missing, unreadable, or mismatched initial pair prevents
startup.

The active `tls.Certificate` is held behind an atomic pointer. The TLS
`GetCertificate` callback normally returns that cached certificate without
touching the filesystem. At most once per second, the first new handshake after
the interval checks both certificate paths, following Kubernetes projected
Secret symlinks. Only a changed path target or file metadata triggers PEM reads
and `tls.LoadX509KeyPair`.

A newly loaded pair is published atomically only after both files parse and
match. If a replacement is temporarily missing, unreadable, or invalid, the
agent continues serving the last known-good certificate and emits a
rate-limited warning to stderr. A later handshake retries the check and adopts a
valid replacement. Existing keep-alive connections and established TLS
sessions naturally continue until they reconnect.

This design bounds steady-state filesystem work to approximately two metadata
checks per second per agent pod, independent of handshake volume, and reads PEM
data only after a detected change. It avoids a dependency on `fsnotify` and
works with Kubernetes' atomic projected-Secret symlink updates as well as
ordinary files replaced by an operator.

TLS explicitly requires version 1.2 or newer.

## Listener lifecycle

The existing single-server shutdown helper is generalized to run one or more
named HTTP servers under the same signal context. The agent passes its HTTP
server and, when enabled, its HTTPS server. The UI continues to pass only one
server.

Each listener prints a protocol-labelled startup banner to stderr. If either
listener fails to bind or returns an unexpected serve error, the helper shuts
down every running server with the existing bounded grace period and returns an
exit-code-1 error. SIGINT or SIGTERM similarly drains both listeners. The
coordination path must not leak goroutines or block waiting for a server that
never started.

## Helm contract

The chart adds this values block:

```yaml
agent:
  tls:
    enabled: false
    port: 8733
    hostPort: ""
    secretName: ""
    certKey: tls.crt
    privateKeyKey: tls.key
    caSecret: ""
    caKey: ca.crt
    serverName: ""
    insecureSkipVerify: false
```

With `enabled: false`, the rendered workloads, Service, discovery port, and
agent transport remain HTTP-only and match current behavior.

With `enabled: true`:

- `secretName` is required and refers to an externally managed Secret. The
  chart never renders that Secret or a Certificate resource.
- The agent DaemonSet mounts `certKey` and `privateKeyKey` read-only and starts
  the additional HTTPS listener on `tls.port`.
- The agent container exposes a named `https` port. When
  `agent.network.hostPort.enabled` is true, its host port defaults to
  `tls.port`; a non-empty `tls.hostPort` overrides it.
- The headless Service exposes both named `http` and `https` ports.
- The UI switches its global agent scheme and discovery port to `https` and
  `tls.port`.
- `serverName` defaults to the chart-computed headless Service DNS name. A
  non-empty value overrides that name.
- A non-empty `caSecret` is mounted read-only into the UI, and `caKey` becomes
  the `--agent-tls-ca-file`. `caSecret` may equal `secretName` when the same
  Secret contains `ca.crt`. Empty `caSecret` uses system roots.
- `insecureSkipVerify` maps to the explicit UI flag and defaults to false.

The TLS Secret does not receive a checksum pod annotation: the desired rotation
mechanism is kubelet's projected-volume update plus the agent's certificate
reloader, not a DaemonSet rollout. The optional CA Secret also has no checksum;
operators roll the UI when the trust root changes.

Kubernetes liveness, readiness, and startup probes remain on the named HTTP
port and public `/healthz` endpoint. This preserves stable health reporting
during certificate rotation while startup validation still prevents an agent
with an invalid initial TLS pair from becoming available.

The schema and templates reject a missing TLS Secret, ports outside
`1..65535`, and conflicts between the effective HTTP and HTTPS listen/host
ports. File-key and Secret-name fields are non-empty when their associated
feature is enabled.

## Documentation

Update the root and chart configuration tables and the deployment guide with:

- standalone dual-listener examples;
- the secure default using a private CA and `serverName`;
- a cert-manager-managed Secret example, explicitly described as an external
  prerequisite rather than a chart-created resource;
- the server leaf-certificate hot-reload behavior;
- the UI-rollout requirement for CA rotation;
- a warning that `insecureSkipVerify` disables both chain and hostname checks;
- confirmation that bearer-token authentication remains necessary because TLS
  protects transport but does not authorize callers.

## Testing

All tests remain hermetic and use generated in-memory or temporary-file test
certificates; they do not contact real networks or Kubernetes clusters.

### Agent and command tests

- TLS disabled preserves the existing HTTP-only flag behavior.
- TLS requires a listener, certificate, and key in valid combinations.
- The initial certificate pair is validated before serving.
- HTTP and HTTPS simultaneously serve the same handler.
- A signal or listener error shuts down both servers without leaking a
  goroutine.
- The reload callback does not read PEM on every handshake.
- Replacing certificate files publishes a certificate with the new serial
  number after the check interval.
- A malformed replacement keeps the last known-good certificate, warns once
  per retry window, and later recovers when valid files appear.
- Concurrent handshakes and reload checks are race-safe.

### UI tests

- HTTP URLs and bearer headers are unchanged by default.
- HTTPS rejects an untrusted self-signed certificate by default.
- A configured CA accepts the same certificate.
- A hostname mismatch fails without `serverName` and succeeds with the correct
  override.
- `insecureSkipVerify` accepts the untrusted certificate and produces the
  startup warning.
- Invalid schemes, CA bundles, and HTTP/TLS flag combinations fail closed.

### Chart tests

- Default rendering contains no TLS arguments, ports, or mounts.
- Enabled rendering contains both listeners, both Service ports, the external
  certificate mount, HTTPS UI settings, and the computed server name.
- A separate CA Secret is mounted only into the UI.
- The same Secret can supply server certificate files and `ca.crt`.
- Health probes remain HTTP.
- Host-port defaults and overrides render correctly.
- Missing Secrets, invalid ports, and conflicting ports fail rendering or
  schema validation with specific messages.

Before completion, run `gofmt`/`goimports` on changed Go files and verify:

```sh
go build ./...
go vet ./...
go test ./...
go test -race ./internal/cmd ./internal/ui
helm lint charts/portreach
```
