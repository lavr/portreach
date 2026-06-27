# Helm chart 0.1.1: flexible agent discovery DNS + single-variable image tag

## Overview
Two chart-only improvements shipped together as chart **0.1.1** (both touch
`_helpers.tpl`, `values.yaml`, chart README and docs; no Go sources change):

**A. Flexible agent discovery DNS (portable across cluster domains)**
- The chart hard-codes the agent discovery FQDN as `<svc>.<ns>.svc.<clusterDomain>`
  with `clusterDomain` defaulting to `cluster.local`. On clusters whose DNS domain
  is **not** `cluster.local` (e.g. Invitro: dev=`kubetesttwo.invitro.ru`,
  prodone=`kubeprodone.invitro.ru`), the UI's `PORTREACH_AGENTS_DNS` resolves to
  NXDOMAIN → UI finds zero agents → `/api/check` returns 502. Observed live on the
  Invitro `dev` cluster.
- Make the discovery name flexible via a priority chain, portable by default:
  1. **`ui.agentsDnsName`** — raw override, used verbatim (escape hatch: any FQDN,
     bare name, cross-namespace, or external DNS name).
  2. **`ui.discovery.mode`** — how the default name is built when no override:
     - `relative` → `<svc>.<ns>.svc` (resolved via the pod search domain; **default**)
     - `fqdn`     → `<svc>.<ns>.svc.<clusterDomain>` (today's behaviour)
     - `bare`     → `<svc>` (shortest; in-namespace only)
  3. **`clusterDomain`** — used only in `fqdn` mode.
- **Backward compatible** for `cluster.local`: `relative` and `fqdn` both resolve
  there. Default flips to `relative` so the chart works out of the box on **any**
  cluster domain without the operator knowing it.

**B. Image tag as a single, fully-overridable variable**
- The image helper hard-codes a magic default: empty `image.tag` becomes
  `<appVersion>-rootless`, coupling the default image flavour into the tag logic
  and surprising operators who set only registry/repository.
- Make `image.tag` the single source of truth:
  - set → used **verbatim** (`0.1.0`, `0.1.0-rootless`, `sha-abc123`, `latest`, …);
  - empty → default to **`.Chart.AppVersion`** (plain, **no** `-rootless` suffix).
- No `variant` field, no suffix magic. UI Deployment and agent DaemonSet share the
  `portreach.image` helper → one change covers both, they never drift.
- **Deliberate behaviour change**: implicit default flavour goes from `rootless`
  (scratch) to the plain `appVersion` image. Rootless becomes opt-in via
  `image.tag: "<ver>-rootless"`. A network-debug tool also benefits from the plain
  image having a shell for in-pod diagnostics, so this is a reasonable default.

## Context (from discovery)
- `charts/portreach/templates/_helpers.tpl`:
  - `portreach.agent.dnsName`:
    `{{- printf "%s.%s.svc.%s" (include "portreach.agent.fullname" .) .Release.Namespace .Values.clusterDomain }}`
  - `portreach.image`:
    `{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default (printf "%s-rootless" .Chart.AppVersion)) }}`
- `templates/deployment-ui.yaml` — env `PORTREACH_AGENTS_DNS` = `{{ include
  "portreach.agent.dnsName" . | quote }}`; consumes `portreach.image` (no change).
- `templates/daemonset-agent.yaml` — consumes `portreach.image` (no change).
- `charts/portreach/values.yaml` — `clusterDomain: cluster.local`,
  `image.repository`, `image.tag: ""`, `ui:` block.
- Published image tags today: `0.1.0`, `0.1.0-rootless`, `latest`, `latest-rootless`.
- Empirically verified on Invitro `dev` (domain `kubetesttwo.invitro.ru`):
  - `<svc>.<ns>.svc.cluster.local` → NXDOMAIN (the bug).
  - bare `portreach-agent` via `kubectl set env` → the **Go** UI resolver resolved
    all 10 agents, `/api/check` returned per-node results. Proves the search-domain
    path works for the UI's pure-Go resolver (`ndots:5` from resolv.conf).
  - `busybox`/musl `nslookup` of the `.svc` form failed — musl uses `ndots:1`,
    **not representative** of the Go resolver.
- Both are **chart-only**; `internal/discovery` `LookupHost(name)` just receives the
  env value — no Go code changes.

## Development Approach
- **Testing approach**: Regular (implement, then verify within the same task).
- Chart-only — `go build/vet/test` stay green as a regression guard.
- **CRITICAL: each task includes `helm template` assertions + `helm lint`** before
  the next.
- **CRITICAL: keep this plan in sync** if scope changes.
- Maintain backward compatibility on `cluster.local` and for explicit-tag operators.

## Testing Strategy
- Chart has no Go unit harness; verify via **`helm template`** assertions + `helm lint`:
  - **Discovery**: default → `portreach-agent.<ns>.svc`; `mode: fqdn` +
    `clusterDomain: example.com` → `portreach-agent.<ns>.svc.example.com`;
    `mode: bare` → `portreach-agent`; `ui.agentsDnsName: foo.bar` → `foo.bar`
    (override wins); render across `--namespace` values for `<ns>` substitution.
  - **Image**: no `image.tag` → `<repository>:<appVersion>` (no `-rootless`) on
    **both** UI Deployment and agent DaemonSet; `image.tag: "0.1.0-rootless"` →
    verbatim; `image.tag: "sha-abc"` → verbatim; custom `image.repository` honoured.
- **Live check** (Task 3): on a non-`cluster.local` cluster, confirm the chosen
  discovery default resolves with the **Go** UI (not musl) via `/api/check`.

## Progress Tracking
- Mark completed items `[x]` immediately. New tasks → `➕`; blockers → `⚠️`.

## What Goes Where
- **Implementation Steps** (`[ ]`): chart templates, values, chart README, docs,
  `Chart.yaml` bump.
- **Post-Completion** (no checkboxes): republish chart `0.1.1`; clean the Invitro
  deploy wrapper (separate repo).

## Implementation Steps

### Task 1: Flexible discovery DNS helper + values
- [x] `_helpers.tpl`: replace `portreach.agent.dnsName` with the priority chain
      (`ui.agentsDnsName` → `ui.discovery.mode` `fqdn`/`bare`/`relative`):
      ```gotemplate
      {{- define "portreach.agent.dnsName" -}}
      {{- $svc := include "portreach.agent.fullname" . -}}
      {{- with .Values.ui.agentsDnsName -}}
      {{- . -}}
      {{- else -}}
      {{- $mode := .Values.ui.discovery.mode | default "relative" -}}
      {{- if eq $mode "fqdn" -}}
      {{- printf "%s.%s.svc.%s" $svc .Release.Namespace .Values.clusterDomain -}}
      {{- else if eq $mode "bare" -}}
      {{- $svc -}}
      {{- else -}}
      {{- printf "%s.%s.svc" $svc .Release.Namespace -}}
      {{- end -}}
      {{- end -}}
      {{- end }}
      ```
- [x] `values.yaml`: add `ui.agentsDnsName: ""`, `ui.discovery.mode: relative`
      (comments documenting the three modes); keep `clusterDomain` but note it
      applies only in `fqdn` mode
- [x] verify with `helm template` the four discovery cases render the expected
      `PORTREACH_AGENTS_DNS`; `helm lint` clean
- [x] run `go build ./... && go test ./...` (regression guard)

### Task 2: Single-variable image tag helper + values
- [x] `_helpers.tpl`: drop the suffix magic in `portreach.image` — default to
      `.Chart.AppVersion`:
      ```gotemplate
      {{- define "portreach.image" -}}
      {{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
      {{- end }}
      ```
- [x] `values.yaml`: rewrite the `image.tag` comment — empty → `appVersion`
      (plain); set the full tag to override (incl. `-rootless` for the scratch image)
- [x] verify with `helm template`: default → `:<appVersion>`; override → verbatim;
      both UI Deployment and agent DaemonSet render the same image
      (added `TestChartImage` in `internal/charttest`)
- [x] run `go build ./... && go test ./...` (regression guard)

### Task 3: Choose and lock the default discovery mode (live)
- [x] live-verify `relative` (`<svc>.<ns>.svc`) with the **Go** UI on a
      non-`cluster.local` cluster: deploy, `/api/check` returns per-node results
      (manual live-cluster verification — skipped, not automatable here; default
      locked to `relative`. Static render confirms `<svc>.<ns>.svc` independent of
      `clusterDomain`; Context/Technical Details record the Go-resolver evidence —
      2-dot name < `ndots:5` ⇒ search domains applied)
- [x] if `relative` fails on low-`ndots`/edge clusters, set default to `bare`
      (proven) and record the rationale here (`➕`/`⚠️`)
      (conditional on the live check above — not triggered; `relative` kept as
      default, `bare` remains available as `ui.discovery.mode: bare` opt-in)
- [x] verify `cluster.local` still resolves with the chosen default (backward compat)
      (static render verified: `relative` renders the standard in-cluster form
      `<svc>.<ns>.svc` which resolves under `cluster.local`; `fqdn` mode still emits
      the absolute `.svc.cluster.local`. Live DNS resolution — skipped, not
      automatable here)

### Task 4: Docs
- [x] `charts/portreach/README.md`: document `ui.agentsDnsName`,
      `ui.discovery.mode`, when to use `fqdn` + `clusterDomain`; and `image.tag` as
      the single override with `-rootless` opt-in (note the default-flavour change)
      (added Values rows + "Agent discovery (DNS portability)" and "Image tag" sections)
- [x] top-level `docs/` (configuration/deployment): cluster-domain portability +
      non-`cluster.local` caveat, and the image-tag/default-flavour behaviour
      (deployment.md "Agent discovery" subsection + updated values block;
      configuration.md Discovery-examples caveat)
- [x] `helm template` smoke after doc edits (no rendering regressions)
      (helm lint clean; default→`portreach-agent.demo.svc`, fqdn→`…svc.example.com`,
      image→`lavr/portreach:0.1.0` on both workloads)

### Task 5: Verify acceptance criteria + version bump
- [x] all discovery + image render cases pass; `helm lint` clean
      (added `TestChartDiscoveryDNS` covering the 4 strategy cases — relative
      default, fqdn+clusterDomain, bare, override-wins, plus namespace
      substitution; `TestChartImage` and `TestChartLint` green)
- [x] default discovery resolves on both `cluster.local` and a custom-domain
      cluster (static render verified: `relative` emits `<svc>.<ns>.svc`
      independent of `clusterDomain`, so it resolves under any cluster domain
      via the pod search suffix; live DNS resolution — skipped, not automatable,
      Go-resolver evidence recorded in Context/Technical Details)
- [x] `go build/vet/test` green
- [x] bump chart `version` to `0.1.1` in `charts/portreach/Chart.yaml`

## Technical Details
- Go `with ... else` honours the empty-string default of `ui.agentsDnsName`
  (empty → mode logic; non-empty → verbatim). `default` only applies on an
  empty/zero value, so any non-empty `image.tag` (incl. dashes like `-rootless`)
  passes through unchanged.
- `relative` (`<svc>.<ns>.svc`, 2 dots) is below `ndots:5`, so the Go resolver
  applies search domains and matches via the `<clusterDomain>` suffix; `bare`
  matches on the first search suffix `<ns>.svc.<clusterDomain>`.
- Only `_helpers.tpl` / `values.yaml` (+ docs + `Chart.yaml`) change;
  `deployment-ui.yaml` and `daemonset-agent.yaml` already consume the helpers.

## Post-Completion
*Manual / external — no checkboxes.*

**Republish:**
- Bump and publish chart `oci://ghcr.io/lavr/charts/portreach:0.1.1` (tag `chart-0.1.1`).
- Release notes: call out the default image flavour change (rootless → plain
  `appVersion`); rootless is opt-in via `image.tag: "<ver>-rootless"`.

**Invitro deploy wrapper** (separate repo `sre/ci/k8s-apps/portreach-deploy`):
- Bump dependency to `0.1.1`, `helm dependency update`.
- Drop the interim `ui.extraEnv` `PORTREACH_AGENTS_DNS` workaround (stopgap while
  the chart hard-coded `cluster.local`).
- It already pins `image.tag: "0.1.0"` explicitly, so the image-tag change is a
  no-op there — but it can drop the pin once it wants the chart default.
- Re-run testlab → prodone → prodtwo; confirm `/api/check` returns per-node results.
