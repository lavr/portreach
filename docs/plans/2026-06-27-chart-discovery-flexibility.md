# Flexible agent discovery DNS name (portable across cluster domains)

## Overview
- The Helm chart hard-codes the agent discovery FQDN as
  `<svc>.<ns>.svc.<clusterDomain>` with `clusterDomain` defaulting to
  `cluster.local`. On clusters whose DNS domain is **not** `cluster.local`
  (e.g. Acme: dev=`kube-dev.corp.example`, prodone=`kube-prod.corp.example`),
  the UI's `PORTREACH_AGENTS_DNS` resolves to NXDOMAIN → UI finds zero agents →
  `/api/check` returns 502. Observed live on the Acme `dev` cluster.
- Make the discovery name **flexible** via a priority chain, portable by default:
  1. **`ui.agentsDnsName`** — raw override, used verbatim (escape hatch: any FQDN,
     bare name, cross-namespace, or external DNS name).
  2. **`ui.discovery.mode`** — how the default name is built when no override:
     - `relative` → `<svc>.<ns>.svc` (resolved via the pod search domain; default)
     - `fqdn`     → `<svc>.<ns>.svc.<clusterDomain>` (today's behaviour)
     - `bare`     → `<svc>` (shortest; in-namespace only)
  3. **`clusterDomain`** — used only in `fqdn` mode.
- **Backward compatible** for `cluster.local` clusters: `relative` and `fqdn`
  both resolve there. Default flips to `relative` so the chart works out of the
  box on **any** cluster domain without the operator knowing it.

## Context (from discovery)
- `charts/portreach/templates/_helpers.tpl` — `portreach.agent.dnsName`:
  ```gotemplate
  {{- printf "%s.%s.svc.%s" (include "portreach.agent.fullname" .) .Release.Namespace .Values.clusterDomain }}
  ```
- `charts/portreach/templates/deployment-ui.yaml` — env `PORTREACH_AGENTS_DNS`
  value is `{{ include "portreach.agent.dnsName" . | quote }}` (no change needed).
- `charts/portreach/values.yaml` — `clusterDomain: cluster.local`, `ui:` block.
- Empirically verified on Acme `dev` (domain `kube-dev.corp.example`):
  - `<svc>.<ns>.svc.cluster.local` → NXDOMAIN (the bug).
  - bare `portreach-agent` set via `kubectl set env` → the **Go** UI resolver
    resolved all 10 agents and `/api/check` returned per-node results. Proves the
    search-domain path works for the UI's pure-Go resolver.
  - `busybox`/musl `nslookup` of the relative/`.svc` form failed — musl uses
    `ndots:1`, **not representative** of the Go resolver (`ndots:5` from resolv.conf).
- Discovery code: `internal/discovery` `LookupHost(name)`; the chart only feeds it
  the name via env — this change is **chart-only**, no Go code changes.

## Development Approach
- **Testing approach**: Regular (implement, then verify within the same task).
- Chart-only change — no Go sources touched; `go build/vet/test` stay green and
  serve as a regression guard that nothing else moved.
- **CRITICAL: every task includes verification** (`helm template` assertions +
  `helm lint`) before the next task.
- **CRITICAL: keep this plan in sync** if scope changes.
- Maintain backward compatibility on `cluster.local`.

## Testing Strategy
- The chart has no unit-test harness; verification is via **`helm template`**
  assertions on the rendered `PORTREACH_AGENTS_DNS` env value, plus `helm lint`:
  - default (no override) → `portreach-agent.<ns>.svc`
  - `mode: fqdn` + `clusterDomain: example.com` → `portreach-agent.<ns>.svc.example.com`
  - `mode: bare` → `portreach-agent`
  - `ui.agentsDnsName: foo.bar` → `foo.bar` (override wins over mode)
  - rendered across `--namespace` values to confirm `<ns>` substitution.
- **Live check** (Task 3): on a non-`cluster.local` cluster, confirm the chosen
  default actually resolves with the **Go** UI (not musl), via `/api/check`.

## Progress Tracking
- Mark completed items `[x]` immediately. New tasks → `➕`; blockers → `⚠️`.

## What Goes Where
- **Implementation Steps** (`[ ]`): chart templates, values, chart README, docs.
- **Post-Completion** (no checkboxes): republish chart `0.1.1`; clean the Acme
  deploy wrapper (separate repo) to drop the interim `ui.extraEnv` workaround.

## Implementation Steps

### Task 1: Rewrite `portreach.agent.dnsName` helper + values
- [ ] `_helpers.tpl`: replace the helper with the priority chain
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
- [ ] `values.yaml`: add `ui.agentsDnsName: ""`, `ui.discovery.mode: relative`
      (with comments documenting the three modes); keep `clusterDomain` but note
      it applies only in `fqdn` mode
- [ ] verify with `helm template` the four cases from Testing Strategy render the
      expected `PORTREACH_AGENTS_DNS`; `helm lint` clean
- [ ] run `go build ./... && go test ./...` (regression: nothing else changed)

### Task 2: Choose and lock the default mode
- [ ] live-verify `relative` (`<svc>.<ns>.svc`) with the **Go** UI on a
      non-`cluster.local` cluster: deploy, `/api/check` returns per-node results
- [ ] if `relative` fails on low-`ndots`/edge clusters, set default to `bare`
      (proven) and record the rationale in this plan (`➕`/`⚠️`)
- [ ] verify `cluster.local` still resolves with the chosen default (backward compat)

### Task 3: Docs
- [ ] `charts/portreach/README.md`: document `ui.agentsDnsName`,
      `ui.discovery.mode`, and when to use `fqdn` + `clusterDomain`
- [ ] top-level `docs/` (configuration/deployment): note the cluster-domain
      portability behaviour and the non-`cluster.local` caveat
- [ ] `helm template` smoke after doc edits (no rendering regressions)

### Task 4: Verify acceptance criteria
- [ ] all four render cases pass; `helm lint` clean; default resolves on both
      `cluster.local` and a custom-domain cluster
- [ ] `go build/vet/test` green; chart version bumped to `0.1.1` in `Chart.yaml`

## Technical Details
- Go `with ... else` honours the empty-string default of `ui.agentsDnsName`
  (empty → falls through to mode logic; non-empty → used verbatim).
- `relative` (`<svc>.<ns>.svc`, 2 dots) is below `ndots:5`, so the Go resolver
  applies search domains and matches `<svc>.<ns>.svc.<clusterDomain>` via the
  `<clusterDomain>` search suffix. `bare` matches on the first search suffix
  `<ns>.svc.<clusterDomain>`.
- No template other than `_helpers.tpl`/`values.yaml` changes; `deployment-ui.yaml`
  already consumes the helper.

## Post-Completion
*Manual / external — no checkboxes.*

**Republish:**
- Bump and publish chart `oci://ghcr.io/lavr/charts/portreach:0.1.1`.

**Acme deploy wrapper** (separate repo `sre/ci/k8s-apps/portreach-deploy`):
- Bump dependency to `0.1.1`, `helm dependency update`.
- Drop the interim `ui.extraEnv` override in `helm/portreach/values.yaml`
  (added as a stopgap while the chart hard-coded `cluster.local`).
- Re-run testlab → prodone → prodtwo; confirm `/api/check` returns per-node results.

## Related
- Image tag flexibility (drop the magic `-rootless` default; make `image.tag` a
  single, fully-overridable variable) is tracked separately in
  `docs/plans/2026-06-27-image-tag-single-variable.md`.
