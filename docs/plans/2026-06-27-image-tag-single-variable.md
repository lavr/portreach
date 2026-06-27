# Image tag as a single, fully-overridable variable

## Overview
- The image helper hard-codes a magic default: when `image.tag` is empty it
  becomes `<appVersion>-rootless`. This couples the **default image flavour**
  (scratch/rootless) into the tag logic and surprises operators who set only the
  registry/repository.
- Make `image.tag` the **single source of truth** for the whole tag:
  - set → used **verbatim** (`0.1.0`, `0.1.0-rootless`, `sha-abc123`, `latest`, …);
  - empty → default to **`.Chart.AppVersion`** (plain, **no** `-rootless` suffix).
- **No `variant` field, no suffix magic.** Operators override the entire tag with
  one value; both the UI Deployment and the agent DaemonSet (which share the
  `portreach.image` helper) get the same tag.
- **Deliberate behaviour change**: the implicit default flavour goes from
  `rootless` (scratch) to the plain `appVersion` image. Rootless becomes opt-in via
  `image.tag: "<ver>-rootless"`. A network-debug tool also benefits from the plain
  image having a shell for in-pod diagnostics, so this is a reasonable default.

## Context (from discovery)
- `charts/portreach/templates/_helpers.tpl` — `portreach.image`:
  ```gotemplate
  {{- define "portreach.image" -}}
  {{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default (printf "%s-rootless" .Chart.AppVersion)) }}
  {{- end }}
  ```
- Consumed by both `templates/deployment-ui.yaml` and `templates/daemonset-agent.yaml`
  via `{{ include "portreach.image" . | quote }}` — one change covers both.
- `charts/portreach/values.yaml` — `image.repository`, `image.tag: ""`, with a
  comment describing the current `-rootless` default (to be rewritten).
- Published tags today: `0.1.0`, `0.1.0-rootless`, `latest`, `latest-rootless`.
- Chart-only change; no Go sources touched.

## Development Approach
- **Testing approach**: Regular (implement, then verify within the same task).
- Chart-only — `go build/vet/test` stay green as a regression guard.
- **CRITICAL: each task includes `helm template` verification + `helm lint`** before
  the next.
- **CRITICAL: keep this plan in sync** if scope changes.

## Testing Strategy
- `helm template` assertions on the rendered `image:` of **both** the UI Deployment
  and the agent DaemonSet:
  - no `image.tag` → `<repository>:<appVersion>` (no `-rootless`);
  - `image.tag: "0.1.0-rootless"` → `<repository>:0.1.0-rootless` (verbatim);
  - `image.tag: "sha-abc"` → `<repository>:sha-abc` (verbatim);
  - custom `image.repository` honoured.
- `helm lint` clean.

## Progress Tracking
- Mark completed items `[x]` immediately. New tasks → `➕`; blockers → `⚠️`.

## What Goes Where
- **Implementation Steps** (`[ ]`): chart helper, values, chart README/docs.
- **Post-Completion** (no checkboxes): republish chart `0.1.1`; the Acme deploy
  wrapper already pins `image.tag: "0.1.0"` explicitly, so it is unaffected — but
  note the default flavour change in release notes.

## Implementation Steps

### Task 1: Simplify the image helper + values
- [ ] `_helpers.tpl`: drop the suffix magic — default to `.Chart.AppVersion`:
      ```gotemplate
      {{- define "portreach.image" -}}
      {{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
      {{- end }}
      ```
- [ ] `values.yaml`: rewrite the `image.tag` comment — empty → `appVersion`
      (plain); set the full tag to override (incl. `-rootless` for the scratch image)
- [ ] verify with `helm template`: default → `:<appVersion>`; override → verbatim;
      both UI Deployment and agent DaemonSet render the same image
- [ ] run `go build ./... && go test ./...` (regression: nothing else moved)

### Task 2: Docs
- [ ] `charts/portreach/README.md`: document `image.tag` as the single override and
      the `-rootless` opt-in; note the default-flavour change (rootless → plain)
- [ ] top-level `docs/` (configuration/deployment): mention the same
- [ ] `helm template` smoke after doc edits

### Task 3: Verify acceptance criteria
- [ ] all render cases pass; `helm lint` clean
- [ ] `go build/vet/test` green; chart version bumped to `0.1.1` in `Chart.yaml`

## Technical Details
- `default` only applies on an empty/zero value, so any non-empty `image.tag`
  (including ones containing dashes like `-rootless`) passes through unchanged.
- Single helper → UI and agent never drift in tag.

## Post-Completion
*Manual / external — no checkboxes.*

- Republish chart `oci://ghcr.io/lavr/charts/portreach:0.1.1`.
- Release notes: call out the default image flavour change (rootless → plain
  `appVersion`); rootless is opt-in via `image.tag: "<ver>-rootless"`.
- Acme deploy wrapper pins `image.tag` explicitly already — no change required,
  but it can drop the pin once it wants the chart default.

## Related
- Agent discovery DNS flexibility (the cluster-domain portability fix) is tracked
  in `docs/plans/2026-06-27-chart-discovery-flexibility.md`.
