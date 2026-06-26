# Configurable UI branding (title / description / footer) for environment identification

## Overview
- Make the main UI page (`/`) brandable via config so operators can tell **which
  environment / cluster** they are looking at when a company runs several
  Kubernetes clusters each with its own portreach.
- Three new configurable, **HTML-capable** fields, all set via config:
  - **title** — the page heading (`<h1>`). When empty in config, the heading is
    **not rendered at all** (no empty `<h1>`).
  - **description** — a new block rendered **under the title**.
  - **footer** — a new block rendered at the bottom of the page.
- All three accept raw HTML (operator-controlled, trusted input → rendered with
  `template.HTML`, not escaped). The browser tab `<title>` is also set from the
  configured title (HTML stripped) so clusters are distinguishable by tab.
- **Backward compatible**: unset config → today's behaviour. Default title falls
  back to the current `portreach — reachability from every node`; description and
  footer default to empty (nothing rendered).

## Coordination / sequencing
- Touches the same files as `docs/plans/2026-06-27-ui-sso-auth.md` Task 7
  (`internal/ui/web/index.html`, `internal/ui/web.go`, `internal/cmd/ui.go`,
  helm `deployment-ui.yaml` / `values.yaml`). **Sequence this after the
  auth+i18n plan is merged** to avoid template conflicts.
- The branding strings are operator HTML, **not** localized — they are rendered
  verbatim regardless of `Accept-Language` (independent of the i18n layer).

## Context (from discovery)
- `internal/ui/web/index.html`: hard-coded `<h1>portreach &mdash; reachability
  from every node</h1>`; `<title>portreach</title>`. Rendered via
  `html/template` from `pageData` (`internal/ui/web.go` `handleIndex`).
- `internal/ui/server.go`: `New(disc, timeout)` builds `Server`; `Handler()`
  serves `/`, `/api/check`, `/healthz`.
- `internal/cmd/ui.go` `runUI`: flags + `PORTREACH_*` env (pattern: `envInt`,
  `os.Getenv`). Builds `ui.New(disc, *timeout)`.
- Helm `deployment-ui.yaml` passes args/env, supports `.Values.ui.extraEnv`.
- Tests next to code as `*_test.go` (`internal/ui/*_test.go`,
  `internal/cmd/cmd_test.go`) with `httptest`.

## Development Approach
- **Testing approach**: Regular (implement, then unit tests within the same task).
- Complete each task fully before the next; small focused changes.
- **CRITICAL: every task MUST include new/updated tests** (success + error paths).
- **CRITICAL: all tests must pass before starting the next task.**
- **CRITICAL: keep this plan in sync** if scope changes.
- Run `go build ./...`, `go vet ./...`, `go test ./...` after each change.
- Maintain backward compatibility — unset config = identical to today.

## Testing Strategy
- **Unit tests** every task via `httptest`: title present → `<h1>` rendered;
  title empty → no `<h1>`; description/footer rendered as raw HTML (not escaped);
  document `<title>` reflects configured title (tags stripped) or default.
- No new e2e framework (none exists); Go handler tests are the integration layer.

## Progress Tracking
- Mark completed items `[x]` immediately. New tasks → `➕`; blockers → `⚠️`.

## What Goes Where
- **Implementation Steps** (`[ ]`): code, tests, helm, docs — all in-repo.
- **Post-Completion** (no checkboxes): visual check in a real browser per cluster.

## Implementation Steps

### Task 1: Branding config (flags / env)
- [ ] add to `internal/cmd/ui.go` `runUI`: `--ui-title` (`PORTREACH_UI_TITLE`),
      `--ui-description` (`PORTREACH_UI_DESCRIPTION`), `--ui-footer`
      (`PORTREACH_UI_FOOTER`); flag value else env else default
- [ ] define a `ui.Branding` struct (`Title, Description, Footer string`) and an
      option/param on `ui.New` (e.g. `New(disc, timeout, Branding{...})`),
      defaulting unset Title to the current heading text
- [ ] write tests: flag/env precedence and default-title fallback parsing
- [ ] run tests — must pass before Task 2

### Task 2: Render branding in the page
- [ ] thread `Branding` into `Server` and into `pageData`
      (`internal/ui/web.go`), exposing `Title template.HTML`,
      `Description template.HTML`, `Footer template.HTML`, plus a plain
      `DocTitle string` (HTML-stripped title) for the `<title>` tag
- [ ] update `internal/ui/web/index.html`: render `<h1>{{.Title}}</h1>` **only
      when** title is non-empty; render `{{.Description}}` under the title and
      `{{.Footer}}` at the bottom when non-empty; set `<title>{{.DocTitle}}</title>`
- [ ] add minimal footer styling (muted, top border) consistent with existing CSS
- [ ] write tests: title-set renders `<h1>`; title-empty omits `<h1>`;
      description/footer rendered unescaped; `DocTitle` strips tags / falls back to
      `portreach`
- [ ] run tests — must pass before Task 3

### Task 3: Helm chart support
- [ ] `charts/portreach/values.yaml`: add `ui.branding` block (`title`,
      `description`, `footer`), all optional/empty by default
- [ ] `templates/deployment-ui.yaml`: pass `PORTREACH_UI_TITLE` /
      `PORTREACH_UI_DESCRIPTION` / `PORTREACH_UI_FOOTER` env when set (skip when
      empty so defaults apply)
- [ ] write/extend a `helm template` render assertion (branding set vs unset);
      run `helm lint`
- [ ] run tests — must pass before Task 4

### Task 4: Documentation
- [ ] `docs/configuration.md`: document the three flags/env, the HTML behaviour,
      the empty-title rule, and the security note (operator-trusted HTML →
      rendered unescaped; do not expose config to untrusted users)
- [ ] `docs/deployment.md`: per-cluster branding example (e.g. title
      `<span style="color:#b62324">PROD — eu-cluster</span>`) for environment
      identification
- [ ] `README.md`: brief mention of branding
- [ ] run `go test ./...` — no regression

### Task 5: Verify acceptance criteria
- [ ] verify: title configurable, empty title hides heading, description under
      title, footer at bottom, all support HTML, browser tab title reflects env
- [ ] verify edge cases: empty all (defaults), HTML in each field, very long values
- [ ] run full unit suite `go test ./... -v`; `go vet ./...`; `helm lint`
- [ ] verify `internal/ui` coverage stays ≥ 80%

### Task 6: [Final] Knowledge
- [ ] re-read docs for accuracy; note the branding config and HTML-trust caveat

*Note: ralphex automatically moves completed plans to `docs/plans/completed/`.*

## Technical Details
- **Config fields**: `Title`, `Description`, `Footer` (strings; HTML allowed).
  Flags `--ui-title|--ui-description|--ui-footer`, env `PORTREACH_UI_TITLE|
  _DESCRIPTION|_FOOTER`.
- **Rendering**: `template.HTML` for the three blocks (unescaped, operator-trusted).
  `<h1>` and the description/footer blocks are emitted only when their value is
  non-empty. Document `<title>` uses an HTML-stripped form of Title, defaulting to
  `portreach`.
- **Defaults**: Title → current heading (`portreach — reachability from every
  node`); Description → empty (omitted); Footer → empty (omitted).
- **Security**: branding HTML is rendered without escaping — this is safe only
  because it is set by the operator via flags/env/helm, never by end users.
  Documented explicitly.
- **Not in scope**: per-request/dynamic branding, logos/image upload, theming
  beyond the existing CSS — keep to title/description/footer text+HTML.

## Post-Completion
*Items requiring manual intervention or external systems — informational only.*

**Manual verification:**
- Deploy to two clusters with distinct titles/colors and confirm at a glance (page
  heading + browser tab) which environment is open.
- Confirm HTML (e.g. a colored `<span>`) renders as intended and an empty title
  produces no heading gap.
