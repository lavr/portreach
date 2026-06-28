# Configurable UI branding (main + login + denied pages; title / description / header / footer; env-var templating) for environment identification

## Overview
- Make the main UI page (`/`) brandable via config so operators can tell **which
  environment / cluster** they are looking at when a company runs several
  Kubernetes clusters each with its own portreach.
- Three new configurable, **HTML-capable** fields, all set via config:
  - **title** — the page heading (`<h1>`). Tri-state (see below): **unset** →
    today's localized heading; **set & empty** → `<h1>` not rendered at all;
    **set** → the configured value.
  - **description** — a new block rendered **under the title**.
  - **footer** — a new block rendered at the bottom of the page.
- All three accept raw HTML (operator-controlled, trusted input → rendered with
  `template.HTML`, not escaped). The browser tab `<title>` is also set from the
  configured title (HTML stripped) so clusters are distinguishable by tab.
- **Tri-state semantics for fields with an i18n default** (main title + its tab
  title, login title, login header): the config distinguishes **unset** from
  **set-but-empty**.
  - **unset** (env key absent / flag not passed) → the existing **localized**
    default (`app.heading` / `app.title` / `auth.login.*`) — identical to today.
  - **set & empty** (`PORTREACH_UI_TITLE=` or `--ui-title=""`) → suppress the
    element (no `<h1>` / no tab text override).
  - **set** → render the value.
  Implementation: env via `os.LookupEnv` (presence), flags via `fs.Visit`
  (explicitly passed). description/footer/login-footer have an empty default, so
  unset and set-empty behave identically (nothing rendered) — no tri-state needed.
- **Backward compatible**: unset config → today's behaviour (localized headings,
  no description/footer). Default heading stays the localized `app.heading`;
  description and footer default to empty (nothing rendered).
- **Login page branding** — the optional SSO login page (`internal/auth`,
  `templates/login.html`) is also brandable so operators can identify the
  environment *before* signing in: a configurable **login title** (browser tab),
  **login header** (`<h1>` above the provider buttons), and a new **login footer**
  block. Unset → today's i18n-driven title/heading and no footer.
- **Env-var templating in branding strings** — every branding string (main page
  *and* login: title, description, header, footer) supports referencing
  environment variables as template placeholders (e.g.
  `PORTREACH_UI_TITLE='PROD — ${CLUSTER_NAME}'`). This lets one chart/values set
  render distinct branding per cluster from injected env (`CLUSTER_NAME`,
  `HOSTNAME`, downward-API fields) without per-cluster string overrides.

## Coordination / sequencing
- The SSO auth + i18n work is **already merged to `main`** (the code below
  confirms it: `index.html` renders `{{.L.T "app.title"}}`/`{{.L.T "app.heading"}}`
  and `internal/auth` exists). This plan edits those same files
  (`internal/ui/web/index.html`, `internal/ui/web.go`, `internal/cmd/ui.go`,
  `internal/auth/*`, helm `deployment-ui.yaml` / `values.yaml`) — merge carefully.
- The branding strings are operator HTML, **not** localized — they are rendered
  verbatim regardless of `Accept-Language`. But when a field is **unset** they
  fall back to the **localized** i18n default (see tri-state in Overview), so the
  branding layer sits *on top of* i18n rather than replacing it.

## Context (from discovery)
- `internal/ui/web/index.html`: title/heading are **i18n-driven, not hard-coded** —
  `<title>{{.L.T "app.title"}}</title>` and `<h1>{{.L.T "app.heading"}}</h1>`.
  `app.title`=`portreach`; `app.heading`=`portreach — reachability from every node`
  (en) / `portreach — доступность с каждого узла` (ru). Rendered via `html/template`
  from `pageData` (`internal/ui/web.go` `handleIndex`), which already carries
  `L *i18n.Localizer` and `Lang`. **Implication**: an unset branding title must
  keep rendering the *localized* `app.heading`, never a static English constant.
- `internal/ui/server.go`: `New(disc, timeout) *Server` builds `Server` (fields
  `disc, client, timeout`); `Handler()` serves `/`, `/api/check`, `/healthz`.
  Only production caller is `buildUIHandler` (`cmd/ui.go`); tests also call `ui.New`.
- `internal/cmd/ui.go` `runUI`: flags + `PORTREACH_*` env (pattern: `envInt`,
  `os.Getenv`). `buildUIHandler` builds `ui.New(disc, *timeout)` and
  `auth.New(cfg, auth.WithLogger(logger))`.
- `internal/auth/auth.go`: `handleLogin` renders `templates/login.html` from an
  anonymous struct `{Lang, Title, Heading string; Buttons []loginButton}`, with
  `Title`/`Heading` from i18n (`loc.T("auth.login.title"|"auth.login.heading")`).
  The template has **no footer**. `renderDenied` renders `templates/denied.html`
  from `{Lang, Title, Heading, Message, LoginURL, LoginLabel}`, also i18n-driven
  and **unbranded** today. `Option`/`WithLogger` (`internal/auth/audit.go`) is the
  construction-option pattern; add `WithBranding` the same way.
- Helm `deployment-ui.yaml` passes args/env, supports `.Values.ui.extraEnv`.
- Tests next to code as `*_test.go` (`internal/ui/*_test.go`,
  `internal/cmd/cmd_test.go`, `internal/auth/*_test.go`) with `httptest`.

## Development Approach
- **Testing approach**: Regular (implement, then unit tests within the same task).
- Complete each task fully before the next; small focused changes.
- **CRITICAL: every task MUST include new/updated tests** (success + error paths).
- **CRITICAL: all tests must pass before starting the next task.**
- **CRITICAL: keep this plan in sync** if scope changes.
- Run `go build ./...`, `go vet ./...`, `go test ./...` after each change.
- Maintain backward compatibility — unset config = identical to today.

## Testing Strategy
- **Unit tests** every task via `httptest`. Main page: **tri-state** — unset →
  localized `app.heading` (test en **and** ru via `Accept-Language`); set-value →
  `<h1>` with value; set-empty → no `<h1>` but tab `<title>` still non-blank;
  description/footer rendered as raw HTML (not escaped); `DocTitle` strips tags.
- **Login + denied branding** (`internal/auth/auth_test.go`): branding overrides
  i18n title/heading; set-empty header suppresses `<h1>`; login footer unescaped
  when set / absent when empty; unset branding reproduces today's pages.
- **Tri-state resolution** (`internal/cmd`): unset→nil, set-empty→`""`,
  set→value; flag-over-env precedence.
- **Env templating**: `${VAR}`/`$VAR` substituted from env; undefined → empty;
  `$$` literal; nil tri-state untouched; env value containing HTML renders as HTML.
- No new e2e framework (none exists); Go handler tests are the integration layer.

## Progress Tracking
- Mark completed items `[x]` immediately. New tasks → `➕`; blockers → `⚠️`.
- [x] Go 1.25.4 installed locally under `.tools/go`; `go build ./...`, `go vet ./...`, `go test ./...`, and `helm lint charts/portreach` pass.

## What Goes Where
- **Implementation Steps** (`[ ]`): code, tests, helm, docs — all in-repo.
- **Post-Completion** (no checkboxes): visual check in a real browser per cluster.

## Implementation Steps

### Task 1: Branding config (flags / env, tri-state)
- [x] define `ui.Branding` with **tri-state title** — `Title *string` (nil =
      unset → localized default; non-nil = set, may be `""` to suppress) plus
      `Description, Footer string` (plain — empty = nothing rendered). Add a
      **variadic option** API: `New(disc, timeout, ...Option)` with
      `ui.WithBranding(Branding)` (mirrors `auth.WithLogger`), so existing
      `ui.New(disc, timeout)` callers/tests keep compiling
- [x] add to `internal/cmd/ui.go` `runUI`: `--ui-title` (`PORTREACH_UI_TITLE`),
      `--ui-description` (`PORTREACH_UI_DESCRIPTION`), `--ui-footer`
      (`PORTREACH_UI_FOOTER`). Resolve title as tri-state: explicitly-set flag
      (`fs.Visit`) **or** present env (`os.LookupEnv`) → non-nil `*string`
      (flag wins over env); neither → nil (unset). description/footer: flag else
      env else `""`
- [x] add a small `cmd` helper to read tri-state flag+env (returns `*string`) and
      a plain flag+env helper, both reusable for the login fields in Task 3
- [x] write tests: tri-state resolution (unset→nil, set-empty→non-nil `""`,
      set-value→value), flag-over-env precedence, description/footer precedence
- [x] run tests — must pass before Task 2

### Task 2: Render branding in the page
- [x] thread `Branding` into `Server` (via `WithBranding`) and into `pageData`
      (`internal/ui/web.go`). Compute per-request from the tri-state + the
      localizer `L`:
      - `Title template.HTML`, `ShowTitle bool` — unset → `app.heading`
        (localized) + show; set-empty → show=false; set → value + show
      - `DocTitle string` (HTML-stripped, plain) — unset → `app.title`
        (localized); set-empty → `app.title` (tab should never be blank); set →
        stripped value
      - `Description template.HTML`, `Footer template.HTML` (empty = omitted)
- [x] update `internal/ui/web/index.html`: render `<h1>{{.Title}}</h1>` only
      `{{if .ShowTitle}}`; render `{{.Description}}` / `{{.Footer}}` only when
      non-empty; set `<title>{{.DocTitle}}</title>`
- [x] add minimal footer styling (muted, top border) consistent with existing CSS
- [x] write tests: unset → localized `app.heading` (test both en + ru via
      `Accept-Language`) and `app.title`; set-value → renders value; set-empty →
      no `<h1>` but tab title still `app.title`; description/footer rendered
      unescaped; `DocTitle` strips tags
- [x] run tests — must pass before Task 3

### Task 3 ➕: Login + denied page branding (title / header / footer)
- [x] define `auth.LoginBranding{Title, Header *string; Footer string}` —
      tri-state `Title`/`Header` (nil = unset → i18n default; non-nil incl. `""`),
      plain `Footer` (empty = omitted). Add `auth.WithBranding(LoginBranding)`
      Option mirroring `WithLogger` (`internal/auth/audit.go`); store on
      `Authenticator`
- [x] add flags/env in `internal/cmd/ui.go` (reuse the Task 1 tri-state helper):
      `--login-title` (`PORTREACH_LOGIN_TITLE`), `--login-header`
      (`PORTREACH_LOGIN_HEADER`), `--login-footer` (`PORTREACH_LOGIN_FOOTER`);
      pass via `auth.WithBranding` when `auth.New` is constructed in
      `buildUIHandler`
- [x] `internal/auth/auth.go` `handleLogin`: resolve from tri-state + localizer —
      `Title` (tab, HTML-stripped; unset → `auth.login.title`, set-empty → keep a
      non-blank tab = i18n title), `Heading` (unset → `auth.login.heading`,
      set-empty → suppress `<h1>` via a `ShowHeading` bool, set → value as
      `template.HTML`); add `Footer template.HTML` rendered only when set
- [x] `internal/auth/auth.go` `renderDenied`: apply the **same** `Title`/`Header`
      branding (tri-state) to the denied page (no footer there); thread it through
      the existing denied struct
- [x] `internal/auth/templates/login.html`: make `<h1>` conditional
      (`{{if .ShowHeading}}`) and render a `{{.Footer}}` block below the provider
      buttons (muted, top border, consistent with existing inline CSS), emitted
      only when non-empty
- [x] `internal/auth/templates/denied.html`: use the branded title/heading
      (conditional `<h1>` like login)
- [x] write tests (`internal/auth/auth_test.go`): login + denied — branding
      overrides i18n title/heading; set-empty header suppresses `<h1>` (tab title
      stays non-blank); footer rendered unescaped when set / absent when empty;
      unset branding reproduces today's pages; tab title HTML-stripped
- [x] run tests — must pass before Task 4

### Task 4 ➕: Env-var templating in branding strings
- [x] add an `expandEnv(string) string` helper using `os.Expand` over `os.Getenv`,
      supporting `${VAR}` and `$VAR`; undefined var → empty string; `$$` → literal
      `$`. Put it in `internal/cmd` (it serves both `ui` and `auth` branding,
      which are both resolved in `cmd`) to avoid an odd `ui`→`auth` layering.
      (Shell-style chosen over `{{.Env.X}}` to avoid colliding with the
      `html/template` `{{…}}` pipeline, since branding HTML is inserted via
      `template.HTML` and not re-parsed.)
- [x] apply expansion in `internal/cmd/ui.go` to the **resolved** branding values
      (after tri-state resolution; expand the pointed-to string when non-nil, and
      description/footer/login-footer), so it covers all branding strings — main
      page and login/denied — once, at startup. A set-empty (`""`) stays empty
- [x] write tests: `${VAR}`/`$VAR` substituted from env; undefined → empty;
      literal `$$`; no-placeholder string unchanged; tri-state nil left untouched;
      expansion happens before HTML rendering (a `${VAR}` holding `<b>x</b>`
      renders as HTML)
- [x] run tests — must pass before Task 5

### Task 5: Helm chart support
- [x] `charts/portreach/values.yaml`: add `ui.branding` (`title`, `description`,
      `footer`) and `ui.loginBranding` (`title`, `header`, `footer`) blocks,
      **null by default** (not `""`) so the tri-state maps through: null = unset
      (omit env → localized default), `""` = set-empty (emit empty env → suppress)
- [x] `templates/deployment-ui.yaml`: emit `PORTREACH_UI_TITLE` /
      `_DESCRIPTION` / `_FOOTER` and `PORTREACH_LOGIN_TITLE` / `_HEADER` /
      `_FOOTER` **only when the value is non-null** (`{{- if not (kindIs "invalid"
      ...) }}` / explicit `hasKey`), so an explicit empty string still emits
      `NAME=""` (set-empty) while null omits the var (unset → default). Note
      `extraEnv` can inject the vars referenced by `${...}` placeholders (e.g.
      `CLUSTER_NAME`, downward-API `metadata.*`)
- [x] extend `internal/charttest` render assertions: unset (null) → no env var;
      set-value → `NAME=value`; set-empty (`""`) → `NAME=""`; for both ui and
      login branding; run `helm lint`
- [x] run tests — must pass before Task 6

### Task 6: Documentation
- [x] `docs/configuration.md`: document the main-page, login **and** denied
      flags/env, the HTML behaviour, the **tri-state rule** (unset → localized
      default; set-empty → suppressed; set → value), the `${VAR}`/`$VAR`
      env-templating syntax (undefined → empty; literal `$` must be written `$$`),
      and the security note (operator-trusted HTML → rendered unescaped; do not
      expose config to untrusted users)
- [x] `docs/deployment.md`: per-cluster branding example (e.g. title
      `<span style="color:#b62324">PROD — ${CLUSTER_NAME}</span>` driven by an
      injected env var) for environment identification, plus a login-page example
- [x] `README.md`: brief mention of branding (incl. login + env templating)
- [x] run `go test ./...` — no regression

### Task 7: Verify acceptance criteria
- [x] verify main page tri-state: unset → localized heading (en + ru); set-value →
      value; set-empty → no `<h1>` (tab title still non-blank); description under
      title; footer at bottom; all support HTML; tab reflects env
- [x] verify login + denied pages: title/header tri-state, login footer renders,
      unset reproduces today's pages
- [x] verify env templating: `${VAR}`/`$VAR` resolved across all fields; undefined
      → empty; `$$` → literal `$`
- [x] verify edge cases: unset all (today's behaviour), HTML in each field, very
      long values
- [x] run full unit suite `go test ./... -v`; `go vet ./...`; `helm lint`
- [x] verify `internal/ui`, `internal/auth`, `internal/cmd` coverage stay ≥ 80%

### Task 8: [Final] Knowledge
- [x] re-read docs for accuracy; note the branding config (main + login + denied),
      the tri-state (unset/set-empty/set) rule, the env-templating syntax, and the
      HTML-trust caveat

*Note: ralphex automatically moves completed plans to `docs/plans/completed/`.*

## Technical Details
- **API style**: `ui.New(disc, timeout, ...Option)` + `ui.WithBranding(Branding)`,
  mirroring `auth.WithLogger`/`auth.WithBranding`. Keeps existing `ui.New(disc,
  timeout)` callers and tests compiling.
- **Tri-state for i18n-default fields** (main title, login title, login header,
  denied title/header): represented as `*string` — `nil` = unset (→ localized
  i18n default), non-nil = set (`""` suppresses the element; tab `<title>` never
  goes blank — falls back to i18n title even when the heading is suppressed).
  Resolved in `cmd` from `fs.Visit` (flag explicitly passed) and `os.LookupEnv`
  (env present); flag wins over env. Plain `string` (empty = omitted) for
  description, footer, login footer.
- **Main-page config fields**: `Title *string`, `Description, Footer string` (HTML
  allowed). Flags `--ui-title|--ui-description|--ui-footer`, env
  `PORTREACH_UI_TITLE|_DESCRIPTION|_FOOTER`.
- **Login/denied config fields**: `auth.LoginBranding{Title, Header *string;
  Footer string}` (HTML allowed). Flags `--login-title|--login-header|
  --login-footer`, env `PORTREACH_LOGIN_TITLE|_HEADER|_FOOTER`. Passed into
  `auth.New` via `auth.WithBranding`. Title/Header brand both the login and denied
  pages; Footer is login-only.
- **Rendering**: `template.HTML` for every block (unescaped, operator-trusted).
  `<h1>` is gated by a `ShowTitle`/`ShowHeading` bool; description/footer/
  login-footer emitted only when non-empty. Document `<title>` uses an
  HTML-stripped form of the configured title, falling back to the **localized**
  i18n title (`app.title` / `auth.login.title`).
- **Env templating**: each resolved branding string is expanded once at startup
  via `os.Expand`/`os.Getenv` (`${VAR}` and `$VAR`; undefined → empty; `$$` → `$`).
  Helper lives in `internal/cmd` (serves both `ui` and `auth`). Expansion runs
  **before** HTML rendering, so an env value may itself contain HTML; a `nil`
  tri-state value is left untouched, a set-empty `""` stays empty. Shell-style
  chosen over `{{.Env.X}}` to avoid colliding with the `html/template` `{{…}}`
  pipeline.
- **Defaults**: all fields **unset** → today's behaviour — localized `app.heading`/
  `app.title` (main), localized `auth.login.*` (login/denied), no description/
  footer.
- **Security**: branding HTML is rendered without escaping — safe only because it
  is set by the operator via flags/env/helm, never by end users. Env templating
  reads only process env (operator-controlled), not request data. Documented.
- **Not in scope**: per-request/dynamic branding, logos/image upload, theming
  beyond the existing CSS; template logic beyond simple env-var substitution
  (no conditionals/loops/funcs) — keep to title/description/header/footer text+HTML.

## Post-Completion
*Items requiring manual intervention or external systems — informational only.*

**Manual verification:**
- Deploy to two clusters with distinct titles/colors and confirm at a glance (page
  heading + browser tab) which environment is open.
- Confirm HTML (e.g. a colored `<span>`) renders as intended and an empty title
  produces no heading gap.
- With SSO enabled, confirm the login **and denied** pages show the configured
  title/header (footer on login) — environment identifiable before/around sign-in.
- Confirm the tri-state by eye: unset → localized heading; `--ui-title=""` → no
  heading but a sane browser-tab title; a value → that value.
- Set a branding string using `${CLUSTER_NAME}` (or downward-API env) and confirm
  the per-cluster value is substituted at render time.
