# Abuse controls: rate limiter + bounded fan-out + default-deny cloud metadata

## Overview
Limit how much and where the tool can be pointed, so hundreds of developers (with
turnover) can't turn it into an internal port-scanner, a DoS amplifier, or an SSRF to
cloud credentials. Independent controls — the rate limiter and fan-out cap are
backward-compatible (off/unlimited by default), while the metadata guard is an
**intentional, default-on security change** (see its bullet):

- **Rate limiter (optional)** on the UI API: per-user and per-target token buckets with
  **atomic multi-bucket reservation + rollback** (a request denied by one bucket must
  not consume the others), plus a global cap. Over limit → `429` + `Retry-After`
  derived from the reservation delay. Optional mirror on the agent.
- **Bounded fan-out** (opt-in, `0 = unlimited` default): an optional `maxAgentsPerCheck`
  cap on how many discovered agents a single check fans out to, executed through a
  bounded worker pool. Default `0` preserves the "from every node" promise unchanged;
  when set, selection is **deterministic** (agents sorted by `Addr`) and dropped agents
  are reported.
- **Default-deny cloud metadata**: refuse connections to the **whole IPv4 link-local
  range `169.254.0.0/16`** (deliberately broader than the single metadata IP — it covers
  AWS/GCP/Azure IMDS `169.254.169.254`, ECS task metadata `169.254.170.2`, and any other
  link-local target) plus IPv6 `fd00:ec2::254` — enforced at **connect time** so it does
  not change the dial/report path of normal targets (finding #6). ⚠️ **Not fully
  backward-compatible**: a deployment that legitimately checked a link-local address is
  now denied by default — this is an intentional security default, opt back in via
  `agent.targetPolicy.allowMetadata: true`. Operator `--deny` is independent and wins.

## Review findings addressed (2026-06-28)
5. **Fan-out is actually bounded.** The API takes one target but `CheckAll`
   (`aggregator.go:49`) spawns a goroutine per discovered agent, so `maxTargets` is
   nearly meaningless and `maxConcurrentFanout` alone still hits every agent. Added a
   hard `maxAgentsPerCheck` (cap on agents queried after discovery) + a bounded worker
   pool; dropped agents are surfaced (no silent truncation). (Task 2/3)
6. **Metadata deny does not force policy-mode.** Folding it into `Policy` would make
   every open deployment pre-resolve, fail-closed on DNS errors, and lose CNAME
   reporting (`agent.go:223-246`). Instead it is a **connect-time guard**
   (`net.Dialer.Control`) on the probe dial path: normal targets dial and report
   exactly as today; only a connect to a metadata IP is refused. Compatibility tests
   required for plain hostnames, CNAME, and DNS-error behaviour. (Task 4)
7. **Rate limiter is reservation-based.** `Allow` reserves across user/target/global
   atomically and **cancels all reservations** if any bucket denies, so a rejected
   request burns no unrelated tokens; `Retry-After` comes from the reservation delay,
   not a second guess. Regression test: "denied request consumes no unrelated bucket".
   (Task 1)
8. **Per-IP fallback is proxy-aware.** Behind an Ingress, `RemoteAddr` is the proxy and
   raw `X-Forwarded-For` is spoofable. Added trusted-proxy CIDR + header config; the
   forwarded client IP is trusted only when `RemoteAddr` is a configured trusted proxy,
   else `RemoteAddr` is used. Documented: per-IP keying is only meaningful with auth
   off **and** correct trusted-proxy config; otherwise enable auth for per-user keys.
   (Task 1/2)

### Open question — decision baked in
- **Metadata opt-out is separate from operator policy.** `agent.targetPolicy.allowMetadata:
  true` removes only the *built-in* metadata guard. An operator `--deny` (and the
  resolve-time `Policy`) is independent and **always wins** — opting out of the
  built-in guard never overrides an explicit deny.

## Review findings addressed (round 2, 2026-06-28)
- **#R4 (`maxAgentsPerCheck` doesn't silently break "from every node").** Default is
  **`0 = unlimited`** (opt-in), so existing clusters fan out to every node exactly as
  today. Only when an operator sets a positive cap do results become partial — and then
  the drop count is reported and the docs/README wording is updated. (Overview, Task 3)
- **#R5 (explicit probe↔agent contract for denial).** `probe.Run` returns Result-only
  and `handleCheck` writes HTTP 200 + counts fail (`probe.go:109`, `agent.go:194`), so a
  `net.Dialer.Control` rejection would otherwise look like a generic connection failure.
  Task 4 adds a typed status on the result (**`Result.Denied`** + reason) that the guard
  sets; `handleCheck` inspects it and routes to the **same denial path as a policy deny**
  (increments `denied`, same response shape), so metadata and policy denials are
  indistinguishable to clients. (Task 4)
- **#R6 (rate-limit config is validated; impossible reservations fall back).** Edge
  configs (`burst 0`, negative rate, `n > burst`) make `ReserveN` unusable/infinite.
  Task 1 adds validation (rate > 0, burst ≥ 1, requested n ≤ burst, sane global) and a
  **bounded fallback**: a non-OK / `+Inf`-delay reservation is treated as an immediate
  reject with a capped `Retry-After`, never a hang.
- **Open question — deterministic selection.** When discovery returns more agents than
  the cap, agents are **sorted by `Addr`** before truncation, so partial results are
  stable and reproducible. (`Addr` is the only stable key available pre-request:
  `discovery.Agent` has just `Addr`; `Node` only appears in the agent's response —
  `discovery.go:15`, `aggregator.go:30`.) (Task 3)

## Dependency / context (from discovery)
- `internal/ui/server.go` routes `/`, `/api/check`, `/healthz`;
  `internal/ui/aggregator.go` `CheckAll` (goroutine-per-agent — to be bounded).
- `internal/auth` `IdentityFromContext` (per-user keying; degrades to per-IP when auth
  off — see finding #8).
- `internal/agent/agent.go`: `resolveTarget` (`agent.go:223`) — policy pre-resolves
  only when non-empty; `Policy`/`ParsePolicy`; `internal/probe` dial path (where the
  connect-time metadata guard is injected).
- Helm: `values.yaml`/`values.schema.json`, `deployment-ui.yaml`, `daemonset-agent.yaml`,
  `internal/charttest`.
- New dep: `golang.org/x/time/rate` (token bucket with reservations). Justified.

## Development Approach
- **Testing approach**: Regular (implement, then unit tests in the same task).
- Each task ends with tests; must pass before the next.
- **Backward compatible**: limiter **off** unless configured; metadata guard is a
  *default-on* connect check that does **not** alter normal dial/report behaviour;
  bounded fan-out defaults to `0` = unlimited (every-node, today's behaviour). Don't
  break open `cluster.local` deployments.
- `go build/vet/test ./...` + `helm lint` after each change; `gofmt` clean.

## Testing Strategy
- Hermetic: inject a fake clock / limiter so tests are deterministic (no real sleeps).
- Cover: allow-then-deny; per-user and per-target isolation; **denied request consumes
  no unrelated bucket** (reservation rollback); `429` + correct `Retry-After`; disabled
  = unlimited; trusted-proxy header honoured only from trusted source, ignored
  otherwise; `maxAgentsPerCheck` caps and reports drops; metadata guard refuses
  `169.254.169.254` **and a second in-range IP (`169.254.170.2`)** at connect (proving
  the whole `/16` is denied, not just the metadata IP); a **name resolving only to a
  denied IP → `Result.Denied=true`** while a **mixed RRset never connects to the denied IP
  but may return OK via an allowed sibling** (the narrowed connect-guard semantics, not
  strict denied-wins reporting); a **plain hostname still dials and reports CNAME and DNS
  errors exactly as before**; `allowMetadata` re-enables; operator `--deny` still wins.

## Progress Tracking
- Mark `[x]` immediately. New tasks → `➕`; blockers → `⚠️`.

## What Goes Where
- **Implementation Steps** (`[ ]`): code, tests, helm, docs.
- **Post-Completion** (no checkboxes): tune limits per environment; confirm metadata
  unreachable on a real cloud node.

## Implementation Steps

### Task 1: Rate-limiter core (reservation-based, multi-bucket)
- [ ] add `golang.org/x/time/rate`; `go mod tidy` (commit `go.sum`)
- [ ] new `internal/ratelimit`: registries for user, target (`host:port`), and global
      buckets (rate/burst per scope); injectable clock
- [ ] **config validation (#R6), enabled-gated (Medium)**: a disabled/unset limiter
      (zero defaults) is **valid** (no-op). The positive checks (rate > 0, burst ≥ 1, sane
      global, reject `n > burst`) apply **only when the limiter is enabled/configured** —
      so the default-off config passes `Validate()` and only a half-configured limiter is
      rejected
- [ ] `Reserve(identityKey, targetKey) (Reservation, ok, retryAfter)`: take a
      reservation from **each** applicable bucket; if any is not immediately OK,
      **Cancel() all** taken reservations and return `ok=false` with the max delay as
      `retryAfter` (finding #7) — never partially consume
- [ ] **bounded fallback (#R6)**: a reservation that is not OK or whose `Delay()` is
      `+Inf`/exceeds a max wait is treated as an immediate reject with a **capped**
      `Retry-After` (never a hang or an unbounded value)
- [ ] identity key = authenticated user when present, else proxy-aware client IP
      (finding #8): trust a forwarded header only when `RemoteAddr` ∈ configured
      trusted-proxy CIDRs, else use `RemoteAddr`
- [ ] idle buckets evicted to bound memory
- [ ] write tests (fake clock): allow→deny at limit; per-user and per-target isolation;
      **denied request leaves other buckets untouched**; refill over time;
      trusted-proxy header honoured only from trusted source; **disabled/default config
      passes Validate (no-op)**; **invalid configs rejected only when enabled** (burst 0,
      negative rate, n > burst); **impossible reservation → capped Retry-After reject, no
      hang**
- [ ] run tests — must pass before Task 2

### Task 2: Wire limiter + proxy-aware client IP into the UI API
- [ ] `internal/cmd/ui.go`: build limiter + trusted-proxy config from flags/env
      (`--rate-*`, `--trusted-proxies`); unset limiter = no-op (unlimited)
- [ ] wrap `/` (on submit) and `/api/check`: over limit → `429` + `Retry-After`
      (JSON for `/api/check`, page message for `/`)
- [ ] emit an audit event on throttle (user/IP, target, reason)
- [ ] write tests (`httptest`): 429 + `Retry-After` over limit; under limit passes;
      disabled = unlimited; client-IP keying uses the right source behind/without proxy
- [ ] run tests — must pass before Task 3

### Task 3: Bound the per-check fan-out
- [ ] add `maxAgentsPerCheck` (config, **default `0` = unlimited**, #R4) and a worker
      pool to `CheckAll` (`internal/ui/aggregator.go`)
- [ ] **`maxConcurrentFanout` default + validation (Medium)**: define `0`/unset =
      **unlimited concurrency** (today's goroutine-per-agent, no pool — preserves current
      behaviour); `> 0` = bounded pool of that size; **reject negative** in
      `Config.Validate()`. Never spawn a zero-worker pool (would hang)
- [ ] when `maxAgentsPerCheck > 0` and discovery returns more agents than the cap,
      **sort agents deterministically by `Addr`** (`discovery.Agent` has no `Node`
      pre-request), query the first N — no silent truncation
- [ ] **explicit response contract (Medium)**: today `Summary.Total = len(results)`
      (`aggregator.go:119`) — after a cap that would silently become the *queried* count.
      Add explicit `discovered` / `queried` / `dropped` counts to the response (and
      define `Summary.Total` = queried), so partial results are unambiguous; mirror in the
      audit event
- [ ] update README/docs wording so the "from every node" promise notes the optional cap
- [ ] write tests: default `0` queries all (compat); `maxConcurrentFanout` 0/unset =
      unlimited, `> 0` bounds concurrency, **negative rejected by Validate**; cap enforced
      with **stable selection**; **`discovered`/`queried`/`dropped` correct** under and
      over the cap
- [ ] run tests — must pass before Task 4

### Task 4: Default-deny cloud metadata (connect-time guard, not policy-mode)
- [ ] **define the probe↔agent contract first (#R5)**: `probe.Run` returns only a
      `Result` and `handleCheck` currently writes HTTP 200 + counts fail
      (`probe.go:109`, `agent.go:194`). Add an explicit typed status to `Result` — e.g.
      `Result.Denied bool` (+ `Result.DeniedReason string`) — so a connect-guard refusal
      is distinguishable from a generic dial failure **without** changing `Run`'s
      "Result-only, never errors except invalid input" contract
- [ ] **JSON wire-compat (Low #5)**: `probe.Result` is serialized straight to the API
      (`probe.go:56`); the new fields **must** use `json:"denied,omitempty"` /
      `json:"denied_reason,omitempty"` so a normal (non-denied) response is byte-identical
      to today. Add a test asserting normal-response JSON gains no new keys
- [ ] `internal/probe`: connect guard on the dial path via `net.Dialer.Control` rejects
      connects whose resolved IP ∈ a deny set. A `Control` rejection is a **candidate-level**
      signal (recorded via the shared flag), **not** an immediate `Result.Denied`:
      `Run` promotes it to `Result.Denied=true` (+ reason) **only when the overall dial
      produced no successful TCP connection** (`out.OK == false`) **and** the failure was
      the guard. If an allowed sibling still connected (`TCP.OK == true`), a candidate-level
      denial **must not** surface as `Result.Denied` — it stays a normal OK result (per the
      narrowed semantics below)
- [ ] **concurrency-safe guard signal (Medium)**: `Control` can fire from multiple
      goroutines at once — `probe.dial` runs a worker pool of `DialContext` calls
      (`probe.go:223`) and `net.Dialer` itself may stagger Happy-Eyeballs attempts — so the
      guard-hit signal **must not** be a plain `bool`/`string` (data race; `go test -race`
      would flag it). Use an `atomic.Bool` for guard-hit and carry the reason without shared
      mutable memory — a fixed/const denial reason (the deny set is static), or a
      typed-error path returned from `Control` that `Run` inspects after the dial. `Run`
      reads the atomic **after** the dial completes, then applies the `out.OK == false`
      gate above. Run the package under `-race`
- [ ] **mixed-address semantics — what the connect guard actually guarantees (High)**:
      the guard's hard property is that **a connection to a denied IP is never
      established** — `Control` runs before every connection `net.Dialer` actually
      attempts, so a denied address is refused at connect. It does **not** guarantee
      `Result.Denied=true` for a *mixed* RRset (one allowed + one denied IP), because the
      open-policy path (the only path where this guard matters) dials a single
      **hostname**: `resolveTarget` returns `nil` when `policy.empty()` (`agent.go:224`),
      so `probe.Run` sets `dialHosts=[host]` (`probe.go:118`) and `probe.dial` runs **one**
      `DialContext` of the name — address selection (and Happy Eyeballs first-success
      stop) happens **inside `net.Dialer`**, so `Control` may never fire for the denied IP
      if an allowed sibling connects first. (`probe.dial`'s concurrent race over candidate
      IPs only applies in **policy** mode, where `resolveTarget` already fail-closes on any
      denied IP before dialing — `agent.go:240`.) **Decision: narrow the semantics, don't
      pre-resolve** (keeps finding #6's no-pre-resolve design — CNAME/DNS-error reporting,
      no fail-closed-on-DNS): a name resolving **only** to denied IP(s) → `Result.Denied=true`
      (the `Control` rejection sets the atomic guard-hit flag `Run` reads after the failed
      dial — see the concurrency-safe signal bullet);
      a name that also has an allowed IP that connects first **may return OK** — the denied
      IP is simply never attempted, never connected to. (Alternative, if strict
      denied-wins *reporting* is ever required: pre-resolve the set and check it like
      policy mode — rejected here because it reintroduces the duplicate-lookup, rebinding
      window, and lost CNAME/DNS-error reporting that finding #6 deliberately avoids.)
- [ ] `internal/agent`: by default install a guard for the **whole IPv4 link-local
      range `169.254.0.0/16`** (covers IMDS `169.254.169.254`, ECS `169.254.170.2`, etc.)
      **+ IPv6 `fd00:ec2::254`**; `--allow-metadata` (chart
      `agent.targetPolicy.allowMetadata`) removes only this built-in guard; operator
      `--deny` / `Policy` is unchanged and still applies/wins
- [ ] **`handleCheck` inspects `res.Denied`** and routes it to the existing
      policy-denial path: increment the `denied` metric and return the same denial
      response shape/status as a `resolveTarget` policy deny (`agent.go:176`), so
      metadata and policy denials are identical to clients (document the HTTP status)
- [ ] **do not** enable `resolveTarget` policy-mode for open deployments — the guard is
      independent of `Policy.empty()`
- [ ] write tests: metadata IP refused at connect → **typed denial, `denied` metric
      incremented, denial-shaped response** (not a generic TCP error); **name resolving
      only to a denied IP → `Result.Denied=true`** (no connection established); **a denied
      IP is never successfully connected to even when a mixed RRset has an allowed sibling**
      (assert no connection to the denied address is accepted — e.g. a listener on the
      denied IP records zero accepts; do **not** assert that `Control` fired for it nor
      assert `Result.Denied`, since `net.Dialer` may connect the allowed sibling first and
      never attempt the denied IP, per the narrowed semantics above); **plain hostname
      still dials, reports CNAME and DNS errors exactly as today** (compat); `allowMetadata`
      re-enables; operator `--deny` still wins
- [ ] run tests — must pass before Task 5

### Task 5: Optional agent-side limiter + Helm wiring
- [ ] `internal/cmd/agent.go`: `--rate-*` per-process/per-target cap on `/check`
      (defence in depth for direct calls); unset = unlimited
- [ ] `values.yaml`+`values.schema.json`: `ui.rateLimit` / `agent.rateLimit`
      (enabled, rate, burst, global, `maxAgentsPerCheck`, `maxConcurrentFanout`),
      `ui.trustedProxies`, and `agent.targetPolicy.allowMetadata` (default false → denied)
- [ ] render the `--rate-*` / `--trusted-proxies` / metadata flags; ensure the metadata
      guard is on unless `allowMetadata: true`
- [ ] extend `internal/charttest` (limiter+fanout+proxy args; metadata guard default-on,
      off when allowed); `helm lint`
- [ ] write tests for the agent limiter (throttles over limit, open when unset)
- [ ] run tests — must pass before Task 6

### Task 6: Documentation
- [ ] `docs/configuration.md`: rate-limit knobs (per-user/per-target/global,
      reservation/429/`Retry-After`), `maxAgentsPerCheck` + fan-out bounding,
      trusted-proxy config (and that per-IP keying needs it / prefer auth), and the
      metadata default-deny + override semantics (operator `--deny` always wins)
- [ ] `docs/deployment.md`: recommend enabling the limiter + trusted-proxies behind an
      Ingress; security note on metadata
- [ ] `README.md`: brief mention under security
- [ ] run `go test ./...` — no regression

### Task 7: Verify acceptance criteria
- [ ] limiter enforces per-user/per-target/global with reservation rollback and correct
      `429`+`Retry-After`; disabled = unlimited; fan-out capped with drops reported;
      proxy-aware IP keying correct; metadata denied by default (no behaviour change for
      normal targets) and override works while operator `--deny` wins
- [ ] `go test ./... -v`, `go vet ./...`, `helm lint` clean; new pkg coverage ≥ 80%

### Task 8: [Final] Knowledge
- [ ] note the limiter, bounded fan-out, trusted-proxy, and metadata guard in
      README/AGENTS.md

*Note: ralphex auto-moves completed plans to `docs/plans/completed/`.*

## Technical Details
- **Reservation rollback (#7)**: use `rate.Limiter.ReserveN`; gather reservations from
  all applicable buckets, and if any `!OK()` or its `Delay()` exceeds the allowed wait,
  `Cancel()` every reservation taken and reject. `Retry-After` = max `Delay()` across
  the binding reservations.
- **Keying / proxy (#8)**: identity = authed user > proxy-trusted forwarded IP >
  `RemoteAddr`. Forwarded header trusted only when `RemoteAddr` ∈ `trustedProxies`.
  Per-IP keying is documented as a fallback that is only meaningful for direct
  deployments or with correct trusted-proxy config; otherwise enable auth.
- **Fan-out (#5/#R4)**: `maxAgentsPerCheck` (default `0` = unlimited = today's
  every-node behaviour) bounds the blast radius when set; `maxConcurrentFanout` is the
  pool size (`0`/unset = unlimited = today's goroutine-per-agent; negative rejected;
  never a zero-worker pool). Over the cap, agents are sorted by `Addr` for
  **deterministic** selection (no `Node` is known pre-request). The response carries
  explicit `discovered`/`queried`/`dropped` counts (`Summary.Total` = queried) so partial
  results are unambiguous — drops are never silent.
- **Metadata guard (#6/#R5)**: enforced at connect via `net.Dialer.Control` so it sees
  the real connect IP (defeats rebinding) without pre-resolving in the agent or changing
  CNAME/DNS-error reporting for normal targets. A `Control` rejection is candidate-level;
  `Run` sets `Result.Denied`(+reason) **only when the whole dial yielded no successful TCP
  connection** (`out.OK == false`) — a denial that loses the race to an allowed sibling
  stays a normal OK result and is **not** reported as denied. When `Result.Denied` is set,
  `handleCheck` routes it to the `denied` metric + denial response (parity with a
  policy deny). Independent of `Policy`; operator `--deny` still applies and wins;
  `allowMetadata` removes only the built-in set.
- **Metadata-guard semantics — key security tradeoff (High)**: the guaranteed property is
  that **a denied IP is never connected to** (`Control` runs before every connection
  `net.Dialer` attempts). It is **not** strict denied-wins *reporting*: the open-policy
  path (the only one where this guard applies — policy mode already fail-closes at resolve,
  `agent.go:240`) dials a single **hostname**, so `net.Dialer` does its own address
  selection and stops at the first success. A name resolving **only** to denied IP(s)
  reports `Result.Denied=true` (`Control` rejection → atomic guard-hit flag read after the
  failed dial); a **mixed** RRset whose allowed sibling connects first may report OK — the
  denied IP is just never attempted. No pre-resolution is added (would lose the CNAME/
  DNS-error reporting and no-fail-closed-on-DNS behaviour finding #6 preserves).
- **Dep**: `golang.org/x/time/rate` only.

## Post-Completion
*Manual / external — no checkboxes.*
- Tune per-environment limits and `maxAgentsPerCheck`; watch the audit log for throttle
  events / anomalous broad scans.
- On a real cloud node, confirm `169.254.169.254` is unreachable through the agent.
- Set `trustedProxies` to your Ingress/CNI egress ranges before relying on per-IP
  limits; prefer enabling auth (pairs with `api-and-agent-auth`) for per-user limits.
