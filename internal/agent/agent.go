// Package agent implements the probe HTTP server that runs on each point.
package agent

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lavr/portreach/internal/checkapi"
	"github.com/lavr/portreach/internal/probe"
	"github.com/lavr/portreach/internal/ratelimit"
)

// Policy restricts which target IPs an agent may connect to, mitigating use of
// the agent as an SSRF proxy. Deny always wins; an empty allow list means
// allow-all (subject to deny).
type Policy struct {
	allow []*net.IPNet
	deny  []*net.IPNet
}

// ParsePolicy builds a Policy from comma-separated CIDR lists.
func ParsePolicy(allow, deny string) (*Policy, error) {
	p := &Policy{}
	var err error
	if p.allow, err = parseCIDRs(allow); err != nil {
		return nil, fmt.Errorf("allow: %w", err)
	}
	if p.deny, err = parseCIDRs(deny); err != nil {
		return nil, fmt.Errorf("deny: %w", err)
	}
	return p, nil
}

func parseCIDRs(list string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func (p *Policy) empty() bool {
	return len(p.allow) == 0 && len(p.deny) == 0
}

// metadataNets are the link-local / cloud-metadata networks the agent refuses to
// connect to by default. The whole IPv4 link-local range 169.254.0.0/16 is denied
// (deliberately broader than the single metadata IP — it covers AWS/GCP/Azure IMDS
// 169.254.169.254, ECS task metadata 169.254.170.2, and any other link-local
// target), plus the IPv6 IMDS address fd00:ec2::254. The guard runs at connect
// time, independent of the operator Policy, and is removed only by
// WithAllowMetadata.
func metadataNets() []*net.IPNet {
	cidrs := []string{"169.254.0.0/16", "fd00:ec2::254/128"}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		// Static, known-good CIDRs: a parse failure is a programming error.
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("agent: invalid metadata CIDR " + c + ": " + err.Error())
		}
		nets = append(nets, n)
	}
	return nets
}

// Allowed reports whether connecting to ip is permitted.
func (p *Policy) Allowed(ip net.IP) bool {
	for _, n := range p.deny {
		if n.Contains(ip) {
			return false
		}
	}
	if len(p.allow) == 0 {
		return true
	}
	for _, n := range p.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type metrics struct {
	ok        atomic.Int64
	fail      atomic.Int64
	denied    atomic.Int64
	badReq    atomic.Int64
	throttled atomic.Int64
}

// ipResolver resolves a hostname to its IP addresses. *net.Resolver satisfies
// it; tests inject a fake.
type ipResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Server serves the agent HTTP endpoints.
type Server struct {
	nodeName string
	policy   *Policy
	resolver ipResolver
	metrics  metrics

	// guard is the connect-time deny guard applied to every probe dial. By default
	// it denies the cloud-metadata / link-local set (see metadataNets); nil when
	// WithAllowMetadata removed it. It is independent of policy — operator --deny
	// still applies and wins.
	guard *probe.DenyGuard
	// allowMetadata, when set via WithAllowMetadata, removes the built-in metadata
	// guard. The operator Policy (--deny) is unaffected.
	allowMetadata bool

	// limiter, when non-nil, gates /check as defence-in-depth for direct calls
	// (see WithLimiter). Nil = unlimited, the backward-compatible default.
	limiter *ratelimit.Limiter

	// postgresLimiter is a SEPARATE limiter layered on top of limiter for the
	// postgres endpoint only: an auth probe drives a real login attempt (and,
	// on success, a live query) against the target, so it warrants a tighter,
	// dedicated budget rather than sharing the general check limiter's buckets.
	// New auto-builds one with the built-in defaults whenever the postgres
	// check is enabled, unless disablePostgresRateLimit opts out or a caller
	// supplied one directly via WithPostgresLimiter. Both limiters are
	// consulted independently (see allow/allowPostgres) — tripping one never
	// spends tokens from the other.
	postgresLimiter *ratelimit.Limiter
	// disablePostgresRateLimit, set via WithDisablePostgresRateLimit, is the
	// only way to opt out of the auto-built postgres limiter above.
	disablePostgresRateLimit bool

	// postgres is the Postgres check runner. Its zero value uses the real
	// pgconn-backed prober (see probe.Postgres.prober); tests set Prober to a
	// fake so the postgres handler's wiring can be exercised without a real
	// PostgreSQL server, mirroring how resolver is overridden directly in
	// tests below.
	postgres probe.Postgres

	// logger receives the postgres check audit trail (see auditPostgres). A
	// nil logger falls back to slog.Default(), matching internal/auth's audit
	// pattern.
	logger *slog.Logger

	// token, when non-empty, is the shared bearer secret required on /check and
	// (unless metricsPublic) /metrics. Empty disables the check entirely, keeping
	// the agent open — the backward-compatible default.
	token string
	// metricsPublic re-opens /metrics for unauthenticated scraping (Prometheus)
	// even when a token is configured. /check stays gated regardless.
	metricsPublic bool

	// enabledChecks is the --enabled-checks allowlist (default tcp-only; see
	// checkapi.ParseEnabledChecks). Handler consults it to decide which check
	// routes to register at all: a disabled check's route is never added to
	// the mux, so a request for it 404s exactly like any other unknown path.
	// It never governs /healthz or /metrics, which stay available regardless.
	// An empty set is a startup configuration error (see
	// checkapi.EnabledChecks.RequireNonEmpty), enforced by the cmd layer
	// before New is ever called.
	enabledChecks checkapi.EnabledChecks
}

// Option configures a Server built by New.
type Option func(*Server)

// WithToken sets the shared bearer token required on /check (and /metrics unless
// WithMetricsPublic is set). An empty token leaves the agent open.
func WithToken(token string) Option {
	return func(s *Server) { s.token = token }
}

// WithMetricsPublic leaves /metrics reachable without the bearer token, for
// Prometheus scrapers that cannot present it. /check stays gated.
func WithMetricsPublic(public bool) Option {
	return func(s *Server) { s.metricsPublic = public }
}

// WithAllowMetadata removes the built-in cloud-metadata / link-local connect
// guard (default-on). It opts back into the pre-guard behaviour for deployments
// that legitimately probe a link-local address. The operator Policy (--deny) is
// independent and still applies and wins.
func WithAllowMetadata(allow bool) Option {
	return func(s *Server) { s.allowMetadata = allow }
}

// WithEnabledChecks sets the --enabled-checks allowlist this agent serves.
// The zero value (checkapi.EnabledChecks{}) enables nothing; New does not
// substitute a default — cmd is responsible for resolving the "tcp" default
// via checkapi.ParseEnabledChecks before calling New.
func WithEnabledChecks(checks checkapi.EnabledChecks) Option {
	return func(s *Server) { s.enabledChecks = checks }
}

// WithPostgresLimiter overrides the postgres-specific limiter New would
// otherwise auto-build (see the postgresLimiter field doc). Tests use this to
// inject a limiter with an injected clock (ratelimit.WithClock) so the 429
// path is exercised hermetically; production code should prefer
// WithDisablePostgresRateLimit to opt out rather than supplying a permissive
// limiter here.
func WithPostgresLimiter(l *ratelimit.Limiter) Option {
	return func(s *Server) { s.postgresLimiter = l }
}

// WithDisablePostgresRateLimit opts out of the auto-built postgres limiter
// entirely (the only supported way to disable it — see the postgresLimiter
// field doc). The general /check limiter (WithLimiter), if any, still applies.
func WithDisablePostgresRateLimit(disable bool) Option {
	return func(s *Server) { s.disablePostgresRateLimit = disable }
}

// WithLogger sets the slog.Logger used for the postgres check audit trail
// (see auditPostgres). A nil logger is ignored, leaving the default
// (slog.Default()).
func WithLogger(l *slog.Logger) Option {
	return func(s *Server) {
		if l != nil {
			s.logger = l
		}
	}
}

// auditLogger returns the configured audit logger, falling back to the
// process default so a Server built without WithLogger (e.g. in tests) still
// logs.
func (s *Server) auditLogger() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}

// New builds an agent Server. An empty nodeName is resolved via NodeName; a nil
// policy means allow-all.
func New(nodeName string, policy *Policy, opts ...Option) *Server {
	if nodeName == "" {
		nodeName = NodeName()
	}
	if policy == nil {
		policy = &Policy{}
	}
	s := &Server{nodeName: nodeName, policy: policy, resolver: net.DefaultResolver}
	for _, o := range opts {
		o(s)
	}
	// Install the default-on metadata guard unless the operator opted out. Built
	// after options so WithAllowMetadata can suppress it.
	if !s.allowMetadata {
		s.guard = probe.NewDenyGuard(metadataNets())
	}
	// Auto-build the postgres-specific limiter whenever the postgres check is
	// served, unless the operator opted out or already supplied one via
	// WithPostgresLimiter (checked after options so both overrides apply).
	// The bounds are fixed, known-good constants (see postgresLimiterConfig),
	// so a Validate failure here would only mean one of them regressed — a
	// programming error, not a runtime condition to recover from.
	if s.enabledChecks.Has(checkapi.CheckPostgres) && !s.disablePostgresRateLimit && s.postgresLimiter == nil {
		lim, err := ratelimit.New(postgresLimiterConfig)
		if err != nil {
			panic("agent: built-in postgres limiter config is invalid: " + err.Error())
		}
		s.postgresLimiter = lim
	}
	return s
}

// NodeName returns the agent's point name from NODE_NAME, falling back to the
// hostname.
func NodeName() string {
	if n := strings.TrimSpace(os.Getenv("NODE_NAME")); n != "" {
		return n
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

// Handler returns the agent's HTTP routes. Each check endpoint
// (/api/check/tcp, /api/check/postgres) is registered only when the
// corresponding check is in enabledChecks — a disabled check's route is never
// added to the mux, so a request for it 404s exactly like any unknown path,
// rather than the handler having to reject it itself. The check endpoints
// (and /metrics, unless metricsPublic) require the bearer token when one is
// configured; /healthz is always open so cluster probes do not need the
// secret.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	if s.enabledChecks.Has(checkapi.CheckTCP) {
		mux.HandleFunc("/api/check/tcp", s.requireToken(requireMethod(http.MethodPost, s.handleCheckTCP)))
	}
	if s.enabledChecks.Has(checkapi.CheckPostgres) {
		mux.HandleFunc("/api/check/postgres", s.requireToken(requireMethod(http.MethodPost, s.handleCheckPostgres)))
	}
	mux.HandleFunc("/healthz", s.handleHealthz)
	if s.metricsPublic {
		mux.HandleFunc("/metrics", s.handleMetrics)
	} else {
		mux.HandleFunc("/metrics", s.requireToken(s.handleMetrics))
	}
	return mux
}

// requireMethod rejects any request whose method isn't method with a 405
// before next ever sees it. The check endpoints take a JSON body and have no
// meaningful query-string form, so a non-POST request is a protocol error
// (wrong verb), not a validation failure on the payload — hence 405, not 400.
func requireMethod(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		next(w, r)
	}
}

// requireToken wraps next so it only runs when the request carries the right
// bearer token. With no token configured it is a pass-through (open agent, the
// backward-compatible default). The token comparison is constant-time so a
// wrong token cannot be recovered by timing.
func (s *Server) requireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" && !s.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

// authorized reports whether r presents the configured bearer token. The scheme
// match is case-insensitive per RFC 6750, matching the UI's bearer parsing.
func (s *Server) authorized(r *http.Request) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return false
	}
	got := strings.TrimSpace(h[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// checkResponse is the shared response envelope for both check endpoints: the
// serving node's name alongside the probe's structured Result. A check that
// itself failed (TCP refused, auth rejected, TLS error, ...) is still a
// successful agent operation, so it is reported here with 200 — see
// handleCheckTCP/handleCheckPostgres in checkhandlers.go for the 200-vs-4xx
// boundary this type sits on.
type checkResponse struct {
	Node string `json:"node"`
	probe.Result
}

// denied writes the standard 403 response for a policy/metadata refusal and
// increments the denied metric. Shared by both check handlers so a guard hit
// or a resolveTarget policy denial look identical to clients regardless of
// which check kind (or which rejection path) produced it.
func (s *Server) denied(w http.ResponseWriter) {
	s.metrics.denied.Add(1)
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "target denied by policy"})
}

// throttled writes the standard 429 response (with a Retry-After hint derived
// from the limiter's reservation delay) and increments the throttled metric.
// Shared by both check handlers and by both limiters (general + postgres) that
// can produce this outcome.
func (s *Server) throttled(w http.ResponseWriter, retry time.Duration) {
	s.metrics.throttled.Add(1)
	ra := ratelimit.RetryAfterSeconds(retry)
	w.Header().Set("Retry-After", ra)
	writeJSON(w, http.StatusTooManyRequests, map[string]string{
		"error":       "rate limit exceeded",
		"retry_after": ra,
	})
}

// resolveTarget enforces the connection policy and returns the addresses to
// dial. When a policy is configured, host is resolved exactly once here and
// every resolved IP is checked against the policy; the returned dialHosts are
// vetted IP literals so the subsequent probe dials precisely what was
// authorized, rather than re-resolving the name — which a DNS-rebinding attacker
// could swing to an internal address between the policy check and the dial. All
// vetted addresses are returned (not just the first) so the probe keeps the
// normal multi-address fallback for dual-stack or round-robin targets — it races
// them concurrently, so the target is reachable as long as any vetted address
// is. With no policy configured, nil is returned so the probe dials the host
// name directly.
//
// dns carries the vetted addresses (and the lookup latency) back to the caller
// so the probe reports exactly what it dialed, without a second DNS query; it is
// nil when no policy is configured (the probe resolves host itself). CNAME is
// intentionally not reported in policy mode: capturing it would need an extra
// lookup, reintroducing the duplicate-query cost the single resolution avoids.
//
// ok is false when the target is denied or, with a policy set, the host cannot
// be resolved (fail closed, since the dial target cannot be verified).
func (s *Server) resolveTarget(ctx context.Context, host string) (dialHosts []string, dns *probe.DNSResult, ok bool) {
	if s.policy.empty() {
		return nil, nil, true
	}
	if ip := net.ParseIP(host); ip != nil {
		if !s.policy.Allowed(ip) {
			return nil, nil, false
		}
		return []string{host}, &probe.DNSResult{Resolved: []string{host}}, true
	}
	start := time.Now()
	addrs, err := s.resolver.LookupIPAddr(ctx, host)
	elapsedMS := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil || len(addrs) == 0 {
		return nil, nil, false
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if !s.policy.Allowed(a.IP) {
			return nil, nil, false
		}
		out = append(out, a.IP.String())
	}
	return out, &probe.DNSResult{Resolved: out, MS: elapsedMS}, true
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "node": s.nodeName})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	b.WriteString("# HELP portreach_checks_total Total number of probe checks by result.\n")
	b.WriteString("# TYPE portreach_checks_total counter\n")
	fmt.Fprintf(&b, "portreach_checks_total{result=\"ok\"} %d\n", s.metrics.ok.Load())
	fmt.Fprintf(&b, "portreach_checks_total{result=\"fail\"} %d\n", s.metrics.fail.Load())
	fmt.Fprintf(&b, "portreach_checks_total{result=\"denied\"} %d\n", s.metrics.denied.Load())
	fmt.Fprintf(&b, "portreach_checks_total{result=\"bad_request\"} %d\n", s.metrics.badReq.Load())
	fmt.Fprintf(&b, "portreach_checks_total{result=\"throttled\"} %d\n", s.metrics.throttled.Load())
	_, _ = io.WriteString(w, b.String())
}

func (s *Server) badRequest(w http.ResponseWriter, msg string) {
	s.metrics.badReq.Add(1)
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
