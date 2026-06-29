// Package agent implements the probe HTTP server that runs on each point.
package agent

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lavr/portreach/internal/probe"
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
	ok     atomic.Int64
	fail   atomic.Int64
	denied atomic.Int64
	badReq atomic.Int64
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

	// token, when non-empty, is the shared bearer secret required on /check and
	// (unless metricsPublic) /metrics. Empty disables the check entirely, keeping
	// the agent open — the backward-compatible default.
	token string
	// metricsPublic re-opens /metrics for unauthenticated scraping (Prometheus)
	// even when a token is configured. /check stays gated regardless.
	metricsPublic bool
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

// Handler returns the agent's HTTP routes. /check (and /metrics, unless
// metricsPublic) require the bearer token when one is configured; /healthz is
// always open so cluster probes do not need the secret.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/check", s.requireToken(s.handleCheck))
	mux.HandleFunc("/healthz", s.handleHealthz)
	if s.metricsPublic {
		mux.HandleFunc("/metrics", s.handleMetrics)
	} else {
		mux.HandleFunc("/metrics", s.requireToken(s.handleMetrics))
	}
	return mux
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

type checkResponse struct {
	Node string `json:"node"`
	probe.Result
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := q.Get("host")
	proto := q.Get("proto")
	if proto == "" {
		proto = "tcp"
	}

	port, err := strconv.Atoi(q.Get("port"))
	if err != nil {
		s.badRequest(w, "invalid port: "+q.Get("port"))
		return
	}

	timeout := probe.DefaultTimeout
	if ts := q.Get("timeout"); ts != "" {
		d, err := time.ParseDuration(ts)
		if err != nil {
			s.badRequest(w, "invalid timeout: "+ts)
			return
		}
		timeout = d
	}

	proto, timeout, err = probe.Validate(host, port, proto, timeout)
	if err != nil {
		s.badRequest(w, err.Error())
		return
	}

	// Bound the policy DNS resolution by the same capped timeout the probe uses.
	// resolveTarget's LookupIPAddr runs before the probe and would otherwise sit
	// on the bare request context (no deadline), letting a hostile or blackholed
	// name pin the request well past probe.MaxTimeout — the request-pinning DoS
	// the cap exists to prevent, just on the policy-resolution step.
	resolveCtx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	dialHosts, dns, ok := s.resolveTarget(resolveCtx, host)
	if !ok {
		s.metrics.denied.Add(1)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "target denied by policy"})
		return
	}

	// The dial uses the vetted dialHosts (IP literals when a policy is active) to
	// stay rebinding-safe. When the policy already resolved host, that lookup is
	// passed through as dns so probe.Run reports the exact vetted address set
	// rather than resolving a second time — a second lookup would both spend more
	// of the shared timeout before any TCP attempt and could report a different
	// answer set than the one actually dialed/authorized (rebinding or round-robin
	// churn between the two queries). With no policy, dns is nil and probe.Run
	// resolves host itself for reporting. resolveCtx is reused (not r.Context())
	// so the policy resolution and the probe share a single timeout budget —
	// context.WithDeadline keeps the earlier resolveCtx deadline, making timeout
	// the real end-to-end cap instead of being spent once per step.
	res := probe.Run(resolveCtx, host, dialHosts, port, proto, timeout, dns, s.guard)

	// A connect-guard refusal (cloud metadata / link-local) surfaces as res.Denied.
	// Route it to the exact same denial path as a resolveTarget policy deny —
	// increment the denied metric and return the same 403 shape — so metadata and
	// policy denials are indistinguishable to clients.
	if res.Denied {
		s.metrics.denied.Add(1)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "target denied by policy"})
		return
	}
	if res.TCP != nil && res.TCP.OK {
		s.metrics.ok.Add(1)
	} else {
		s.metrics.fail.Add(1)
	}
	writeJSON(w, http.StatusOK, checkResponse{Node: s.nodeName, Result: res})
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
