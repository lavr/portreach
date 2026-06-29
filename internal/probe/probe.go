// Package probe performs DNS resolution and TCP reachability checks with
// latency measurement, using only the standard library.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// DefaultTimeout is used when the caller passes a non-positive timeout.
const DefaultTimeout = 5 * time.Second

// maxConcurrentDials bounds how many addresses dial() races at once. Capping the
// number of simultaneous dials stops a name that resolves to hundreds of records
// — e.g. an attacker-controlled zone whose every A/AAAA record passes the agent's
// connection policy — from turning a single /check into hundreds of concurrent
// outbound sockets and goroutines (resource-exhaustion DoS).
//
// The cap trades a sliver of coverage for that bound: bounded concurrency, a
// single shared deadline, and a guarantee that every address in an arbitrarily
// large RRset gets a real attempt cannot all hold at once. Up to this many
// addresses the probe dials them all simultaneously, so the target is reachable
// as long as ANY address is; beyond it, if the first wave blackholes until the
// deadline a reachable address sorting later may never be attempted. Real targets
// have a handful of addresses (≤ this cap), so they keep the full guarantee and
// are never throttled; only RRsets large enough to be the abuse case lose it.
const maxConcurrentDials = 16

// MaxTimeout caps the per-probe timeout. The agent endpoint is independently
// reachable, so a caller-supplied timeout is bounded here to stop a request
// like /check?timeout=1h from pinning a goroutine and a half-open dial for an
// arbitrary duration (resource-exhaustion DoS). A reachability probe never
// legitimately needs longer than this.
const MaxTimeout = 30 * time.Second

// DNSResult holds the outcome of resolving the target host.
type DNSResult struct {
	Resolved []string `json:"resolved,omitempty"`
	CNAME    string   `json:"cname,omitempty"`
	MS       float64  `json:"ms"`
	Error    string   `json:"error,omitempty"`
}

// DialResult holds the outcome of the TCP connection attempt.
type DialResult struct {
	OK    bool    `json:"ok"`
	MS    float64 `json:"ms"`
	Error string  `json:"error,omitempty"`
}

// Result is the full outcome of a single probe.
type Result struct {
	Host  string      `json:"host"`
	Port  int         `json:"port"`
	Proto string      `json:"proto"`
	SrcIP string      `json:"src_ip,omitempty"`
	DNS   *DNSResult  `json:"dns,omitempty"`
	TCP   *DialResult `json:"tcp,omitempty"`
	Error string      `json:"error,omitempty"`

	// Denied is set when the connect-time guard refused every address the dial
	// attempted and no TCP connection succeeded, so the caller can route a guard
	// refusal to its policy-denial path instead of reporting a generic dial
	// failure. A guard rejection that loses the race to an allowed sibling leaves
	// Denied false — the denied IP was simply never connected to (the narrowed
	// mixed-RRset semantics). omitempty on both fields keeps a normal (non-denied)
	// response byte-identical to before these fields existed.
	Denied       bool   `json:"denied,omitempty"`
	DeniedReason string `json:"denied_reason,omitempty"`
}

// DenyReason is the fixed reason reported when the connect guard denies a probe.
// It is a constant because the deny set is static, so no per-connection mutable
// reason string has to cross goroutines — only the atomic hit flag does.
const DenyReason = "destination is a denied (cloud metadata / link-local) address"

// errConnDenied is returned by the guard's Control hook to refuse a connection.
var errConnDenied = errors.New("connection to denied address refused")

// DenyGuard refuses TCP connects whose resolved IP falls inside any of its
// networks. It is enforced at connect time via net.Dialer.Control, so it sees the
// actual address net.Dialer selected — defeating DNS rebinding — without the probe
// pre-resolving the name (which would lose the CNAME / DNS-error reporting normal
// targets get). A rejection is candidate-level: it sets a shared atomic flag and
// fails that one connect; Run promotes it to Result.Denied only when the whole
// dial produced no successful connection.
type DenyGuard struct {
	nets []*net.IPNet
}

// NewDenyGuard returns a guard refusing connects to any address in nets, or nil
// when nets is empty (nil guard == no guard, the open default).
func NewDenyGuard(nets []*net.IPNet) *DenyGuard {
	if len(nets) == 0 {
		return nil
	}
	return &DenyGuard{nets: nets}
}

// denied reports whether ip falls in any guarded network.
func (g *DenyGuard) denied(ip net.IP) bool {
	for _, n := range g.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// control returns a net.Dialer.Control hook that refuses a connect to a guarded
// address and records the hit on the supplied atomic flag. The hook can run from
// several goroutines at once — the dial worker pool, plus net.Dialer's own
// Happy-Eyeballs attempts for a single name — so it touches only the atomic and
// the read-only nets, never shared mutable memory.
func (g *DenyGuard) control(hit *atomic.Bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		if ip := net.ParseIP(host); ip != nil && g.denied(ip) {
			hit.Store(true)
			return errConnDenied
		}
		return nil
	}
}

// Validate checks the probe inputs and normalizes the protocol and timeout.
// It returns the proto to use, the timeout to use, and an error for bad input.
func Validate(host string, port int, proto string, timeout time.Duration) (string, time.Duration, error) {
	if strings.TrimSpace(host) == "" {
		return "", 0, errors.New("host is required")
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port out of range: %d", port)
	}
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" {
		return "", 0, fmt.Errorf("unsupported proto: %q", proto)
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}
	return proto, timeout, nil
}

// Run resolves host via DNS for reporting, then attempts a TCP connection on
// port, measuring latency for each step. dialHosts are the addresses to dial:
// they differ from host only when the caller has pre-resolved and vetted target
// IPs (e.g. an agent's connection policy pinning the dial to defeat DNS
// rebinding), in which case DNS reporting reflects the requested name while the
// dial races the vetted addresses, taking the first that connects. Pass nil
// (or an empty slice) to dial host directly, letting the resolver provide its
// normal multi-address fallback.
//
// dns is an optional pre-resolved DNS report: when the caller has already
// resolved host (e.g. the agent's policy check), it passes that result here so
// Run reuses it instead of resolving a second time. Reusing it both saves the
// shared timeout budget for the TCP dial and keeps the reported addresses
// identical to the vetted dialHosts — a fresh lookup could return a different
// answer set (DNS rebinding or round-robin churn between the two queries),
// making the report describe addresses that were never dialed or authorized.
// Pass nil to have Run resolve host itself.
//
// guard, when non-nil, is a connect-time DenyGuard: a connection to any address
// it covers is refused at dial time (see DenyGuard). Pass nil to dial without a
// guard (today's behaviour). The guard never changes the dial/report path for an
// allowed target; it only refuses connects to denied IPs.
//
// It never panics: failures are recorded in the returned Result rather than
// returned as an error (except invalid input).
func Run(ctx context.Context, host string, dialHosts []string, port int, proto string, timeout time.Duration, dns *DNSResult, guard *DenyGuard) Result {
	proto, timeout, err := Validate(host, port, proto, timeout)
	res := Result{Host: host, Port: port, Proto: proto}
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if len(dialHosts) == 0 {
		dialHosts = []string{host}
	}

	deadline := time.Now().Add(timeout)

	if dns != nil {
		res.DNS = dns
	} else {
		dnsCtx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		res.DNS = resolve(dnsCtx, host)
	}

	dialCtx, cancel2 := context.WithDeadline(ctx, deadline)
	defer cancel2()

	var guardHit bool
	res.TCP, res.SrcIP, guardHit = dial(dialCtx, dialHosts, port, guard)

	// Promote a connect-guard rejection to a typed denial only when the dial as a
	// whole found no reachable address. If an allowed sibling connected first the
	// denied IP was never reached, so the result stays a normal OK (the narrowed
	// mixed-RRset semantics). guardHit is read after dial has fully returned, so
	// the atomic is settled — no race with in-flight workers.
	if guardHit && (res.TCP == nil || !res.TCP.OK) {
		res.Denied = true
		res.DeniedReason = DenyReason
	}
	return res
}

// resolve looks up host's addresses and CNAME, timing the lookup.
func resolve(ctx context.Context, host string) *DNSResult {
	var r net.Resolver
	out := &DNSResult{}

	start := time.Now()
	addrs, err := r.LookupHost(ctx, host)
	out.MS = msSince(start)
	if err != nil {
		out.Error = normalizeErr(err)
		return out
	}
	out.Resolved = addrs

	if cname, err := r.LookupCNAME(ctx, host); err == nil {
		out.CNAME = cname
	}
	return out
}

// dial races a TCP connection to every host and reports the first that succeeds,
// then cancels the rest. Dialing the vetted addresses in parallel (rather than
// one after another) reproduces the Happy Eyeballs behavior net.Dialer applies
// internally for a hostname: a dual-stack or round-robin target is reachable as
// long as ANY of its concurrently-dialed addresses is, and a slow or blackholing
// address can never consume the deadline at the expense of a sibling dialed in
// the same wave. This holds even for a short timeout, where a serial fallback
// would spend the whole budget on a single hanging address.
//
// The race runs through a bounded pool of at most maxConcurrentDials workers, so
// a name resolving to many addresses cannot fan out into an unbounded number of
// simultaneous sockets and goroutines. Concurrency is capped, not coverage: every
// distinct address is fed to the pool. But the cap and the single shared deadline
// interact — for an RRset larger than maxConcurrentDials, if the first wave of
// workers all blackhole until the deadline, addresses queued behind them get only
// an already-expired dial. The "reachable as long as ANY address is" guarantee is
// therefore unconditional only up to maxConcurrentDials addresses; for larger
// RRsets it is best-effort (see that constant for why this tradeoff is accepted).
// It returns the dial result, the local source IP observed on the winning
// connection (empty if every dial failed), and whether the connect guard refused
// at least one address. The full timeout applies to the race as a whole.
func dial(ctx context.Context, hosts []string, port int, guard *DenyGuard) (*DialResult, string, bool) {
	out := &DialResult{}
	portStr := strconv.Itoa(port)
	start := time.Now()

	// Dedup repeated records (a name can return the same address more than once)
	// but feed every distinct address to the pool: truncating the list would let a
	// host whose only reachable address sorts late — e.g. an IPv6-only-reachable,
	// dual-stack target where the IPv4 records come first — be falsely reported
	// down. The pool bounds concurrency, not the set of addresses fed in; for an
	// RRset larger than maxConcurrentDials a late address is still attempted unless
	// the first wave consumes the whole deadline (see maxConcurrentDials).
	hosts = dedup(hosts)

	// Cancelling stops the remaining in-flight dials once we have a winner.
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		srcIP string
		err   error
	}
	// Buffered for every address so each worker sends exactly once and exits even
	// after we stop reading on the first success — no goroutine or connection leak.
	ch := make(chan outcome, len(hosts))

	workers := len(hosts)
	if workers > maxConcurrentDials {
		workers = maxConcurrentDials
	}

	// Feed addresses to the worker pool. Sends are gated by the workers ranging
	// over addrCh, so at most `workers` dials are in flight at once. Once a winner
	// cancels dctx the remaining DialContext calls return immediately, draining
	// the queue quickly; we still read one outcome per address below.
	addrCh := make(chan string)
	go func() {
		defer close(addrCh)
		for _, host := range hosts {
			addrCh <- net.JoinHostPort(host, portStr)
		}
	}()

	// guardHit records whether the connect guard refused any address. It is shared
	// across the worker pool (and net.Dialer's own Happy-Eyeballs attempts), so it
	// must be atomic; Run reads it only after every worker has finished.
	var guardHit atomic.Bool
	var d net.Dialer
	if guard != nil {
		d.Control = guard.control(&guardHit)
	}
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range addrCh {
				conn, err := d.DialContext(dctx, "tcp", addr)
				if err != nil {
					ch <- outcome{err: err}
					continue
				}
				srcIP := ""
				if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
					srcIP = la.IP.String()
				}
				_ = conn.Close() // the probe only needs reachability + source IP
				ch <- outcome{srcIP: srcIP}
			}
		}()
	}

	var lastErr error
	winnerSrc := ""
	for range hosts {
		o := <-ch
		if o.err != nil {
			lastErr = o.err
			continue
		}
		if !out.OK {
			out.OK = true
			out.MS = msSince(start)
			winnerSrc = o.srcIP
			cancel() // abort the remaining dials; we already have a connection
		}
	}
	if out.OK {
		return out, winnerSrc, guardHit.Load()
	}
	out.MS = msSince(start)
	out.Error = normalizeErr(lastErr)
	return out, "", guardHit.Load()
}

// dedup returns the unique hosts in their original order.
func dedup(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

// normalizeErr renders a network error into a stable, human-readable string,
// distinguishing timeouts from connection refusals.
func normalizeErr(err error) string {
	if err == nil {
		return ""
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return "i/o timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "i/o timeout"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return opErr.Err.Error()
	}
	return err.Error()
}

// msSince returns elapsed milliseconds since t, rounded to 0.1ms.
func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}
