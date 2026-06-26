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
// It never panics: failures are recorded in the returned Result rather than
// returned as an error (except invalid input).
func Run(ctx context.Context, host string, dialHosts []string, port int, proto string, timeout time.Duration, dns *DNSResult) Result {
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

	res.TCP, res.SrcIP = dial(dialCtx, dialHosts, port)
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
// It returns the dial result plus the local source IP observed on the winning
// connection (empty if every dial failed). The full timeout applies to the race
// as a whole.
func dial(ctx context.Context, hosts []string, port int) (*DialResult, string) {
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

	var d net.Dialer
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
		return out, winnerSrc
	}
	out.MS = msSince(start)
	out.Error = normalizeErr(lastErr)
	return out, ""
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
