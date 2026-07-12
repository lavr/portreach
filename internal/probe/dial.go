package probe

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

// connect is the DNS-report + concurrent-dial core shared by every protocol
// runner. It fills res.DNS, res.TCP, res.SrcIP, res.Denied and res.DeniedReason
// exactly as the monolithic TCP path always has, and returns the winning OPEN
// connection — or nil when no address connected.
//
// Ownership of a non-nil conn passes to the caller, which MUST Close it: the TCP
// runner (Run) closes it immediately because it needs nothing more than the fact
// that an address opened; a protocol runner hands it to a handshake and closes it
// afterwards. Every connection that loses the race is already closed inside the
// dial layer, so the caller only ever receives the single winner (see dialConn).
//
// host, port and timeout must already be validated/normalized (see Validate) —
// connect assumes a legal target so both runners share one Validate call up top.
// The deadline handling, the DenyGuard and the bounded worker pool are unchanged
// from the original Run: connect only relocates that core so a second runner can
// reuse it.
func connect(ctx context.Context, host string, dialHosts []string, port int, timeout time.Duration, dns *DNSResult, guard *DenyGuard, res *Result) net.Conn {
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

	dr, conn, srcIP, guardHit := dialConn(dialCtx, dialHosts, port, guard)
	res.TCP = dr
	res.SrcIP = srcIP

	// Promote a connect-guard rejection to a typed denial only when the dial as a
	// whole found no reachable address. If an allowed sibling connected first the
	// denied IP was never reached, so the result stays a normal OK (the narrowed
	// mixed-RRset semantics). guardHit is read after dialConn has fully returned,
	// so the atomic is settled — no race with in-flight workers.
	if guardHit && (res.TCP == nil || !res.TCP.OK) {
		res.Denied = true
		res.DeniedReason = DenyReason
	}
	return conn
}

// dialConn races a TCP connection to every host and returns the first that opens,
// leaving that one connection OPEN for the caller to own; every other connection
// is closed here. Dialing the vetted addresses in parallel (rather than one after
// another) reproduces the Happy Eyeballs behavior net.Dialer applies internally
// for a hostname: a dual-stack or round-robin target is reachable as long as ANY
// of its concurrently-dialed addresses is, and a slow or blackholing address can
// never consume the deadline at the expense of a sibling dialed in the same wave.
// This holds even for a short timeout, where a serial fallback would spend the
// whole budget on a single hanging address.
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
//
// Conn ownership: the dial layer owns every conn it opens. The first successful
// address becomes the winner and is returned still OPEN; a connection that opens
// after a winner was already chosen (a late worker that raced past the cancel) is
// a loser and is closed here, so exactly one conn — or none, on total failure —
// ever escapes this function. It returns the dial result, that winning conn (nil
// unless DialResult.OK), the local source IP observed on it (empty if every dial
// failed), and whether the connect guard refused at least one address. The full
// timeout applies to the race as a whole.
func dialConn(ctx context.Context, hosts []string, port int, guard *DenyGuard) (*DialResult, net.Conn, string, bool) {
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
		conn net.Conn
		err  error
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
	// must be atomic; the caller reads it only after every worker has finished.
	var guardHit atomic.Bool
	var d net.Dialer
	if guard != nil {
		d.Control = guard.control(&guardHit)
	}
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range addrCh {
				conn, err := d.DialContext(dctx, "tcp", addr)
				// Hand every opened conn back over the channel unclosed; the
				// collector below picks the single winner and closes the rest, so
				// conn ownership stays in exactly one place.
				ch <- outcome{conn: conn, err: err}
			}
		}()
	}

	var lastErr error
	var winner net.Conn
	for range hosts {
		o := <-ch
		if o.err != nil {
			lastErr = o.err
			continue
		}
		if winner == nil {
			// First address to open wins: keep this conn OPEN for the caller and
			// cancel the rest of the race.
			winner = o.conn
			out.OK = true
			out.MS = msSince(start)
			cancel() // abort the remaining dials; we already have a connection
			continue
		}
		// A connection that opened after we already have a winner (a worker that
		// raced past the cancel). The caller takes only one conn, so this loser is
		// closed here — the dial layer never leaks a conn it does not hand back.
		_ = o.conn.Close()
	}
	if winner != nil {
		// The source IP is read from the still-open winning conn; LocalAddr is
		// valid for the life of the connection, so the caller sees the same value
		// the old worker recorded just before it used to close the conn.
		srcIP := ""
		if la, ok := winner.LocalAddr().(*net.TCPAddr); ok {
			srcIP = la.IP.String()
		}
		return out, winner, srcIP, guardHit.Load()
	}
	out.MS = msSince(start)
	out.Error = normalizeErr(lastErr)
	return out, nil, "", guardHit.Load()
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
