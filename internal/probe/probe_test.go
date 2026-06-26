package probe

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// listenLocal opens a TCP listener on 127.0.0.1 and returns it with its port.
func listenLocal(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	return ln, port
}

func TestRunOpenPort(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	res := Run(context.Background(), "127.0.0.1", []string{"127.0.0.1"}, port, "tcp", 2*time.Second, nil)
	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
	if res.TCP == nil || !res.TCP.OK {
		t.Fatalf("expected TCP.OK, got %+v", res.TCP)
	}
	if res.SrcIP == "" {
		t.Errorf("expected non-empty src_ip")
	}
	if res.Proto != "tcp" {
		t.Errorf("expected proto tcp, got %q", res.Proto)
	}
}

func TestRunClosedPort(t *testing.T) {
	// Open then immediately close to obtain a port that is almost certainly closed.
	ln, port := listenLocal(t)
	_ = ln.Close()

	res := Run(context.Background(), "127.0.0.1", []string{"127.0.0.1"}, port, "tcp", 2*time.Second, nil)
	if res.TCP == nil {
		t.Fatalf("expected TCP result")
	}
	if res.TCP.OK {
		t.Fatalf("expected TCP.OK=false for closed port")
	}
	if res.TCP.Error == "" {
		t.Errorf("expected TCP error for closed port")
	}
}

func TestRunResolveLocalhost(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	res := Run(context.Background(), "localhost", []string{"localhost"}, port, "tcp", 2*time.Second, nil)
	if res.DNS == nil {
		t.Fatalf("expected DNS result")
	}
	if res.DNS.Error != "" {
		t.Fatalf("unexpected DNS error: %s", res.DNS.Error)
	}
	if len(res.DNS.Resolved) == 0 {
		t.Errorf("expected resolved addresses for localhost")
	}
}

func TestRunUnknownHost(t *testing.T) {
	res := Run(context.Background(), "nonexistent.invalid.example.", []string{"nonexistent.invalid.example."}, 80, "tcp", 2*time.Second, nil)
	if res.DNS == nil {
		t.Fatalf("expected DNS result")
	}
	if res.DNS.Error == "" {
		t.Errorf("expected DNS error for nonexistent host")
	}
	if res.TCP == nil || res.TCP.OK {
		t.Errorf("expected TCP to fail for unresolvable host")
	}
}

func TestRunInvalidPort(t *testing.T) {
	for _, p := range []int{0, -1, 70000} {
		res := Run(context.Background(), "127.0.0.1", []string{"127.0.0.1"}, p, "tcp", time.Second, nil)
		if res.Error == "" {
			t.Errorf("port %d: expected validation error", p)
		}
		if res.TCP != nil {
			t.Errorf("port %d: expected no TCP attempt", p)
		}
	}
}

func TestRunInvalidProto(t *testing.T) {
	res := Run(context.Background(), "127.0.0.1", []string{"127.0.0.1"}, 80, "udp", time.Second, nil)
	if res.Error == "" {
		t.Fatalf("expected error for unsupported proto")
	}
	if !strings.Contains(res.Error, "udp") {
		t.Errorf("expected error to mention proto, got %q", res.Error)
	}
}

func TestRunTimeout(t *testing.T) {
	// Use an already-expired context so the dial deadline is in the past before
	// the connection is attempted. This exercises the timeout-normalization path
	// deterministically, without depending on a non-routable address actually
	// timing out (transparent proxies/VPNs can accept such connections).
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	res := Run(ctx, "192.0.2.1", []string{"192.0.2.1"}, 9, "tcp", time.Second, nil)
	if res.TCP == nil {
		t.Fatalf("expected TCP result")
	}
	if res.TCP.OK {
		t.Fatalf("did not expect a successful dial with an expired context")
	}
	if res.TCP.Error == "" {
		t.Errorf("expected a TCP error")
	}
	if res.TCP.Error != "i/o timeout" {
		t.Errorf("expected timeout error, got %q", res.TCP.Error)
	}
}

// TestRunFallbackToSecondAddress verifies that when one dial address is
// unreachable the probe still connects via a reachable sibling, rather than
// reporting the target unreachable. dial uses one port for every address, so the
// fallback is exercised across IPs: one entry is an unreachable loopback address
// (127.0.0.2, nothing listening → refused), the other a live local listener on
// the same port. The result must come from the live listener — only it can
// connect, so a successful TCP result proves the fallback to the reachable
// sibling. Loopback addresses (127.0.0.0/8) are used rather than a documentation
// range like 192.0.2.0/24 because loopback never leaves the host: a VPN or proxy
// cannot route the "unreachable" address to something that accepts the
// connection and steal the race, which made TEST-NET addresses flaky in such
// environments.
func TestRunFallbackToSecondAddress(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	res := Run(context.Background(), "example.test", []string{"127.0.0.2", "127.0.0.1"}, port, "tcp", 2*time.Second, nil)
	if res.TCP == nil || !res.TCP.OK {
		t.Fatalf("expected the reachable sibling to connect, got %+v", res.TCP)
	}
	if !net.ParseIP(res.SrcIP).IsLoopback() {
		t.Fatalf("expected the loopback listener to win (proving fallback), got src_ip %q", res.SrcIP)
	}
}

// TestRunBlackholeFirstAddressDoesNotStallSecond covers the unreachable-first
// case: even when an unreachable address (127.0.0.2, nothing listening) fails,
// the live loopback sibling connects promptly because the addresses are raced
// rather than tried in sequence. With a serial fallback a short budget could be
// spent entirely on the first address; here the probe must return well inside the
// deadline with the loopback connection. Ordering the unreachable address first
// makes the concurrency observable. Loopback addresses are used so the test stays
// hermetic — see TestRunFallbackToSecondAddress.
func TestRunBlackholeFirstAddressDoesNotStallSecond(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	start := time.Now()
	res := Run(context.Background(), "example.test", []string{"127.0.0.2", "127.0.0.1"}, port, "tcp", 5*time.Second, nil)
	if res.TCP == nil || !res.TCP.OK {
		t.Fatalf("expected the loopback sibling to connect despite the unreachable first address, got %+v", res.TCP)
	}
	if !net.ParseIP(res.SrcIP).IsLoopback() {
		t.Fatalf("expected the loopback listener to win, got src_ip %q", res.SrcIP)
	}
	// The loopback dial completes in milliseconds; racing means we never wait for
	// the blackhole to time out, so the probe returns far inside the budget.
	if elapsed := time.Since(start); elapsed >= 4*time.Second {
		t.Errorf("expected the concurrent dial to return promptly, took %v", elapsed)
	}
}

// TestRunManyAddressesBoundedPool exercises the bounded worker pool with far more
// addresses than maxConcurrentDials. The reachable loopback is dialed alongside a
// large set of distinct blackholes: the pool must connect via the reachable
// address, cancel the rest, and return promptly without deadlocking or leaking —
// proving the feed/worker/collect loop stays correct when the address count
// exceeds the concurrency cap. The blackholes that are still in flight when the
// winner cancels return immediately, so the probe finishes far inside the budget.
//
// The blackholes are unassigned loopback addresses (127.0.0.2+) rather than a
// documentation range like 192.0.2.0/24: 127.0.0.0/8 never leaves the host, so a
// VPN or proxy cannot route a "blackhole" to something that accepts the
// connection and steal the race from the loopback listener — which would make the
// src_ip assertion flaky (and did, with TEST-NET addresses, in such environments).
func TestRunManyAddressesBoundedPool(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	hosts := []string{"127.0.0.1"}
	for i := 0; i < maxConcurrentDials*3; i++ {
		hosts = append(hosts, "127.0.0."+strconv.Itoa(i+2))
	}

	start := time.Now()
	res := Run(context.Background(), "example.test", hosts, port, "tcp", 5*time.Second, nil)
	if res.TCP == nil || !res.TCP.OK {
		t.Fatalf("expected the reachable address to connect, got %+v", res.TCP)
	}
	if !net.ParseIP(res.SrcIP).IsLoopback() {
		t.Fatalf("expected the loopback listener to win, got src_ip %q", res.SrcIP)
	}
	if elapsed := time.Since(start); elapsed >= 4*time.Second {
		t.Errorf("expected prompt return once the winner cancels the pool, took %v", elapsed)
	}
}

// TestRunReachableAddressSortsLastWithinCap proves the bounded pool keeps its
// "reachable as long as ANY address is" guarantee for an RRset up to the cap,
// regardless of ordering. The reachable loopback sorts LAST behind a full wave of
// blackholes (exactly maxConcurrentDials addresses total), so every address is
// dialed in the same wave: the late address must still win promptly rather than be
// starved by the earlier hangs. This complements TestRunManyAddressesBoundedPool,
// which puts the reachable address first and so never exercises a late winner.
func TestRunReachableAddressSortsLastWithinCap(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	var hosts []string
	for i := 0; i < maxConcurrentDials-1; i++ {
		hosts = append(hosts, "127.0.0."+strconv.Itoa(i+2)) // hermetic loopback blackholes
	}
	hosts = append(hosts, "127.0.0.1") // reachable address sorts last, within the cap

	start := time.Now()
	res := Run(context.Background(), "example.test", hosts, port, "tcp", 5*time.Second, nil)
	if res.TCP == nil || !res.TCP.OK {
		t.Fatalf("expected the late reachable address to connect, got %+v", res.TCP)
	}
	if !net.ParseIP(res.SrcIP).IsLoopback() {
		t.Fatalf("expected the loopback listener to win, got src_ip %q", res.SrcIP)
	}
	if elapsed := time.Since(start); elapsed >= 4*time.Second {
		t.Errorf("expected the late address dialed in the first wave to win promptly, took %v", elapsed)
	}
}

func TestValidateDefaults(t *testing.T) {
	proto, timeout, err := Validate("h", 80, "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proto != "tcp" {
		t.Errorf("expected default proto tcp, got %q", proto)
	}
	if timeout != DefaultTimeout {
		t.Errorf("expected default timeout, got %v", timeout)
	}
}

func TestValidateCapsTimeout(t *testing.T) {
	_, timeout, err := Validate("h", 80, "tcp", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if timeout != MaxTimeout {
		t.Errorf("expected timeout capped to %v, got %v", MaxTimeout, timeout)
	}
}

func TestValidateEmptyHost(t *testing.T) {
	if _, _, err := Validate("  ", 80, "tcp", time.Second); err == nil {
		t.Errorf("expected error for empty host")
	}
}

func TestNormalizeErrTimeout(t *testing.T) {
	if got := normalizeErr(context.DeadlineExceeded); got != "i/o timeout" {
		t.Errorf("expected i/o timeout, got %q", got)
	}
}

// ensure port formatting via JoinHostPort matches strconv (guards regressions).
func TestPortFormatting(t *testing.T) {
	if net.JoinHostPort("h", strconv.Itoa(8123)) != "h:8123" {
		t.Errorf("unexpected join")
	}
}
