package ratelimit

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// fakeClock is a hermetic, advanceable time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func mustNew(t *testing.T, cfg Config, opts ...Option) *Limiter {
	t.Helper()
	l, err := New(cfg, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

func TestDisabledConfigValidatesAndAllows(t *testing.T) {
	// The zero value is a valid no-op even with nonsense fields ignored.
	if err := (Config{}).Validate(); err != nil {
		t.Fatalf("zero config should validate: %v", err)
	}
	l := mustNew(t, Config{})
	for i := 0; i < 1000; i++ {
		if r := l.Reserve("u", "t"); !r.OK {
			t.Fatalf("disabled limiter denied at %d", i)
		}
	}
	// A nil limiter is also a valid disabled limiter.
	var nilL *Limiter
	if r := nilL.Reserve("u", "t"); !r.OK {
		t.Fatal("nil limiter should allow")
	}
}

func TestInvalidConfigsRejectedOnlyWhenEnabled(t *testing.T) {
	// Disabled: even contradictory scopes are tolerated (no-op).
	bad := Config{User: Scope{Rate: -1, Burst: 0}}
	if err := bad.Validate(); err != nil {
		t.Fatalf("disabled config must pass: %v", err)
	}

	cases := []struct {
		name string
		cfg  Config
	}{
		{"negative rate", Config{Enabled: true, User: Scope{Rate: -1, Burst: 5}}},
		{"burst zero", Config{Enabled: true, User: Scope{Rate: 5, Burst: 0}}},
		{"no scope", Config{Enabled: true}},
		{"negative maxWait", Config{Enabled: true, User: Scope{Rate: 5, Burst: 5}, MaxWait: -time.Second}},
		{"bad proxy", Config{Enabled: true, User: Scope{Rate: 5, Burst: 5}, TrustedProxies: []string{"not-an-ip"}}},
	}
	for _, tc := range cases {
		if err := tc.cfg.Validate(); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}
}

func TestAllowThenDenyAtLimitAndRefill(t *testing.T) {
	clk := newClock()
	l := mustNew(t, Config{
		Enabled: true,
		User:    Scope{Rate: 1, Burst: 2}, // 2 burst, refills 1/sec
	}, WithClock(clk.now))

	// Burst of 2 allowed.
	for i := 0; i < 2; i++ {
		if r := l.Reserve("a", "t"); !r.OK {
			t.Fatalf("burst token %d denied", i)
		}
	}
	// Third denied.
	r := l.Reserve("a", "t")
	if r.OK {
		t.Fatal("third request should be denied")
	}
	if r.RetryAfter <= 0 || r.RetryAfter > time.Second {
		t.Fatalf("retry-after = %v, want (0, 1s]", r.RetryAfter)
	}

	// After 1s, one token refilled.
	clk.advance(time.Second)
	if r := l.Reserve("a", "t"); !r.OK {
		t.Fatal("request after refill should be allowed")
	}
	if r := l.Reserve("a", "t"); r.OK {
		t.Fatal("only one token should have refilled")
	}
}

func TestPerUserAndPerTargetIsolation(t *testing.T) {
	clk := newClock()
	l := mustNew(t, Config{
		Enabled: true,
		User:    Scope{Rate: 1, Burst: 1},
		Target:  Scope{Rate: 1, Burst: 100},
	}, WithClock(clk.now))

	// Exhaust user "a".
	if r := l.Reserve("a", "t1"); !r.OK {
		t.Fatal("a/t1 should pass")
	}
	if r := l.Reserve("a", "t1"); r.OK {
		t.Fatal("a/t1 should be exhausted")
	}
	// Different user, different target buckets: unaffected.
	if r := l.Reserve("b", "t2"); !r.OK {
		t.Fatal("b/t2 should pass — user isolation")
	}

	// Now stress a shared target across many users to prove per-target keying.
	clk.advance(time.Hour) // refill everything
	l2 := mustNew(t, Config{
		Enabled: true,
		Target:  Scope{Rate: 1, Burst: 3},
	}, WithClock(clk.now))
	for i := 0; i < 3; i++ {
		if r := l2.Reserve("user", "shared:80"); !r.OK {
			t.Fatalf("target burst token %d denied", i)
		}
	}
	if r := l2.Reserve("anotheruser", "shared:80"); r.OK {
		t.Fatal("shared target should be exhausted regardless of user")
	}
}

func TestDeniedRequestLeavesOtherBucketsUntouched(t *testing.T) {
	clk := newClock()
	l := mustNew(t, Config{
		Enabled: true,
		User:    Scope{Rate: 0.001, Burst: 1}, // tiny: one token then locked
		Target:  Scope{Rate: 0.001, Burst: 10},
		Global:  Scope{Rate: 0.001, Burst: 10},
	}, WithClock(clk.now))

	now := clk.now()
	// First request from user "a" to target "t": succeeds, consumes 1 of each.
	if r := l.Reserve("a", "t"); !r.OK {
		t.Fatal("first request should pass")
	}
	if got := l.target.peek("t").TokensAt(now); got != 9 {
		t.Fatalf("target tokens after first req = %v, want 9", got)
	}
	if got := l.global.TokensAt(now); got != 9 {
		t.Fatalf("global tokens after first req = %v, want 9", got)
	}

	// Second request from "a": the user bucket denies. The reservation must be
	// rolled back from the target and global buckets — they stay at 9.
	if r := l.Reserve("a", "t"); r.OK {
		t.Fatal("second request should be denied by user bucket")
	}
	if got := l.target.peek("t").TokensAt(now); got != 9 {
		t.Fatalf("target tokens after denied req = %v, want 9 (rollback)", got)
	}
	if got := l.global.TokensAt(now); got != 9 {
		t.Fatalf("global tokens after denied req = %v, want 9 (rollback)", got)
	}
}

func TestImpossibleReservationCappedRetryAfterNoHang(t *testing.T) {
	clk := newClock()

	// (a) Delay exceeds MaxWait: a near-frozen bucket whose second request would
	// require an enormous wait must be rejected with a capped Retry-After.
	l := mustNew(t, Config{
		Enabled: true,
		User:    Scope{Rate: 0.0001, Burst: 1},
		MaxWait: 5 * time.Second,
	}, WithClock(clk.now))
	if r := l.Reserve("a", "t"); !r.OK {
		t.Fatal("first request should pass")
	}
	r := l.Reserve("a", "t")
	if r.OK {
		t.Fatal("second request should be denied")
	}
	if r.RetryAfter != 5*time.Second {
		t.Fatalf("retry-after = %v, want capped 5s", r.RetryAfter)
	}

	// (b) Impossible reservation (burst 0, n > burst): construct a limiter
	// directly to bypass Validate, proving Reserve rejects (never hangs) with a
	// capped Retry-After rather than waiting on a +Inf delay.
	impossible := &Limiter{
		enabled: true,
		maxWait: 3 * time.Second,
		idleTTL: defaultIdleTTL,
		now:     clk.now,
		global:  rate.NewLimiter(1, 0),
	}
	ir := impossible.Reserve("a", "t")
	if ir.OK {
		t.Fatal("impossible reservation should be rejected")
	}
	if ir.RetryAfter != 3*time.Second {
		t.Fatalf("retry-after = %v, want capped 3s", ir.RetryAfter)
	}
}

func TestClientIPProxyAware(t *testing.T) {
	l := mustNew(t, Config{
		Enabled:        true,
		User:           Scope{Rate: 1, Burst: 1},
		TrustedProxies: []string{"10.0.0.0/8"},
	}, WithClock(newClock().now))

	// From a trusted proxy: the forwarded client IP is honoured.
	req := httpReq("10.1.2.3:5000", "X-Forwarded-For", "203.0.113.9")
	if got := l.ClientIP(req); got != "203.0.113.9" {
		t.Fatalf("trusted proxy: ClientIP = %q, want 203.0.113.9", got)
	}

	// From an untrusted source: the header is ignored, RemoteAddr wins.
	req = httpReq("198.51.100.7:5000", "X-Forwarded-For", "203.0.113.9")
	if got := l.ClientIP(req); got != "198.51.100.7" {
		t.Fatalf("untrusted source: ClientIP = %q, want 198.51.100.7", got)
	}

	// Proxy chain: rightmost non-proxy address is the client.
	req = httpReq("10.1.2.3:5000", "X-Forwarded-For", "203.0.113.9, 10.4.5.6")
	if got := l.ClientIP(req); got != "203.0.113.9" {
		t.Fatalf("proxy chain: ClientIP = %q, want 203.0.113.9", got)
	}

	// No trusted proxies configured: always RemoteAddr.
	plain := mustNew(t, Config{Enabled: true, User: Scope{Rate: 1, Burst: 1}})
	req = httpReq("10.1.2.3:5000", "X-Forwarded-For", "203.0.113.9")
	if got := plain.ClientIP(req); got != "10.1.2.3" {
		t.Fatalf("no trusted proxies: ClientIP = %q, want 10.1.2.3", got)
	}
}

func TestIdleBucketsEvicted(t *testing.T) {
	clk := newClock()
	l := mustNew(t, Config{
		Enabled: true,
		User:    Scope{Rate: 1, Burst: 1},
		IdleTTL: time.Minute,
	}, WithClock(clk.now))

	l.Reserve("a", "t")
	if l.user.len() != 1 {
		t.Fatalf("expected 1 bucket, got %d", l.user.len())
	}
	clk.advance(2 * time.Minute)
	l.evictIdle(clk.now())
	if l.user.len() != 0 {
		t.Fatalf("idle bucket should be evicted, got %d", l.user.len())
	}
}

// TestGlobalScopeThrottlesAcrossUsersAndTargets proves the process-global bucket
// gates a request as the *sole* decider: with the per-user and per-target scopes
// disabled and every request crossing a distinct user AND target, the (burst+1)th
// is still denied. A regression dropping the global consideration from Reserve
// would let it through — the over-limit rollback test alone would not catch that.
func TestGlobalScopeThrottlesAcrossUsersAndTargets(t *testing.T) {
	clk := newClock()
	l := mustNew(t, Config{
		Enabled: true,
		Global:  Scope{Rate: 0.001, Burst: 2}, // 2 then effectively locked
	}, WithClock(clk.now))

	if r := l.Reserve("user-a", "t-a"); !r.OK {
		t.Fatal("first global token should pass")
	}
	if r := l.Reserve("user-b", "t-b"); !r.OK {
		t.Fatal("second global token should pass")
	}
	// A third distinct identity/target pair is denied — only the global bucket is
	// in play, so it must be the gate.
	r := l.Reserve("user-c", "t-c")
	if r.OK {
		t.Fatal("global bucket should deny the third request regardless of user/target")
	}
	if r.RetryAfter <= 0 {
		t.Fatalf("retry-after = %v, want > 0", r.RetryAfter)
	}
}

// TestPeriodicEvictionSweepsIdleBuckets drives Reserve enough times to trip the
// evictEvery sweep — the production path, since callers never invoke evictIdle
// directly — and asserts an idle key's bucket is gone while an active key's
// survives. This exercises maybeEvict's due-branch end to end, not the helper.
func TestPeriodicEvictionSweepsIdleBuckets(t *testing.T) {
	clk := newClock()
	l := mustNew(t, Config{
		Enabled: true,
		User:    Scope{Rate: 1000, Burst: 1000}, // generous: never the limiting factor
		IdleTTL: time.Minute,
	}, WithClock(clk.now))

	// Create a bucket for an idle key, then age it past the TTL.
	l.Reserve("idle", "t")
	if l.user.len() != 1 {
		t.Fatalf("expected 1 bucket after first use, got %d", l.user.len())
	}
	clk.advance(2 * time.Minute)

	// Drive Reserve under a *different*, active key until the periodic sweep fires
	// (calls % evictEvery == 0). The idle key is never touched again, so it should
	// be swept; the active key, refreshed each call, survives.
	for i := 0; i < evictEvery; i++ {
		l.Reserve("active", "t")
	}
	if l.user.peek("idle") != nil {
		t.Errorf("idle bucket should be swept by the periodic eviction, still present")
	}
	if l.user.peek("active") == nil {
		t.Errorf("active bucket should survive eviction")
	}
}

// TestImpossibleReservationRollsBackHealthyBuckets proves the impossible branch
// (n > burst, r.OK() false) still cancels the sibling reservations it tentatively
// took: a healthy user bucket paired with an impossible global bucket must be left
// at full tokens after the denied Reserve. This pins the "all cancelled if any
// denies" invariant for the !OK() path, which the single-bucket case cannot.
func TestImpossibleReservationRollsBackHealthyBuckets(t *testing.T) {
	clk := newClock()
	l := &Limiter{
		enabled: true,
		maxWait: defaultMaxWait,
		idleTTL: defaultIdleTTL,
		now:     clk.now,
		user:    newRegistry(Scope{Rate: 1, Burst: 5}),
		global:  rate.NewLimiter(1, 0), // burst 0 → every reservation impossible
	}
	now := clk.now()
	if r := l.Reserve("a", "t"); r.OK {
		t.Fatal("reservation must be denied by the impossible global bucket")
	}
	if got := l.user.peek("a").TokensAt(now); got != 5 {
		t.Errorf("healthy user bucket = %v tokens, want 5 (impossible sibling rolled back)", got)
	}
}

// TestClientIPEdgeCases covers the keying fallbacks the happy-path proxy test
// misses: an all-trusted-proxy chain falls back to the direct peer, an unparseable
// forwarded entry is skipped, and a RemoteAddr with no port is returned raw. These
// are the security-keying surface — a mis-key here lets one client masquerade as
// many.
func TestClientIPEdgeCases(t *testing.T) {
	l := mustNew(t, Config{
		Enabled:        true,
		User:           Scope{Rate: 1, Burst: 1},
		TrustedProxies: []string{"10.0.0.0/8"},
	}, WithClock(newClock().now))

	// Every hop in the chain is a trusted proxy → fall back to the direct peer.
	req := httpReq("10.1.2.3:5000", "X-Forwarded-For", "10.9.9.9, 10.4.5.6")
	if got := l.ClientIP(req); got != "10.1.2.3" {
		t.Errorf("all-proxy chain: ClientIP = %q, want the peer 10.1.2.3", got)
	}

	// A trailing unparseable entry is skipped; the first valid non-proxy wins.
	req = httpReq("10.1.2.3:5000", "X-Forwarded-For", "203.0.113.9, garbage")
	if got := l.ClientIP(req); got != "203.0.113.9" {
		t.Errorf("malformed entry: ClientIP = %q, want 203.0.113.9", got)
	}

	// RemoteAddr with no port is returned raw (best-effort), not dropped.
	req = httpReq("10.1.2.3", "", "")
	if got := l.ClientIP(req); got != "10.1.2.3" {
		t.Errorf("no-port RemoteAddr: ClientIP = %q, want 10.1.2.3", got)
	}
}

// TestRetryAfterSeconds pins the Retry-After rendering directly on the exported
// helper (whole seconds rounded up, floored at 1 so a sub-second hint never
// serializes as "0").
func TestRetryAfterSeconds(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "1"},                       // floor at 1, never "0"
		{100 * time.Millisecond, "1"},  // sub-second rounds up
		{time.Second, "1"},             // exact
		{1500 * time.Millisecond, "2"}, // rounds up
		{60 * time.Second, "60"},
	}
	for _, c := range cases {
		if got := RetryAfterSeconds(c.d); got != c.want {
			t.Errorf("RetryAfterSeconds(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func httpReq(remoteAddr, hdr, val string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/api/check", nil)
	r.RemoteAddr = remoteAddr
	if hdr != "" {
		r.Header.Set(hdr, val)
	}
	return r
}
