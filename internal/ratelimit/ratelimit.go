// Package ratelimit provides a reservation-based, multi-bucket token-bucket
// limiter for the UI API and (optionally) the agent. A single check is gated by
// up to three independent scopes at once — per identity (authenticated user, or
// proxy-aware client IP when auth is off), per target (host:port), and a process
// global. The defining property (review finding #7) is that the scopes are
// reserved *atomically*: if any bucket would deny, every token tentatively taken
// is rolled back, so a rejected request never burns an unrelated bucket.
//
// The limiter is off unless explicitly enabled; a zero Config Validates as a
// no-op and Reserve always allows. All time flows through an injectable clock so
// tests are hermetic (no real sleeps).
package ratelimit

import (
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// defaultMaxWait caps the Retry-After we ever report (and the largest
// reservation delay we will tolerate before treating a request as rejected). It
// bounds both the value handed to clients and the work the limiter does, so an
// impossible/edge reservation can never turn into a hang or an unbounded hint.
const defaultMaxWait = 60 * time.Second

// defaultIdleTTL is how long an idle per-key bucket is kept before eviction.
const defaultIdleTTL = 10 * time.Minute

// evictEvery sweeps idle buckets once every N Reserve calls, amortizing the
// O(n) sweep so steady-state Reserve stays cheap while memory stays bounded.
const evictEvery = 256

// Scope describes one token bucket dimension. A non-positive Rate disables the
// scope entirely (that dimension is simply not limited); Burst is the bucket
// capacity (and the most tokens available in a burst).
type Scope struct {
	Rate  float64 // tokens per second; <= 0 disables this scope
	Burst int     // bucket capacity
}

func (s Scope) enabled() bool { return s.Rate > 0 }

// Config is the limiter configuration. The zero value (Enabled=false) is a valid
// no-op: Validate passes and Reserve always allows, preserving today's unlimited
// behaviour for deployments that never opt in.
type Config struct {
	Enabled bool

	// Per-scope buckets. Each may be independently disabled (Rate <= 0).
	User   Scope // keyed by identity (authenticated user, else client IP)
	Target Scope // keyed by host:port
	Global Scope // single process-wide bucket

	// Proxy-aware client-IP keying (review finding #8). A forwarded header is
	// honoured only when the request's RemoteAddr is one of these trusted
	// proxies; otherwise RemoteAddr is used. CIDRs or bare IPs.
	TrustedProxies  []string
	ForwardedHeader string // default "X-Forwarded-For" when unset

	// MaxWait caps Retry-After and the tolerated reservation delay; IdleTTL is
	// the idle-bucket eviction horizon. Both fall back to sane defaults when 0.
	MaxWait time.Duration
	IdleTTL time.Duration
}

// Validate reports configuration errors. A disabled/zero limiter is valid (the
// positive checks apply only when Enabled), so the default-off config passes and
// only a half-configured limiter is rejected (review finding #R6).
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if err := c.User.validate("user"); err != nil {
		return err
	}
	if err := c.Target.validate("target"); err != nil {
		return err
	}
	if err := c.Global.validate("global"); err != nil {
		return err
	}
	if !c.User.enabled() && !c.Target.enabled() && !c.Global.enabled() {
		return fmt.Errorf("ratelimit: enabled but no scope configured (set a positive rate on user, target, or global)")
	}
	if c.MaxWait < 0 {
		return fmt.Errorf("ratelimit: maxWait must not be negative")
	}
	if _, err := parsePrefixes(c.TrustedProxies); err != nil {
		return err
	}
	return nil
}

func (s Scope) validate(name string) error {
	if s.Rate < 0 {
		return fmt.Errorf("ratelimit: %s rate must not be negative", name)
	}
	// A configured scope reserves n=1 per request, so burst must be >= 1 — a
	// zero burst makes every reservation impossible (n > burst).
	if s.enabled() && s.Burst < 1 {
		return fmt.Errorf("ratelimit: %s burst must be >= 1 when rate is set", name)
	}
	return nil
}

// Reservation is the outcome of a Reserve call. OK reports whether every
// applicable bucket granted a token immediately; when false the limiter has
// already rolled back every token it tentatively took and RetryAfter is a
// bounded hint for when to retry.
type Reservation struct {
	OK         bool
	RetryAfter time.Duration
}

// Limiter holds the per-scope bucket registries. A nil *Limiter is a valid
// disabled limiter (Reserve always allows), so callers may hold an unset one.
type Limiter struct {
	enabled bool
	maxWait time.Duration
	idleTTL time.Duration
	now     func() time.Time

	user   *registry     // nil when the user scope is disabled
	target *registry     // nil when the target scope is disabled
	global *rate.Limiter // nil when the global scope is disabled

	proxies         []netip.Prefix
	forwardedHeader string

	mu    sync.Mutex
	calls int // Reserve counter driving periodic eviction
}

// Option customizes a Limiter at construction (e.g. an injectable clock).
type Option func(*Limiter)

// WithClock injects the time source, making the limiter hermetic for tests.
func WithClock(now func() time.Time) Option {
	return func(l *Limiter) { l.now = now }
}

// New validates cfg and builds a Limiter. A disabled config yields a limiter
// whose Reserve always allows.
func New(cfg Config, opts ...Option) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	l := &Limiter{
		enabled:         cfg.Enabled,
		maxWait:         cfg.MaxWait,
		idleTTL:         cfg.IdleTTL,
		now:             time.Now,
		forwardedHeader: cfg.ForwardedHeader,
	}
	if l.maxWait <= 0 {
		l.maxWait = defaultMaxWait
	}
	if l.idleTTL <= 0 {
		l.idleTTL = defaultIdleTTL
	}
	if l.forwardedHeader == "" {
		l.forwardedHeader = "X-Forwarded-For"
	}
	if cfg.Enabled {
		if cfg.User.enabled() {
			l.user = newRegistry(cfg.User)
		}
		if cfg.Target.enabled() {
			l.target = newRegistry(cfg.Target)
		}
		if cfg.Global.enabled() {
			l.global = rate.NewLimiter(rate.Limit(cfg.Global.Rate), cfg.Global.Burst)
		}
	}
	// parsePrefixes already validated above; reuse its result.
	l.proxies, _ = parsePrefixes(cfg.TrustedProxies)
	for _, opt := range opts {
		opt(l)
	}
	return l, nil
}

// Reserve atomically takes one token from each applicable bucket. If every
// bucket grants immediately the tokens are kept and OK is true. If any bucket
// would deny (over limit, or an impossible/edge reservation), *all* tentatively
// taken tokens are cancelled — so a denied request consumes no unrelated bucket
// (finding #7) — and OK is false with a bounded RetryAfter.
func (l *Limiter) Reserve(identityKey, targetKey string) Reservation {
	if l == nil || !l.enabled {
		return Reservation{OK: true}
	}
	now := l.now()
	l.maybeEvict(now)

	var taken []*rate.Reservation
	var maxDelay time.Duration
	rejected := false

	consider := func(lim *rate.Limiter) {
		if lim == nil {
			return
		}
		r := lim.ReserveN(now, 1)
		taken = append(taken, r)
		if !r.OK() {
			// Impossible reservation (e.g. n > burst): never wait on it —
			// reject with a capped Retry-After (bounded fallback, #R6).
			rejected = true
			if l.maxWait > maxDelay {
				maxDelay = l.maxWait
			}
			return
		}
		// A reject-style limiter treats any required wait as "over limit".
		if d := r.DelayFrom(now); d > 0 {
			rejected = true
			if d > maxDelay {
				maxDelay = d
			}
		}
	}

	if l.user != nil {
		consider(l.user.get(identityKey, now))
	}
	if l.target != nil {
		consider(l.target.get(targetKey, now))
	}
	consider(l.global)

	if rejected {
		// Roll back every reservation — including the ones that granted
		// immediately — so no bucket is left short by a denied request.
		for _, r := range taken {
			r.CancelAt(now)
		}
		if maxDelay > l.maxWait {
			maxDelay = l.maxWait
		}
		return Reservation{OK: false, RetryAfter: maxDelay}
	}
	return Reservation{OK: true}
}

// RetryAfterSeconds renders a Reservation.RetryAfter as a Retry-After header
// value: whole seconds rounded up, floored at 1 so a sub-second hint never
// serializes as "0" (which clients read as "retry immediately", defeating the
// throttle). Shared by the UI and agent throttle responses.
func RetryAfterSeconds(d time.Duration) string {
	secs := int(math.Ceil(d.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return strconv.Itoa(secs)
}

// maybeEvict sweeps idle buckets periodically to keep memory bounded.
func (l *Limiter) maybeEvict(now time.Time) {
	l.mu.Lock()
	l.calls++
	due := l.calls%evictEvery == 0
	l.mu.Unlock()
	if !due {
		return
	}
	l.evictIdle(now)
}

// evictIdle removes per-key buckets not seen within IdleTTL.
func (l *Limiter) evictIdle(now time.Time) {
	if l.user != nil {
		l.user.evictIdle(now, l.idleTTL)
	}
	if l.target != nil {
		l.target.evictIdle(now, l.idleTTL)
	}
}

// registry is a keyed set of per-scope token buckets, created lazily.
type registry struct {
	rate  rate.Limit
	burst int

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

func newRegistry(s Scope) *registry {
	return &registry{
		rate:    rate.Limit(s.Rate),
		burst:   s.Burst,
		buckets: make(map[string]*bucket),
	}
}

// get returns the bucket for key, creating it on first use and refreshing its
// last-seen time so active buckets survive eviction.
func (r *registry) get(key string, now time.Time) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.buckets[key]
	if b == nil {
		b = &bucket{lim: rate.NewLimiter(r.rate, r.burst)}
		r.buckets[key] = b
	}
	b.seen = now
	return b.lim
}

// peek returns the existing bucket for key without creating one (test helper).
func (r *registry) peek(key string) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if b := r.buckets[key]; b != nil {
		return b.lim
	}
	return nil
}

func (r *registry) evictIdle(now time.Time, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, b := range r.buckets {
		if now.Sub(b.seen) > ttl {
			delete(r.buckets, k)
		}
	}
}

func (r *registry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}
