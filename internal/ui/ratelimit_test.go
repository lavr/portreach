package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lavr/portreach/internal/auth"
	"github.com/lavr/portreach/internal/ratelimit"
)

// fixedClock returns a constant time so reservations are deterministic: no token
// ever refills during a test, making "allow then deny at the burst" exact.
func fixedClock() func() time.Time {
	t := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// newLimiter builds an enabled limiter with a frozen clock for hermetic tests.
func newLimiter(t *testing.T, cfg ratelimit.Config) *ratelimit.Limiter {
	t.Helper()
	cfg.Enabled = true
	l, err := ratelimit.New(cfg, ratelimit.WithClock(fixedClock()))
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	return l
}

func TestAPICheckRateLimited(t *testing.T) {
	// One token per identity; the second request from the same client is denied.
	lim := newLimiter(t, ratelimit.Config{User: ratelimit.Scope{Rate: 1, Burst: 1}})
	srv := httptest.NewServer(New(staticList{}, time.Second, WithLimiter(lim)).Handler())
	defer srv.Close()

	// First request: under limit → 200.
	resp, err := http.Get(srv.URL + "/api/check?host=example&port=80")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", resp.StatusCode)
	}

	// Second request from the same client: over limit → 429 + Retry-After.
	resp, err = http.Get(srv.URL + "/api/check?host=example&port=80")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After = %q, want 1", ra)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] == "" || body["retry_after"] != "1" {
		t.Errorf("429 body = %+v, want error + retry_after=1", body)
	}
}

func TestAPICheckUnderLimitPasses(t *testing.T) {
	// Burst of 3 admits three requests from the same client before throttling.
	lim := newLimiter(t, ratelimit.Config{User: ratelimit.Scope{Rate: 1, Burst: 3}})
	srv := httptest.NewServer(New(staticList{}, time.Second, WithLimiter(lim)).Handler())
	defer srv.Close()

	for i := 0; i < 3; i++ {
		resp, err := http.Get(srv.URL + "/api/check?host=example&port=80")
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, resp.StatusCode)
		}
	}
}

func TestAPICheckDisabledUnlimited(t *testing.T) {
	// A nil limiter (default) never throttles, even on many rapid requests.
	srv := httptest.NewServer(New(staticList{}, time.Second).Handler())
	defer srv.Close()

	for i := 0; i < 5; i++ {
		resp, err := http.Get(srv.URL + "/api/check?host=example&port=80")
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 (unlimited)", i, resp.StatusCode)
		}
	}
}

// TestPerTargetIsolation proves the target scope keys independently: hitting the
// per-target burst for one host:port does not throttle a different target.
func TestPerTargetIsolation(t *testing.T) {
	lim := newLimiter(t, ratelimit.Config{Target: ratelimit.Scope{Rate: 1, Burst: 1}})
	srv := httptest.NewServer(New(staticList{}, time.Second, WithLimiter(lim)).Handler())
	defer srv.Close()

	get := func(path string) int {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	if code := get("/api/check?host=a&port=80"); code != http.StatusOK {
		t.Fatalf("first target-a = %d, want 200", code)
	}
	if code := get("/api/check?host=a&port=80"); code != http.StatusTooManyRequests {
		t.Fatalf("second target-a = %d, want 429", code)
	}
	// A different target is unaffected.
	if code := get("/api/check?host=b&port=80"); code != http.StatusOK {
		t.Fatalf("target-b = %d, want 200 (isolated)", code)
	}
}

func TestIndexFormRateLimited(t *testing.T) {
	lim := newLimiter(t, ratelimit.Config{User: ratelimit.Scope{Rate: 1, Burst: 1}})
	srv := httptest.NewServer(New(staticList{}, time.Second, WithLimiter(lim)).Handler())
	defer srv.Close()

	// First submitted form: 200 with results.
	resp, err := http.Get(srv.URL + "/?host=example&port=80")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first form status = %d, want 200", resp.StatusCode)
	}

	// Second: throttled → 429 page + Retry-After header.
	resp, err = http.Get(srv.URL + "/?host=example&port=80")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second form status = %d, want 429", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After = %q, want 1", ra)
	}
}

// TestClientIPKeyingTrustedProxy proves the proxy-aware keying (finding #8): when
// RemoteAddr is a trusted proxy, the forwarded client IP is the limiter key, so
// two distinct forwarded clients each get their own bucket; a request without a
// trusted RemoteAddr ignores the (spoofable) header and keys on RemoteAddr.
func TestClientIPKeyingTrustedProxy(t *testing.T) {
	lim := newLimiter(t, ratelimit.Config{
		User:           ratelimit.Scope{Rate: 1, Burst: 1},
		TrustedProxies: []string{"10.0.0.1"},
	})
	h := New(staticList{}, time.Second, WithLimiter(lim)).Handler()

	do := func(remote, xff string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/check?host=example&port=80", nil)
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// From the trusted proxy: each distinct forwarded client gets its own bucket.
	if code := do("10.0.0.1:1111", "203.0.113.5"); code != http.StatusOK {
		t.Fatalf("client .5 first = %d, want 200", code)
	}
	if code := do("10.0.0.1:2222", "203.0.113.5"); code != http.StatusTooManyRequests {
		t.Fatalf("client .5 second = %d, want 429", code)
	}
	if code := do("10.0.0.1:3333", "203.0.113.9"); code != http.StatusOK {
		t.Fatalf("client .9 = %d, want 200 (separate forwarded client)", code)
	}
}

func TestClientIPKeyingUntrustedProxyIgnoresHeader(t *testing.T) {
	lim := newLimiter(t, ratelimit.Config{
		User:           ratelimit.Scope{Rate: 1, Burst: 1},
		TrustedProxies: []string{"10.0.0.1"},
	})
	h := New(staticList{}, time.Second, WithLimiter(lim)).Handler()

	do := func(remote, xff string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/check?host=example&port=80", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// RemoteAddr is NOT a trusted proxy: the spoofable header is ignored and both
	// requests key on the same RemoteAddr, so the second is throttled even though
	// the forwarded IPs differ.
	if code := do("192.0.2.7:1111", "203.0.113.5"); code != http.StatusOK {
		t.Fatalf("untrusted first = %d, want 200", code)
	}
	if code := do("192.0.2.7:2222", "203.0.113.99"); code != http.StatusTooManyRequests {
		t.Fatalf("untrusted second = %d, want 429 (header ignored, same RemoteAddr)", code)
	}
}

// TestIdentityKeyingAuthenticatedUser proves the identity scope keys on the
// authenticated user when present (not the client IP): two requests from the same
// user share a bucket (second throttled), a different user is isolated.
func TestIdentityKeyingAuthenticatedUser(t *testing.T) {
	lim := newLimiter(t, ratelimit.Config{User: ratelimit.Scope{Rate: 1, Burst: 1}})
	h := New(staticList{}, time.Second, WithLimiter(lim)).Handler()

	do := func(user string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/check?host=example&port=80", nil)
		req.RemoteAddr = "192.0.2.1:9999" // same IP for all → proves user keys, not IP
		req = req.WithContext(auth.WithIdentity(req.Context(), auth.Session{User: user}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do("alice"); code != http.StatusOK {
		t.Fatalf("alice first = %d, want 200", code)
	}
	if code := do("alice"); code != http.StatusTooManyRequests {
		t.Fatalf("alice second = %d, want 429", code)
	}
	if code := do("bob"); code != http.StatusOK {
		t.Fatalf("bob = %d, want 200 (separate user, same IP)", code)
	}
}

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
		if got := retryAfterSeconds(c.d); got != c.want {
			t.Errorf("retryAfterSeconds(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
