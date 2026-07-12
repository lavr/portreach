package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lavr/portreach/internal/checkapi"
	"github.com/lavr/portreach/internal/probe"
	"github.com/lavr/portreach/internal/probe/pgauth"
	"github.com/lavr/portreach/internal/ratelimit"
)

// fakeResolver returns a fixed answer for any host, letting tests drive the
// policy check without real DNS.
type fakeResolver struct {
	ips []net.IPAddr
	err error
}

func (f fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f.ips, f.err
}

// fakeProber is a pgauth.Prober test double returning a fixed AuthResult (and
// counting invocations), letting postgres endpoint tests drive every auth
// outcome without a real PostgreSQL server. calls is a pointer so tests can
// assert the prober was never reached (e.g. a policy/metadata denial or a
// rate-limit rejection must short-circuit before any auth attempt).
type fakeProber struct {
	result checkapi.AuthResult
	calls  *int
}

func (f fakeProber) Probe(ctx context.Context, host string, port int, creds checkapi.Credentials, tlsOpts *checkapi.TLSOptions, dial pgauth.DialFunc, deadline time.Time) checkapi.AuthResult {
	if f.calls != nil {
		*f.calls++
	}
	return f.result
}

type checkResp struct {
	Node string `json:"node"`
	Host string `json:"host"`
	DNS  *struct {
		Resolved []string `json:"resolved"`
		CNAME    string   `json:"cname"`
	} `json:"dns"`
	TCP *struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	} `json:"tcp"`
	Auth *struct {
		OK            bool    `json:"ok"`
		Code          string  `json:"code"`
		Reason        string  `json:"reason"`
		ServerVersion string  `json:"server_version"`
		MS            float64 `json:"ms"`
	} `json:"auth"`
}

// mustEnabledChecks parses csv and fails the test on an error, so test setup
// reads as a one-liner wherever a checkapi.EnabledChecks value is needed.
func mustEnabledChecks(t *testing.T, csv string) checkapi.EnabledChecks {
	t.Helper()
	e, err := checkapi.ParseEnabledChecks(csv)
	if err != nil {
		t.Fatalf("ParseEnabledChecks(%q): %v", csv, err)
	}
	return e
}

// newTestServer builds a TCP-only agent (the historical default these tests
// exercised before /api/check/postgres existed).
func newTestServer(t *testing.T, allow, deny string) *httptest.Server {
	t.Helper()
	policy, err := ParsePolicy(allow, deny)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return httptest.NewServer(New("testnode", policy, WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
}

// openPort returns a listener and its port; caller closes the listener.
func openPort(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port
}

func get(t *testing.T, base, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, buf
}

// postCheck marshals body as JSON and POSTs it to path, presenting token as a
// bearer token when non-empty. Shared by every /api/check/{tcp,postgres} test.
func postCheck(t *testing.T, base, path, token string, body any) (*http.Response, []byte) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return postRaw(t, base, path, token, data)
}

// postRaw POSTs data verbatim, letting tests exercise malformed-JSON bodies
// that a Go struct could never marshal into.
func postRaw(t *testing.T, base, path, token string, data []byte) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("new request %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, buf
}

func TestCheckOpenPort(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := newTestServer(t, "", "")
	defer srv.Close()

	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: port})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var cr checkResp
	if err := json.Unmarshal(body, &cr); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if cr.Node != "testnode" {
		t.Errorf("node = %q, want testnode", cr.Node)
	}
	if cr.TCP == nil || !cr.TCP.OK {
		t.Errorf("expected TCP.OK on open port, got %+v", cr.TCP)
	}
}

func TestCheckClosedPort(t *testing.T) {
	ln, port := openPort(t)
	_ = ln.Close() // free the port so nothing is listening

	srv := newTestServer(t, "", "")
	defer srv.Close()

	req := checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: port, Timeout: checkapi.Duration(2 * time.Second)}
	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var cr checkResp
	if err := json.Unmarshal(body, &cr); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if cr.TCP == nil || cr.TCP.OK {
		t.Errorf("expected TCP.OK=false on closed port, got %+v", cr.TCP)
	}
	if cr.TCP.Error == "" {
		t.Errorf("expected an error string on closed port")
	}
}

// TestCheckBadInput covers 400s produced by checkapi validation (bad
// host/port) as well as by outright malformed JSON (unparseable timeout, a
// string where a number belongs) — both land in the same 400 path via
// decodeCheckRequest / TCPCheckRequest.Validate.
func TestCheckBadInput(t *testing.T) {
	srv := newTestServer(t, "", "")
	defer srv.Close()

	structCases := []checkapi.TCPCheckRequest{
		{Host: "127.0.0.1"},              // missing port
		{Host: "127.0.0.1", Port: 99999}, // out of range
		{Host: "127.0.0.1", Port: -1},    // negative
		{Host: "", Port: 80},             // empty host
		{Host: "   ", Port: 80},          // blank host
	}
	for _, c := range structCases {
		resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", c)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%+v: status = %d, want 400; body=%s", c, resp.StatusCode, body)
		}
	}

	rawCases := [][]byte{
		[]byte(`not json at all`),
		[]byte(`{"host":"127.0.0.1","port":"abc"}`),                // port must be a number
		[]byte(`{"host":"127.0.0.1","port":80,"timeout":"bogus"}`), // unparseable duration
	}
	for _, c := range rawCases {
		resp, body := postRaw(t, srv.URL, "/api/check/tcp", "", c)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", c, resp.StatusCode, body)
		}
	}
}

// TestCheckRequestBodyTooLarge proves the size cap (checkapi.MaxRequestBody)
// is enforced: a body over the cap is rejected as a 400 rather than the
// handler goroutine buffering it in full.
func TestCheckRequestBodyTooLarge(t *testing.T) {
	srv := newTestServer(t, "", "")
	defer srv.Close()

	oversized := make([]byte, checkapi.MaxRequestBody+1024)
	for i := range oversized {
		oversized[i] = 'a'
	}
	resp, body := postRaw(t, srv.URL, "/api/check/tcp", "", oversized)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body too large); body=%s", resp.StatusCode, body)
	}
}

func TestCheckDenyCIDR(t *testing.T) {
	srv := newTestServer(t, "", "127.0.0.0/8")
	defer srv.Close()

	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: 80})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "denied") {
		t.Errorf("expected denied message, got %s", body)
	}
}

func TestCheckAllowList(t *testing.T) {
	// allow only a network that does not include 127.0.0.1 → denied
	srv := newTestServer(t, "10.0.0.0/8", "")
	defer srv.Close()

	resp, _ := postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: 80})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// TestCheckPolicyChecksResolvedIP proves the policy is enforced against the IP a
// hostname resolves to (not the literal name), so a name that resolves into a
// denied range is rejected. This is the DNS-rebinding-resistant path: the dial
// target is the vetted resolved IP.
func TestCheckPolicyChecksResolvedIP(t *testing.T) {
	policy, err := ParsePolicy("", "127.0.0.0/8")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	s := New("testnode", policy, WithEnabledChecks(mustEnabledChecks(t, "tcp")))
	s.resolver = fakeResolver{ips: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "evil.example", Port: 80})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (resolved IP is denied); body=%s", resp.StatusCode, body)
	}
}

// TestResolveTargetReturnsAllVettedIPs guards the multi-address fallback: when a
// hostname resolves to several allowed IPs, resolveTarget must return all of
// them (not just the first) so the probe can fall back to a reachable address if
// the first is down. A round-robin or dual-stack name must not be reported
// unreachable just because its first address happens to be unavailable.
func TestResolveTargetReturnsAllVettedIPs(t *testing.T) {
	policy, err := ParsePolicy("10.0.0.0/8", "")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	s := New("testnode", policy)
	s.resolver = fakeResolver{ips: []net.IPAddr{
		{IP: net.ParseIP("10.0.0.1")},
		{IP: net.ParseIP("10.0.0.2")},
		{IP: net.ParseIP("10.0.0.3")},
	}}

	dialHosts, dns, ok := s.resolveTarget(context.Background(), "rr.example")
	if !ok {
		t.Fatalf("expected target allowed")
	}
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if len(dialHosts) != len(want) {
		t.Fatalf("got %v, want all %v", dialHosts, want)
	}
	for i, w := range want {
		if dialHosts[i] != w {
			t.Errorf("dialHosts[%d] = %q, want %q", i, dialHosts[i], w)
		}
	}

	// The DNS report handed back to the probe must list exactly the vetted
	// addresses, so the response never describes a set that differs from what was
	// dialed and authorized.
	if dns == nil {
		t.Fatalf("expected DNS report alongside vetted dialHosts")
	}
	if len(dns.Resolved) != len(want) {
		t.Fatalf("dns.Resolved = %v, want %v", dns.Resolved, want)
	}
	for i, w := range want {
		if dns.Resolved[i] != w {
			t.Errorf("dns.Resolved[%d] = %q, want %q", i, dns.Resolved[i], w)
		}
	}
}

// TestCheckPolicyFailsClosedOnResolveError verifies that, when a policy is set
// and the host cannot be resolved, the request is denied rather than allowed
// through (the dial target cannot be verified).
func TestCheckPolicyFailsClosedOnResolveError(t *testing.T) {
	policy, err := ParsePolicy("10.0.0.0/8", "")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	s := New("testnode", policy, WithEnabledChecks(mustEnabledChecks(t, "tcp")))
	s.resolver = fakeResolver{err: fmt.Errorf("no such host")}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "unresolvable.example", Port: 80})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (fail closed); body=%s", resp.StatusCode, body)
	}
}

// TestCheckPolicyDialsVettedIP confirms that, with a policy set, a hostname that
// resolves into the allow range is dialed at its vetted IP and connects, and the
// response still reports the requested host (not the IP).
func TestCheckPolicyDialsVettedIP(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	policy, err := ParsePolicy("127.0.0.0/8", "")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	s := New("testnode", policy, WithEnabledChecks(mustEnabledChecks(t, "tcp")))
	s.resolver = fakeResolver{ips: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "db.example", Port: port})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var cr checkResp
	if err := json.Unmarshal(body, &cr); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if cr.TCP == nil || !cr.TCP.OK {
		t.Errorf("expected TCP.OK dialing the vetted IP, got %+v", cr.TCP)
	}
	if cr.Host != "db.example" {
		t.Errorf("host = %q, want the requested name db.example", cr.Host)
	}
	// The DNS report routed through the HTTP handler must carry exactly the
	// vetted IP that was dialed — not the requested name, and not a second
	// resolution. This pins the resolveTarget → probe.Run pass-through contract
	// at the endpoint boundary.
	if cr.DNS == nil || len(cr.DNS.Resolved) != 1 || cr.DNS.Resolved[0] != "127.0.0.1" {
		t.Errorf("dns.resolved = %+v, want [127.0.0.1] (the vetted IP)", cr.DNS)
	}
}

func TestMetricsDenied(t *testing.T) {
	srv := newTestServer(t, "", "127.0.0.0/8")
	defer srv.Close()

	postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: 80}) // denied by policy
	_, body := get(t, srv.URL, "/metrics")
	if !strings.Contains(string(body), `portreach_checks_total{result="denied"} 1`) {
		t.Errorf("expected denied=1, got %s", body)
	}
}

func TestMetricsFail(t *testing.T) {
	ln, port := openPort(t)
	_ = ln.Close() // closed port → probe fails

	srv := newTestServer(t, "", "")
	defer srv.Close()

	postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: port, Timeout: checkapi.Duration(2 * time.Second)})
	_, body := get(t, srv.URL, "/metrics")
	if !strings.Contains(string(body), `portreach_checks_total{result="fail"} 1`) {
		t.Errorf("expected fail=1, got %s", body)
	}
}

func TestHealthz(t *testing.T) {
	srv := newTestServer(t, "", "")
	defer srv.Close()

	resp, body := get(t, srv.URL, "/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "ok") {
		t.Errorf("expected ok status, got %s", body)
	}
}

// TestHealthzMetricsUnaffectedByEnabledChecks confirms /healthz and /metrics
// stay reachable regardless of what --enabled-checks configured (Task 5
// requirement: the allowlist governs check endpoints only, never these two).
func TestHealthzMetricsUnaffectedByEnabledChecks(t *testing.T) {
	postgresOnly, err := checkapi.ParseEnabledChecks("postgres")
	if err != nil {
		t.Fatalf("ParseEnabledChecks: %v", err)
	}
	srv := httptest.NewServer(New("testnode", &Policy{}, WithEnabledChecks(postgresOnly)).Handler())
	defer srv.Close()

	resp, _ := get(t, srv.URL, "/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz status = %d, want 200", resp.StatusCode)
	}
	resp, _ = get(t, srv.URL, "/metrics")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/metrics status = %d, want 200", resp.StatusCode)
	}
}

func TestMetrics(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := newTestServer(t, "", "")
	defer srv.Close()

	postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: port}) // ok
	postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "127.0.0.1"})             // bad_request (missing port)

	resp, body := get(t, srv.URL, "/metrics")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	text := string(body)
	for _, want := range []string{
		`portreach_checks_total{result="ok"} 1`,
		`portreach_checks_total{result="bad_request"} 1`,
		"# TYPE portreach_checks_total counter",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q\n%s", want, text)
		}
	}
}

// getAuth issues a GET with an Authorization: Bearer header (empty token sends
// no header) and returns the response and body.
func getAuth(t *testing.T, base, path, token string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatalf("new request %s: %v", path, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, buf
}

// TestAgentTokenGatesCheck verifies that, when a token is configured, the check
// endpoint rejects missing/wrong tokens with 401 and accepts the right one.
func TestAgentTokenGatesCheck(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := httptest.NewServer(New("testnode", &Policy{}, WithToken("s3cret"), WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
	defer srv.Close()

	req := checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: port}

	// Missing token → 401.
	if resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401; body=%s", resp.StatusCode, body)
	}
	// Wrong token → 401.
	if resp, body := postCheck(t, srv.URL, "/api/check/tcp", "wrong", req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401; body=%s", resp.StatusCode, body)
	}
	// Right token → 200.
	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "s3cret", req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("right token: status = %d, want 200; body=%s", resp.StatusCode, body)
	}
}

// TestAgentTokenSchemeCaseInsensitive verifies the Authorization scheme match is
// case-insensitive per RFC 6750 (so "bearer"/"BEARER" are accepted), matching the
// UI's bearer parsing.
func TestAgentTokenSchemeCaseInsensitive(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := httptest.NewServer(New("testnode", &Policy{}, WithToken("s3cret"), WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
	defer srv.Close()

	data, err := json.Marshal(checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: port})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, scheme := range []string{"bearer", "BEARER", "BeArEr"} {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/check/tcp", bytes.NewReader(data))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", scheme+" s3cret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("scheme %q: status = %d, want 200", scheme, resp.StatusCode)
		}
	}
}

// TestAgentTokenGatesMetrics verifies /metrics is gated behind the token by
// default while /healthz stays open even with a token set.
func TestAgentTokenGatesMetrics(t *testing.T) {
	srv := httptest.NewServer(New("testnode", &Policy{}, WithToken("s3cret")).Handler())
	defer srv.Close()

	if resp, body := getAuth(t, srv.URL, "/metrics", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/metrics no token: status = %d, want 401; body=%s", resp.StatusCode, body)
	}
	if resp, _ := getAuth(t, srv.URL, "/metrics", "s3cret"); resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics with token: status = %d, want 200", resp.StatusCode)
	}
	// /healthz is always open so cluster probes don't need the secret.
	if resp, _ := getAuth(t, srv.URL, "/healthz", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz no token: status = %d, want 200", resp.StatusCode)
	}
}

// TestAgentMetricsPublic verifies --metrics-public opens /metrics only; the
// check endpoint stays gated behind the token.
func TestAgentMetricsPublic(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := httptest.NewServer(New("testnode", &Policy{}, WithToken("s3cret"), WithMetricsPublic(true), WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
	defer srv.Close()

	// /metrics open without a token.
	if resp, _ := getAuth(t, srv.URL, "/metrics", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics public: status = %d, want 200", resp.StatusCode)
	}
	// The check endpoint still requires the token.
	req := checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: port}
	if resp, _ := postCheck(t, srv.URL, "/api/check/tcp", "", req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("check still gated: status = %d, want 401", resp.StatusCode)
	}
}

// TestAgentNoTokenOpen verifies that, with no token configured, the check
// endpoint and /metrics stay open (backward compatible).
func TestAgentNoTokenOpen(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := httptest.NewServer(New("testnode", &Policy{}, WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
	defer srv.Close()

	req := checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: port}
	if resp, _ := postCheck(t, srv.URL, "/api/check/tcp", "", req); resp.StatusCode != http.StatusOK {
		t.Fatalf("check open: status = %d, want 200", resp.StatusCode)
	}
	if resp, _ := getAuth(t, srv.URL, "/metrics", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics open: status = %d, want 200", resp.StatusCode)
	}
}

// TestAgentRateLimit verifies the optional check limiter throttles direct calls
// over the per-target limit (429 + Retry-After) while a different target keys a
// separate bucket and the throttle is counted in /metrics. A frozen clock makes
// it hermetic — no real sleeps, no refill between calls.
func TestAgentRateLimit(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	fixed := time.Now()
	lim, err := ratelimit.New(ratelimit.Config{
		Enabled: true,
		Target:  ratelimit.Scope{Rate: 1, Burst: 1},
	}, ratelimit.WithClock(func() time.Time { return fixed }))
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	srv := httptest.NewServer(New("testnode", &Policy{}, WithLimiter(lim), WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
	defer srv.Close()

	req := checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: port}

	// First call to this target spends the single burst token → allowed.
	if resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", req); resp.StatusCode != http.StatusOK {
		t.Fatalf("first call: status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	// Second call (clock frozen, no refill) → throttled with a Retry-After hint.
	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", req)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second call: status = %d, want 429; body=%s", resp.StatusCode, body)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("429 response missing Retry-After header")
	}
	if !strings.Contains(string(body), "rate limit exceeded") {
		t.Errorf("expected rate-limit message, got %s", body)
	}

	// A different target keys a different bucket → still allowed (per-target).
	other := checkapi.TCPCheckRequest{Host: "localhost", Port: port}
	if resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", other); resp.StatusCode != http.StatusOK {
		t.Fatalf("other target: status = %d, want 200 (per-target isolation); body=%s", resp.StatusCode, body)
	}

	// The throttle is observable in /metrics.
	_, mbody := get(t, srv.URL, "/metrics")
	if !strings.Contains(string(mbody), `portreach_checks_total{result="throttled"} 1`) {
		t.Errorf("expected throttled=1, got %s", mbody)
	}
}

// TestAgentGlobalRateLimit verifies the agent's optional global scope throttles
// across distinct targets: with only a global bucket configured, a second call to
// a *different* target is still 429 — the process-global cap, not the per-target
// bucket, is the gate. A frozen clock keeps it hermetic (no refill between calls).
func TestAgentGlobalRateLimit(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	fixed := time.Now()
	lim, err := ratelimit.New(ratelimit.Config{
		Enabled: true,
		Global:  ratelimit.Scope{Rate: 1, Burst: 1},
	}, ratelimit.WithClock(func() time.Time { return fixed }))
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	srv := httptest.NewServer(New("testnode", &Policy{}, WithLimiter(lim), WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
	defer srv.Close()

	// First call spends the single global token.
	if resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: port}); resp.StatusCode != http.StatusOK {
		t.Fatalf("first call: status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	// A different target is still throttled by the shared global bucket.
	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "localhost", Port: port})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second call (other target): status = %d, want 429 (global cap); body=%s", resp.StatusCode, body)
	}
}

// TestAgentRateLimitUnsetUnlimited verifies that without a limiter the check
// endpoint stays unlimited (today's behaviour): repeated calls to the same
// target all pass.
func TestAgentRateLimitUnsetUnlimited(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := httptest.NewServer(New("testnode", &Policy{}, WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
	defer srv.Close()

	req := checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: port}
	for i := 0; i < 5; i++ {
		if resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", req); resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d: status = %d, want 200 (unlimited); body=%s", i, resp.StatusCode, body)
		}
	}
}

func TestPolicyAllowed(t *testing.T) {
	p, err := ParsePolicy("10.0.0.0/8", "10.1.0.0/16")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if !p.Allowed(net.ParseIP("10.2.0.1")) {
		t.Error("10.2.0.1 should be allowed")
	}
	if p.Allowed(net.ParseIP("10.1.0.1")) {
		t.Error("10.1.0.1 should be denied (deny wins)")
	}
	if p.Allowed(net.ParseIP("192.168.0.1")) {
		t.Error("192.168.0.1 not in allow list, should be denied")
	}
}

func TestParsePolicyError(t *testing.T) {
	if _, err := ParsePolicy("not-a-cidr", ""); err == nil {
		t.Error("expected error for invalid allow CIDR")
	}
	if _, err := ParsePolicy("", "1.2.3.4"); err == nil {
		t.Error("expected error for invalid deny CIDR (missing mask)")
	}
}

// TestCheckMetadataDeniedByDefault verifies the default-on connect guard refuses
// the whole IPv4 link-local range (not just the single metadata IP): a request to
// 169.254.169.254 (IMDS) and a second in-range IP (169.254.170.2, ECS) is routed
// to the same denial path as a policy deny — 403 with the same shape and the
// denied metric incremented. The guard refuses at connect, so no real outbound
// connection is made (hermetic).
func TestCheckMetadataDeniedByDefault(t *testing.T) {
	for _, ip := range []string{"169.254.169.254", "169.254.170.2"} {
		srv := newTestServer(t, "", "") // open agent, default metadata guard on
		// No short timeout: the guard refuses at connect and returns instantly, so a
		// generous budget keeps the test fast while avoiding a deadline-exhaustion
		// flake (an already-expired dial context never reaches Control).
		resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: ip, Port: 80})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: status = %d, want 403 (metadata denied); body=%s", ip, resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "denied") {
			t.Errorf("%s: expected denied message, got %s", ip, body)
		}
		_, mbody := get(t, srv.URL, "/metrics")
		if !strings.Contains(string(mbody), `portreach_checks_total{result="denied"} 1`) {
			t.Errorf("%s: expected denied=1, got %s", ip, mbody)
		}
		srv.Close()
	}
}

// TestCheckMetadataDeniedEvenWhenPolicyAllows proves the guard is independent of
// the operator Policy: a hostname resolving to a metadata IP that the policy
// explicitly allows (0.0.0.0/0) is still refused at connect and reported denied.
func TestCheckMetadataDeniedEvenWhenPolicyAllows(t *testing.T) {
	policy, err := ParsePolicy("0.0.0.0/0", "")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	s := New("testnode", policy, WithEnabledChecks(mustEnabledChecks(t, "tcp")))
	s.resolver = fakeResolver{ips: []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "imds.test", Port: 80})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (guard wins over allow-all policy); body=%s", resp.StatusCode, body)
	}
}

// TestAllowMetadataRemovesGuard verifies WithAllowMetadata removes only the
// built-in guard (default on, removed when opted out).
func TestAllowMetadataRemovesGuard(t *testing.T) {
	if New("testnode", nil).guard == nil {
		t.Error("default agent must install the metadata guard")
	}
	if New("testnode", nil, WithAllowMetadata(true)).guard != nil {
		t.Error("WithAllowMetadata(true) must remove the metadata guard")
	}
}

// TestOperatorDenyWinsWithAllowMetadata proves an operator --deny still applies
// and wins even when the built-in metadata guard is opted out: opting out of the
// guard never overrides an explicit deny.
func TestOperatorDenyWinsWithAllowMetadata(t *testing.T) {
	policy, err := ParsePolicy("", "127.0.0.0/8")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	srv := httptest.NewServer(New("testnode", policy, WithAllowMetadata(true), WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
	defer srv.Close()

	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: 80})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (operator --deny still wins); body=%s", resp.StatusCode, body)
	}
}

// TestCheckPlainHostnameUnchangedByGuard is the compat assertion: a normal target
// (loopback listener) dials and reports exactly as before with the default guard
// installed — no denial, CNAME/DNS reporting intact.
func TestCheckPlainHostnameUnchangedByGuard(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := newTestServer(t, "", "") // default metadata guard on
	defer srv.Close()

	req := checkapi.TCPCheckRequest{Host: "localhost", Port: port, Timeout: checkapi.Duration(2 * time.Second)}
	resp, body := postCheck(t, srv.URL, "/api/check/tcp", "", req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (normal target unaffected by guard); body=%s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), `"denied"`) {
		t.Errorf("normal response must not contain a denied key, got %s", body)
	}
	var cr checkResp
	if err := json.Unmarshal(body, &cr); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if cr.TCP == nil || !cr.TCP.OK {
		t.Errorf("expected TCP.OK on a reachable target, got %+v", cr.TCP)
	}
	if cr.DNS == nil || len(cr.DNS.Resolved) == 0 {
		t.Errorf("expected DNS reporting intact for a plain hostname, got %+v", cr.DNS)
	}
}

// --- Task 6: route gating / method matrix -----------------------------------

// TestOldCheckRouteRemoved proves the legacy GET /check path is gone: it is not
// registered on the mux at all, so it 404s exactly like any other unknown path
// (not a 405, which would imply the route still exists under a different verb).
func TestOldCheckRouteRemoved(t *testing.T) {
	srv := newTestServer(t, "", "")
	defer srv.Close()

	resp, _ := get(t, srv.URL, "/check?host=127.0.0.1&port=80")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /check: status = %d, want 404", resp.StatusCode)
	}
	resp, _ = postCheck(t, srv.URL, "/check", "", checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: 80})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST /check: status = %d, want 404", resp.StatusCode)
	}
}

// TestDisabledCheckRouteNotRegistered proves a check kind absent from
// --enabled-checks is never registered on the mux: a tcp-only agent 404s
// /api/check/postgres, and a postgres-only agent 404s /api/check/tcp.
func TestDisabledCheckRouteNotRegistered(t *testing.T) {
	tcpOnly := httptest.NewServer(New("testnode", &Policy{}, WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
	defer tcpOnly.Close()
	resp, body := postCheck(t, tcpOnly.URL, "/api/check/postgres", "", checkapi.PostgresCheckRequest{Host: "db", Port: 5432, Credentials: checkapi.Credentials{Username: "u", Password: "p"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("tcp-only agent, POST /api/check/postgres: status = %d, want 404; body=%s", resp.StatusCode, body)
	}

	pgOnly := httptest.NewServer(New("testnode", &Policy{}, WithEnabledChecks(mustEnabledChecks(t, "postgres"))).Handler())
	defer pgOnly.Close()
	resp, body = postCheck(t, pgOnly.URL, "/api/check/tcp", "", checkapi.TCPCheckRequest{Host: "127.0.0.1", Port: 80})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("postgres-only agent, POST /api/check/tcp: status = %d, want 404; body=%s", resp.StatusCode, body)
	}
}

// TestCheckMethodNotAllowed verifies GET (and other non-POST methods) on a
// registered check endpoint is a 405, with an Allow header naming POST, rather
// than the 400/404 a malformed body or missing route would produce.
func TestCheckMethodNotAllowed(t *testing.T) {
	tcpOnly := httptest.NewServer(New("testnode", &Policy{}, WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
	defer tcpOnly.Close()
	resp, body := get(t, tcpOnly.URL, "/api/check/tcp")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/check/tcp: status = %d, want 405; body=%s", resp.StatusCode, body)
	}
	if resp.Header.Get("Allow") != http.MethodPost {
		t.Errorf("Allow header = %q, want POST", resp.Header.Get("Allow"))
	}

	pgOnly := httptest.NewServer(New("testnode", &Policy{}, WithEnabledChecks(mustEnabledChecks(t, "postgres"))).Handler())
	defer pgOnly.Close()
	resp, body = get(t, pgOnly.URL, "/api/check/postgres")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/check/postgres: status = %d, want 405; body=%s", resp.StatusCode, body)
	}
}

// TestCheckMethodNotAllowedWithToken proves the 405 fires even for an
// authenticated caller (requireToken wraps requireMethod, so a right-token GET
// still hits the method guard rather than the handler).
func TestCheckMethodNotAllowedWithToken(t *testing.T) {
	srv := httptest.NewServer(New("testnode", &Policy{}, WithToken("s3cret"), WithEnabledChecks(mustEnabledChecks(t, "tcp"))).Handler())
	defer srv.Close()
	resp, _ := getAuth(t, srv.URL, "/api/check/tcp", "s3cret")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

// --- Task 6: postgres endpoint ------------------------------------------------

// newPostgresServer builds a postgres-only agent whose Postgres runner is
// wired to a fake Prober, so tests drive every auth outcome without a real
// PostgreSQL server (only real TCP reachability, via a real loopback listener,
// is exercised — see probe.Postgres.Run's doc for why the auth probe only
// runs once the reachability dial itself succeeds).
func newPostgresServer(t *testing.T, prober pgauth.Prober, opts ...Option) *Server {
	t.Helper()
	base := append([]Option{WithEnabledChecks(mustEnabledChecks(t, "postgres"))}, opts...)
	s := New("testnode", &Policy{}, base...)
	if prober != nil {
		s.postgres = probe.Postgres{Prober: prober}
	}
	return s
}

func TestPostgresCheckAuthSuccess(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	calls := 0
	s := newPostgresServer(t, fakeProber{result: checkapi.AuthResult{OK: true, ServerVersion: "PostgreSQL 16.1"}, calls: &calls})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	req := checkapi.PostgresCheckRequest{Host: "127.0.0.1", Port: port, Credentials: checkapi.Credentials{Username: "app", Password: "hunter2"}}
	resp, body := postCheck(t, srv.URL, "/api/check/postgres", "", req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var cr checkResp
	if err := json.Unmarshal(body, &cr); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if cr.Auth == nil || !cr.Auth.OK {
		t.Fatalf("expected Auth.OK, got %+v", cr.Auth)
	}
	if cr.Auth.ServerVersion != "PostgreSQL 16.1" {
		t.Errorf("server_version = %q, want PostgreSQL 16.1", cr.Auth.ServerVersion)
	}
	if calls != 1 {
		t.Errorf("expected the prober to be called exactly once, got %d", calls)
	}
}

// TestPostgresCheckAuthRejected proves a failing auth probe (wrong password,
// tls error, ...) is still a 200: the agent successfully ran the check, it's
// the target that rejected the credentials.
func TestPostgresCheckAuthRejected(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	s := newPostgresServer(t, fakeProber{result: checkapi.AuthResult{Code: checkapi.CodeAuthRejected, Reason: "authentication rejected (28P01)"}})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	req := checkapi.PostgresCheckRequest{Host: "127.0.0.1", Port: port, Credentials: checkapi.Credentials{Username: "app", Password: "wrong"}}
	resp, body := postCheck(t, srv.URL, "/api/check/postgres", "", req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var cr checkResp
	if err := json.Unmarshal(body, &cr); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if cr.Auth == nil || cr.Auth.OK || cr.Auth.Code != checkapi.CodeAuthRejected {
		t.Fatalf("expected Auth.Code=auth_rejected, got %+v", cr.Auth)
	}
}

// TestPostgresCheckUnreachable proves that when the reachability dial itself
// fails (no listener), no auth attempt runs — Auth stays nil — mirroring the
// TCP-failure semantics documented on probe.Postgres.Run.
func TestPostgresCheckUnreachable(t *testing.T) {
	ln, port := openPort(t)
	_ = ln.Close() // free the port so nothing is listening

	calls := 0
	s := newPostgresServer(t, fakeProber{result: checkapi.AuthResult{OK: true}, calls: &calls})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	req := checkapi.PostgresCheckRequest{
		Host: "127.0.0.1", Port: port, Timeout: checkapi.Duration(2 * time.Second),
		Credentials: checkapi.Credentials{Username: "app", Password: "hunter2"},
	}
	resp, body := postCheck(t, srv.URL, "/api/check/postgres", "", req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	var cr checkResp
	if err := json.Unmarshal(body, &cr); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if cr.Auth != nil {
		t.Errorf("expected no auth attempt on an unreachable target, got %+v", cr.Auth)
	}
	if calls != 0 {
		t.Errorf("expected the prober never to be called, got %d calls", calls)
	}
}

// TestPostgresBadInput covers 400s from checkapi.PostgresCheckRequest.Validate:
// missing username/password, bad host/port.
func TestPostgresBadInput(t *testing.T) {
	s := newPostgresServer(t, fakeProber{result: checkapi.AuthResult{OK: true}})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	cases := []checkapi.PostgresCheckRequest{
		{Host: "db", Port: 5432}, // missing credentials entirely
		{Host: "db", Port: 5432, Credentials: checkapi.Credentials{Username: "app"}},              // missing password
		{Host: "db", Port: 5432, Credentials: checkapi.Credentials{Password: "x"}},                // missing username
		{Host: "", Port: 5432, Credentials: checkapi.Credentials{Username: "app", Password: "x"}}, // missing host
		{Host: "db", Port: 0, Credentials: checkapi.Credentials{Username: "app", Password: "x"}},  // bad port
	}
	for _, c := range cases {
		resp, body := postCheck(t, srv.URL, "/api/check/postgres", "", c)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%+v: status = %d, want 400; body=%s", c, resp.StatusCode, body)
		}
	}
}

// TestPostgresMetadataDenied proves the metadata/policy guard is enforced
// before the postgres endpoint ever reaches the prober: a request targeting a
// denied address is refused with 403 and the fake prober is never invoked.
func TestPostgresMetadataDenied(t *testing.T) {
	calls := 0
	s := newPostgresServer(t, fakeProber{result: checkapi.AuthResult{OK: true}, calls: &calls})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	req := checkapi.PostgresCheckRequest{Host: "169.254.169.254", Port: 5432, Credentials: checkapi.Credentials{Username: "app", Password: "hunter2"}}
	resp, body := postCheck(t, srv.URL, "/api/check/postgres", "", req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "denied") {
		t.Errorf("expected denied message, got %s", body)
	}
	if calls != 0 {
		t.Errorf("expected the prober never to be called on a denied target, got %d calls", calls)
	}
}

// --- Task 6: dedicated postgres limiter --------------------------------------

// TestNewAutoBuildsPostgresLimiterWithDefaults pins the built-in bound: a
// postgres-enabled agent auto-builds a limiter whose per-target burst is
// exactly 3 (12/min). Real wall-clock time is fine here (no injected clock)
// because the refill rate (0.2/sec) cannot add a token within the test's
// runtime, so exhausting the burst is deterministic.
func TestNewAutoBuildsPostgresLimiterWithDefaults(t *testing.T) {
	s := New("testnode", &Policy{}, WithEnabledChecks(mustEnabledChecks(t, "postgres")))
	if s.postgresLimiter == nil {
		t.Fatal("expected a postgres limiter to be auto-built when postgres is enabled")
	}
	for i := 0; i < 3; i++ {
		if _, ok := s.allowPostgres("127.0.0.1", 5432); !ok {
			t.Fatalf("call %d: expected the default burst of 3 to allow, denied early", i)
		}
	}
	if _, ok := s.allowPostgres("127.0.0.1", 5432); ok {
		t.Fatal("4th call should exceed the default target burst of 3")
	}
}

// TestNewSkipsPostgresLimiterWhenPostgresDisabled confirms the auto-build is
// scoped to postgres-enabled agents: a tcp-only agent never gets a postgres
// limiter (there is no postgres endpoint for it to gate).
func TestNewSkipsPostgresLimiterWhenPostgresDisabled(t *testing.T) {
	s := New("testnode", &Policy{}, WithEnabledChecks(mustEnabledChecks(t, "tcp")))
	if s.postgresLimiter != nil {
		t.Error("expected no postgres limiter when postgres is not enabled")
	}
}

// TestWithDisablePostgresRateLimit proves the explicit opt-out is honoured:
// even with postgres enabled, no limiter is built (and WithLimiter's general
// limiter, if any, is unaffected — it is a wholly separate field).
func TestWithDisablePostgresRateLimit(t *testing.T) {
	s := New("testnode", &Policy{}, WithEnabledChecks(mustEnabledChecks(t, "postgres")), WithDisablePostgresRateLimit(true))
	if s.postgresLimiter != nil {
		t.Error("expected no postgres limiter when disabled via WithDisablePostgresRateLimit")
	}
}

// TestPostgresLimiterIndependentOfGeneralLimiter is the white-box proof that
// the two limiters never share a bucket: exhausting the general limiter's
// target bucket leaves the postgres-specific bucket for the SAME target
// untouched, and vice versa. This is the "one tripping doesn't consume the
// other" requirement, verified directly at the reservation layer (allow /
// allowPostgres) so the assertion isn't confounded by the handler's
// general-then-postgres check ordering.
func TestPostgresLimiterIndependentOfGeneralLimiter(t *testing.T) {
	fixed := time.Now()
	general, err := ratelimit.New(ratelimit.Config{
		Enabled: true,
		Target:  ratelimit.Scope{Rate: 1, Burst: 1},
	}, ratelimit.WithClock(func() time.Time { return fixed }))
	if err != nil {
		t.Fatalf("ratelimit.New(general): %v", err)
	}
	pg, err := ratelimit.New(ratelimit.Config{
		Enabled: true,
		Target:  ratelimit.Scope{Rate: 1, Burst: 1},
	}, ratelimit.WithClock(func() time.Time { return fixed }))
	if err != nil {
		t.Fatalf("ratelimit.New(postgres): %v", err)
	}
	s := New("testnode", &Policy{}, WithLimiter(general), WithPostgresLimiter(pg), WithEnabledChecks(mustEnabledChecks(t, "postgres")))

	// Exhaust the general limiter's bucket for this target.
	if _, ok := s.allow("127.0.0.1", 5432); !ok {
		t.Fatal("first general reservation should succeed")
	}
	if _, ok := s.allow("127.0.0.1", 5432); ok {
		t.Fatal("second general reservation should be denied (burst exhausted)")
	}

	// The postgres-specific bucket for the SAME target is untouched: it is a
	// distinct *ratelimit.Limiter instance with its own bucket.
	if _, ok := s.allowPostgres("127.0.0.1", 5432); !ok {
		t.Fatal("postgres reservation should still succeed — independent of the exhausted general bucket")
	}
	if _, ok := s.allowPostgres("127.0.0.1", 5432); ok {
		t.Fatal("second postgres reservation should now be denied (its own burst exhausted)")
	}

	// And the reverse: the postgres bucket's own trip above must not have
	// touched the (already-exhausted) general bucket's state.
	if _, ok := s.allow("127.0.0.1", 5432); ok {
		t.Fatal("general limiter should remain exhausted regardless of the postgres bucket's state")
	}
}

// TestPostgresCheckRateLimited exercises the postgres limiter end-to-end over
// HTTP: a WithPostgresLimiter injected with a frozen clock trips on the second
// call (429 + Retry-After), and the fake prober is never reached for the
// throttled request.
func TestPostgresCheckRateLimited(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	fixed := time.Now()
	pg, err := ratelimit.New(ratelimit.Config{
		Enabled: true,
		Target:  ratelimit.Scope{Rate: 1, Burst: 1},
	}, ratelimit.WithClock(func() time.Time { return fixed }))
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	calls := 0
	s := newPostgresServer(t, fakeProber{result: checkapi.AuthResult{OK: true}, calls: &calls}, WithPostgresLimiter(pg))
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	req := checkapi.PostgresCheckRequest{Host: "127.0.0.1", Port: port, Credentials: checkapi.Credentials{Username: "app", Password: "hunter2"}}

	if resp, body := postCheck(t, srv.URL, "/api/check/postgres", "", req); resp.StatusCode != http.StatusOK {
		t.Fatalf("first call: status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	resp, body := postCheck(t, srv.URL, "/api/check/postgres", "", req)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second call: status = %d, want 429; body=%s", resp.StatusCode, body)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("429 response missing Retry-After header")
	}
	if calls != 1 {
		t.Errorf("expected the prober to be called exactly once (not for the throttled call), got %d", calls)
	}
}

// --- Task 6: audit + redaction ------------------------------------------------

// TestPostgresAuditLogsExpectedFieldsNoPassword is both the audit-content test
// and the redaction test: it decodes the single emitted audit log line and
// checks event/target/username/outcome/reason, then asserts a distinctive
// canary password appears in NEITHER the response body NOR the log output —
// anywhere, not just in a "password" field.
func TestPostgresAuditLogsExpectedFieldsNoPassword(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	s := newPostgresServer(t, fakeProber{result: checkapi.AuthResult{Code: checkapi.CodeAuthRejected, Reason: "authentication rejected (28P01): password authentication failed for user \"app\""}}, WithLogger(logger))
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	const canaryPassword = "s3cr3t-canary-pw-8f21"
	req := checkapi.PostgresCheckRequest{Host: "127.0.0.1", Port: port, Credentials: checkapi.Credentials{Username: "app", Password: canaryPassword}}
	resp, body := postCheck(t, srv.URL, "/api/check/postgres", "", req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}

	// Redaction: the canary must never reach the response body or the log.
	if strings.Contains(string(body), canaryPassword) {
		t.Fatalf("response body must never contain the password, got %s", body)
	}
	logged := logBuf.String()
	if strings.Contains(logged, canaryPassword) {
		t.Fatalf("audit log must never contain the password, got %s", logged)
	}
	if strings.Contains(strings.ToLower(logged), `"password"`) {
		t.Fatalf("audit log must never carry a password field at all, got %s", logged)
	}

	// Audit content: one JSON line naming actor(remote)/target/username/outcome/reason.
	var entry map[string]any
	if err := json.NewDecoder(&logBuf).Decode(&entry); err != nil {
		t.Fatalf("decode audit log line: %v; raw=%s", err, logged)
	}
	if entry["event"] != "postgres_check" {
		t.Errorf("event = %v, want postgres_check", entry["event"])
	}
	if entry["username"] != "app" {
		t.Errorf("username = %v, want app", entry["username"])
	}
	wantTarget := fmt.Sprintf("127.0.0.1:%d", port)
	if entry["target"] != wantTarget {
		t.Errorf("target = %v, want %v", entry["target"], wantTarget)
	}
	if entry["outcome"] != checkapi.CodeAuthRejected {
		t.Errorf("outcome = %v, want %v", entry["outcome"], checkapi.CodeAuthRejected)
	}
	if remote, _ := entry["remote"].(string); remote == "" {
		t.Errorf("expected a non-empty remote address, got %v", entry["remote"])
	}
	if reason, _ := entry["reason"].(string); !strings.Contains(reason, "28P01") {
		t.Errorf("expected the safe reason to be recorded, got %q", reason)
	}
}

// TestPostgresAuditCoversDeniedAndThrottled proves the audit trail fires for
// every postgres request that got past body validation, not just the ones
// that reach the prober: a policy-denied request and a rate-limited request
// each produce their own "audit" line with the corresponding outcome.
func TestPostgresAuditCoversDeniedAndThrottled(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	fixed := time.Now()
	pg, err := ratelimit.New(ratelimit.Config{
		Enabled: true,
		Target:  ratelimit.Scope{Rate: 1, Burst: 1},
	}, ratelimit.WithClock(func() time.Time { return fixed }))
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}
	s := newPostgresServer(t, fakeProber{result: checkapi.AuthResult{OK: true}}, WithLogger(logger), WithPostgresLimiter(pg))
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// Denied: a metadata address is refused at connect (the default guard,
	// hermetic — no real network I/O; see TestCheckMetadataDeniedByDefault)
	// before the prober is ever reached.
	denyReq := checkapi.PostgresCheckRequest{Host: "169.254.169.254", Port: 5432, Credentials: checkapi.Credentials{Username: "u1", Password: "p"}}
	if resp, _ := postCheck(t, srv.URL, "/api/check/postgres", "", denyReq); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for the metadata target")
	}

	// Throttled: a second metadata address (still hermetic, still never
	// dials real network) on a fresh target so its limiter bucket starts
	// fresh; the first call spends the burst (and is itself denied by the
	// guard — audited as "denied"), the second is denied by the exhausted
	// postgres limiter before resolveTarget/guard ever run — audited as
	// "throttled".
	throttleReq := checkapi.PostgresCheckRequest{Host: "169.254.170.2", Port: 5432, Credentials: checkapi.Credentials{Username: "u2", Password: "p"}}
	postCheck(t, srv.URL, "/api/check/postgres", "", throttleReq)
	if resp, _ := postCheck(t, srv.URL, "/api/check/postgres", "", throttleReq); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on the second call to the throttled target")
	}

	logged := logBuf.String()
	if !strings.Contains(logged, `"outcome":"denied"`) {
		t.Errorf("expected a denied audit entry, got %s", logged)
	}
	if !strings.Contains(logged, `"outcome":"throttled"`) {
		t.Errorf("expected a throttled audit entry, got %s", logged)
	}
}
