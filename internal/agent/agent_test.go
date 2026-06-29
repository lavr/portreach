package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
}

func newTestServer(t *testing.T, allow, deny string) *httptest.Server {
	t.Helper()
	policy, err := ParsePolicy(allow, deny)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return httptest.NewServer(New("testnode", policy).Handler())
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
	buf := make([]byte, 0)
	var tmp [4096]byte
	for {
		n, err := resp.Body.Read(tmp[:])
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return resp, buf
}

func TestCheckOpenPort(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := newTestServer(t, "", "")
	defer srv.Close()

	resp, body := get(t, srv.URL, fmt.Sprintf("/check?host=127.0.0.1&port=%d", port))
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

	resp, body := get(t, srv.URL, fmt.Sprintf("/check?host=127.0.0.1&port=%d&timeout=2s", port))
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

func TestCheckBadInput(t *testing.T) {
	srv := newTestServer(t, "", "")
	defer srv.Close()

	cases := []string{
		"/check?host=127.0.0.1",            // missing port
		"/check?host=127.0.0.1&port=abc",   // non-numeric port
		"/check?host=127.0.0.1&port=99999", // out of range
		"/check?host=&port=80",             // empty host
		"/check?host=127.0.0.1&port=80&timeout=bogus",
		"/check?host=127.0.0.1&port=80&proto=udp", // unsupported proto
	}
	for _, c := range cases {
		resp, body := get(t, srv.URL, c)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", c, resp.StatusCode, body)
		}
	}
}

func TestCheckDenyCIDR(t *testing.T) {
	srv := newTestServer(t, "", "127.0.0.0/8")
	defer srv.Close()

	resp, body := get(t, srv.URL, "/check?host=127.0.0.1&port=80")
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

	resp, _ := get(t, srv.URL, "/check?host=127.0.0.1&port=80")
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
	s := New("testnode", policy)
	s.resolver = fakeResolver{ips: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, body := get(t, srv.URL, "/check?host=evil.example&port=80")
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
	s := New("testnode", policy)
	s.resolver = fakeResolver{err: fmt.Errorf("no such host")}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, body := get(t, srv.URL, "/check?host=unresolvable.example&port=80")
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
	s := New("testnode", policy)
	s.resolver = fakeResolver{ips: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, body := get(t, srv.URL, fmt.Sprintf("/check?host=db.example&port=%d", port))
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

	get(t, srv.URL, "/check?host=127.0.0.1&port=80") // denied by policy
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

	get(t, srv.URL, fmt.Sprintf("/check?host=127.0.0.1&port=%d&timeout=2s", port))
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

func TestMetrics(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := newTestServer(t, "", "")
	defer srv.Close()

	get(t, srv.URL, fmt.Sprintf("/check?host=127.0.0.1&port=%d", port)) // ok
	get(t, srv.URL, "/check?host=127.0.0.1")                            // bad_request

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
	buf := make([]byte, 0)
	var tmp [4096]byte
	for {
		n, err := resp.Body.Read(tmp[:])
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return resp, buf
}

// TestAgentTokenGatesCheck verifies that, when a token is configured, /check
// rejects missing/wrong tokens with 401 and accepts the right one.
func TestAgentTokenGatesCheck(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := httptest.NewServer(New("testnode", &Policy{}, WithToken("s3cret")).Handler())
	defer srv.Close()

	check := fmt.Sprintf("/check?host=127.0.0.1&port=%d", port)

	// Missing token → 401.
	if resp, body := getAuth(t, srv.URL, check, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401; body=%s", resp.StatusCode, body)
	}
	// Wrong token → 401.
	if resp, body := getAuth(t, srv.URL, check, "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401; body=%s", resp.StatusCode, body)
	}
	// Right token → 200.
	resp, body := getAuth(t, srv.URL, check, "s3cret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("right token: status = %d, want 200; body=%s", resp.StatusCode, body)
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

// TestAgentMetricsPublic verifies --metrics-public opens /metrics only; /check
// stays gated behind the token.
func TestAgentMetricsPublic(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := httptest.NewServer(New("testnode", &Policy{}, WithToken("s3cret"), WithMetricsPublic(true)).Handler())
	defer srv.Close()

	// /metrics open without a token.
	if resp, _ := getAuth(t, srv.URL, "/metrics", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics public: status = %d, want 200", resp.StatusCode)
	}
	// /check still requires the token.
	check := fmt.Sprintf("/check?host=127.0.0.1&port=%d", port)
	if resp, _ := getAuth(t, srv.URL, check, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/check still gated: status = %d, want 401", resp.StatusCode)
	}
}

// TestAgentNoTokenOpen verifies that, with no token configured, /check and
// /metrics stay open (backward compatible).
func TestAgentNoTokenOpen(t *testing.T) {
	ln, port := openPort(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	srv := httptest.NewServer(New("testnode", &Policy{}).Handler())
	defer srv.Close()

	if resp, _ := getAuth(t, srv.URL, fmt.Sprintf("/check?host=127.0.0.1&port=%d", port), ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("/check open: status = %d, want 200", resp.StatusCode)
	}
	if resp, _ := getAuth(t, srv.URL, "/metrics", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics open: status = %d, want 200", resp.StatusCode)
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
