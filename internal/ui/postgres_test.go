package ui

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lavr/portreach/internal/checkapi"
	"github.com/lavr/portreach/internal/discovery"
	"github.com/lavr/portreach/internal/probe"
	"github.com/lavr/portreach/internal/ratelimit"
)

// canaryPassword is a distinctive password used across the redaction tests
// below so a leak (into a log line or a response body) is unambiguous — it
// can never appear there by coincidence.
const canaryPassword = "CANARY-p4ssw0rd-zzz9"

// capturedRequest records what a fake agent actually received, so tests can
// assert the POST body/endpoint/bearer reached the agent correctly.
type capturedRequest struct {
	Path   string
	Method string
	Auth   string
	TCP    checkapi.TCPCheckRequest
	PG     checkapi.PostgresCheckRequest
}

// capturingPostgresAgent builds an httptest server that decodes a
// checkapi.PostgresCheckRequest POST body, records the request, and answers
// with a synthetic result: tcpOK controls the reachability outcome
// Summarize keys on, authOK controls the (independent) auth outcome.
func capturingPostgresAgent(t *testing.T, node string, tcpOK, authOK bool, capture *capturedRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capture != nil {
			capture.Path = r.URL.Path
			capture.Method = r.Method
			capture.Auth = r.Header.Get("Authorization")
			_ = json.NewDecoder(r.Body).Decode(&capture.PG)
		}
		res := probe.Result{Host: "x", Proto: "postgres", TCP: &probe.DialResult{OK: tcpOK}}
		if !tcpOK {
			res.TCP.Error = "connection refused"
		} else if authOK {
			res.Auth = &checkapi.AuthResult{OK: true, MS: 1.5}
		} else {
			res.Auth = &checkapi.AuthResult{OK: false, Code: checkapi.CodeAuthRejected, Reason: "password authentication failed"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Node string `json:"node"`
			probe.Result
		}{Node: node, Result: res})
	}))
}

// capturingTCPAgent mirrors capturingPostgresAgent for the TCP endpoint.
func capturingTCPAgent(t *testing.T, node string, tcpOK bool, capture *capturedRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if capture != nil {
			capture.Path = r.URL.Path
			capture.Method = r.Method
			capture.Auth = r.Header.Get("Authorization")
			_ = json.NewDecoder(r.Body).Decode(&capture.TCP)
		}
		res := probe.Result{Host: "x", Proto: "tcp", TCP: &probe.DialResult{OK: tcpOK}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Node string `json:"node"`
			probe.Result
		}{Node: node, Result: res})
	}))
}

// TestTCPRequestReachesAgentEndpointAndBearer proves checkOne POSTs the TCP
// body to /api/check/tcp with the configured bearer token attached.
func TestTCPRequestReachesAgentEndpointAndBearer(t *testing.T) {
	var captured capturedRequest
	agent := capturingTCPAgent(t, "n1", true, &captured)
	defer agent.Close()

	disc := staticList{{Addr: addr(agent)}}
	srv := httptest.NewServer(New(disc, time.Second, WithAgentToken("tok123"), WithEnabledChecks(mustEnabled(t, "tcp"))).Handler())
	defer srv.Close()

	resp := postTCPCheck(t, srv.URL, "example.internal", 5432)
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if captured.Path != "/api/check/tcp" {
		t.Errorf("agent saw path = %q, want /api/check/tcp", captured.Path)
	}
	if captured.Method != http.MethodPost {
		t.Errorf("agent saw method = %q, want POST", captured.Method)
	}
	if captured.Auth != "Bearer tok123" {
		t.Errorf("agent saw Authorization = %q, want Bearer tok123", captured.Auth)
	}
	if captured.TCP.Host != "example.internal" || captured.TCP.Port != 5432 {
		t.Errorf("agent saw body = %+v, want host=example.internal port=5432", captured.TCP)
	}
}

// TestPostgresRequestReachesAgentEndpointAndBearer proves checkOne POSTs the
// Postgres body (with credentials/TLS) to /api/check/postgres with the
// configured bearer token attached — the matching-endpoint half of the
// fan-out change.
func TestPostgresRequestReachesAgentEndpointAndBearer(t *testing.T) {
	var captured capturedRequest
	agent := capturingPostgresAgent(t, "n1", true, true, &captured)
	defer agent.Close()

	disc := staticList{{Addr: addr(agent)}}
	srv := httptest.NewServer(New(disc, time.Second, WithAgentToken("tok123"), WithEnabledChecks(mustEnabled(t, "postgres"))).Handler())
	defer srv.Close()

	body := checkapi.PostgresCheckRequest{
		Host:        "db.internal",
		Port:        5432,
		Credentials: checkapi.Credentials{Username: "alice", Password: canaryPassword, Database: "app"},
	}
	resp := postJSON(t, srv.URL, "/api/check/postgres", body)
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if captured.Path != "/api/check/postgres" {
		t.Errorf("agent saw path = %q, want /api/check/postgres", captured.Path)
	}
	if captured.Method != http.MethodPost {
		t.Errorf("agent saw method = %q, want POST", captured.Method)
	}
	if captured.Auth != "Bearer tok123" {
		t.Errorf("agent saw Authorization = %q, want Bearer tok123", captured.Auth)
	}
	if captured.PG.Host != "db.internal" || captured.PG.Port != 5432 {
		t.Errorf("agent saw target = %+v, want db.internal:5432", captured.PG)
	}
	if captured.PG.Credentials.Username != "alice" || captured.PG.Credentials.Password != canaryPassword || captured.PG.Credentials.Database != "app" {
		t.Errorf("agent saw credentials = %+v, want alice/%s/app", captured.PG.Credentials, canaryPassword)
	}
}

// TestPostgresFanOutAggregation proves a full UI request fans out to multiple
// agents on the postgres route, with the target/discovered/queried/dropped/
// summary envelope computed exactly as the TCP path's (unchanged) semantics.
func TestPostgresFanOutAggregation(t *testing.T) {
	okA := fakeAgent(t, "node-a", true)
	defer okA.Close()
	okB := fakeAgent(t, "node-b", true)
	defer okB.Close()
	failC := fakeAgent(t, "node-c", false)
	defer failC.Close()

	disc := staticList{{Addr: addr(okA)}, {Addr: addr(okB)}, {Addr: addr(failC)}}
	srv := httptest.NewServer(New(disc, 2*time.Second, WithEnabledChecks(mustEnabled(t, "postgres"))).Handler())
	defer srv.Close()

	body := checkapi.PostgresCheckRequest{
		Host:        "db.internal",
		Port:        5432,
		Credentials: checkapi.Credentials{Username: "svc", Password: canaryPassword},
	}
	resp := postJSON(t, srv.URL, "/api/check/postgres", body)
	respBody, err := readAndCloseBody(resp)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, respBody)
	}
	if strings.Contains(string(respBody), canaryPassword) {
		t.Fatalf("response body leaked the password: %s", respBody)
	}

	var out Response
	if err := json.Unmarshal(respBody, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Target.Host != "db.internal" || out.Target.Port != 5432 || out.Target.Proto != "postgres" {
		t.Errorf("target = %+v", out.Target)
	}
	if out.Discovered != 3 || out.Queried != 3 || out.Dropped != 0 {
		t.Errorf("counts = discovered %d queried %d dropped %d, want 3/3/0", out.Discovered, out.Queried, out.Dropped)
	}
	if out.Summary.OK != 2 || out.Summary.Total != 3 {
		t.Errorf("summary = %+v, want ok=2 total=3", out.Summary)
	}
}

// TestPostgresFanoutRespectsCap proves the bounded fan-out (MaxAgentsPerCheck)
// still applies exactly to the postgres route.
func TestPostgresFanoutRespectsCap(t *testing.T) {
	var servers []*httptest.Server
	var agents []discovery.Agent
	for i := 0; i < 3; i++ {
		s := fakeAgent(t, "n", true)
		servers = append(servers, s)
		agents = append(agents, discovery.Agent{Addr: addr(s)})
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	srv := httptest.NewServer(New(staticList(agents), time.Second,
		WithFanout(FanoutConfig{MaxAgentsPerCheck: 2}), WithEnabledChecks(mustEnabled(t, "postgres"))).Handler())
	defer srv.Close()

	body := checkapi.PostgresCheckRequest{Host: "db", Port: 5432, Credentials: checkapi.Credentials{Username: "u", Password: "p"}}
	resp := postJSON(t, srv.URL, "/api/check/postgres", body)
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	var got Response
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Discovered != 3 || got.Queried != 2 || got.Dropped != 1 {
		t.Errorf("counts = discovered %d queried %d dropped %d, want 3/2/1", got.Discovered, got.Queried, got.Dropped)
	}
}

// TestAPICheckPostgresBadInput mirrors TestAPICheckBadInput for the postgres
// route: missing/blank credentials and malformed bodies all 400.
func TestAPICheckPostgresBadInput(t *testing.T) {
	disc := staticList{}
	srv := httptest.NewServer(New(disc, time.Second, WithEnabledChecks(mustEnabled(t, "postgres"))).Handler())
	defer srv.Close()

	cases := []struct {
		name string
		body string
	}{
		{"missing credentials", `{"host":"db","port":5432}`},
		{"empty username", `{"host":"db","port":5432,"credentials":{"username":"","password":"p"}}`},
		{"empty password", `{"host":"db","port":5432,"credentials":{"username":"u","password":""}}`},
		{"missing host", `{"port":5432,"credentials":{"username":"u","password":"p"}}`},
		{"malformed json", `{not-json`},
	}
	for _, c := range cases {
		resp, err := http.Post(srv.URL+"/api/check/postgres", "application/json", strings.NewReader(c.body))
		if err != nil {
			t.Fatalf("%s: POST: %v", c.name, err)
		}
		body, _ := readAndCloseBody(resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %s)", c.name, resp.StatusCode, body)
		}
	}
}

// TestPostgresAuditRedactsPassword proves the UI's postgres audit trail and
// its HTTP response both carry the actor/target/username/outcome fields the
// brief requires, while the password never appears in either — the core
// redaction guarantee.
func TestPostgresAuditRedactsPassword(t *testing.T) {
	agent := fakeAgent(t, "node-ok", true)
	defer agent.Close()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	disc := staticList{{Addr: addr(agent)}}
	srv := httptest.NewServer(New(disc, time.Second, WithLogger(logger), WithEnabledChecks(mustEnabled(t, "postgres"))).Handler())
	defer srv.Close()

	body := checkapi.PostgresCheckRequest{
		Host:        "db.internal",
		Port:        5432,
		Credentials: checkapi.Credentials{Username: "alice", Password: canaryPassword},
	}
	resp := postJSON(t, srv.URL, "/api/check/postgres", body)
	respBody, err := readAndCloseBody(resp)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, respBody)
	}

	// Redaction: the password appears in NEITHER the response body NOR the
	// audit log, despite both carrying rich detail about the request.
	if strings.Contains(string(respBody), canaryPassword) {
		t.Fatalf("response body leaked the password: %s", respBody)
	}
	if strings.Contains(logBuf.String(), canaryPassword) {
		t.Fatalf("audit log leaked the password: %s", logBuf.String())
	}

	// The audit event itself must still be rich enough to be useful: actor
	// (remote), target, username, outcome, reason all present.
	var ev map[string]any
	found := false
	for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var candidate map[string]any
		if err := json.Unmarshal([]byte(line), &candidate); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		if candidate["event"] == "postgres_check" {
			ev = candidate
			found = true
		}
	}
	if !found {
		t.Fatalf("no postgres_check audit event found in log:\n%s", logBuf.String())
	}
	if ev["username"] != "alice" {
		t.Errorf("audit username = %v, want alice", ev["username"])
	}
	if ev["target"] != "db.internal:5432" {
		t.Errorf("audit target = %v, want db.internal:5432", ev["target"])
	}
	if ev["outcome"] != "completed" {
		t.Errorf("audit outcome = %v, want completed", ev["outcome"])
	}
	if ev["remote"] == nil || ev["remote"] == "" {
		t.Errorf("audit remote missing")
	}
}

// TestPostgresAuditOnThrottle proves the postgres audit trail also covers a
// request the postgres-specific limiter turned away (never reached the
// agent), still without leaking the password.
func TestPostgresAuditOnThrottle(t *testing.T) {
	pgLimiter := newLimiter(t, ratelimit.Config{Target: ratelimit.Scope{Rate: 1, Burst: 1}})
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))

	disc := staticList{}
	srv := httptest.NewServer(New(disc, time.Second,
		WithLogger(logger), WithPostgresLimiter(pgLimiter), WithEnabledChecks(mustEnabled(t, "postgres"))).Handler())
	defer srv.Close()

	body := checkapi.PostgresCheckRequest{Host: "db", Port: 5432, Credentials: checkapi.Credentials{Username: "u", Password: canaryPassword}}

	// First request consumes the single postgres-limiter token.
	resp := postJSON(t, srv.URL, "/api/check/postgres", body)
	_, _ = readAndCloseBody(resp)

	// Second: postgres limiter denies → 429, still audited, still redacted.
	resp = postJSON(t, srv.URL, "/api/check/postgres", body)
	respBody, err := readAndCloseBody(resp)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body %s)", resp.StatusCode, respBody)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("missing Retry-After header")
	}
	if strings.Contains(string(respBody), canaryPassword) || strings.Contains(logBuf.String(), canaryPassword) {
		t.Fatalf("password leaked on throttle path (body=%s log=%s)", respBody, logBuf.String())
	}
	if !strings.Contains(logBuf.String(), `"outcome":"throttled"`) {
		t.Errorf("expected a throttled postgres_check audit event, got:\n%s", logBuf.String())
	}
}

// TestPostgresLimiterIndependentOfGeneral proves the postgres-specific
// limiter and the general limiter spend independent buckets: exhausting the
// postgres limiter 429s the postgres route without affecting the general
// limiter's budget for the tcp route (same identity), and vice versa.
func TestPostgresLimiterIndependentOfGeneral(t *testing.T) {
	// General limiter: generous headroom (won't trip during this test).
	general := newLimiter(t, ratelimit.Config{User: ratelimit.Scope{Rate: 1, Burst: 5}})
	// Postgres limiter: a single token, so the second postgres call trips it.
	pgLimiter := newLimiter(t, ratelimit.Config{Target: ratelimit.Scope{Rate: 1, Burst: 1}})

	agent := fakeAgent(t, "n", true)
	defer agent.Close()
	disc := staticList{{Addr: addr(agent)}}

	srv := httptest.NewServer(New(disc, time.Second,
		WithLimiter(general), WithPostgresLimiter(pgLimiter),
		WithEnabledChecks(mustEnabled(t, "tcp,postgres"))).Handler())
	defer srv.Close()

	pgBody := checkapi.PostgresCheckRequest{Host: "db", Port: 5432, Credentials: checkapi.Credentials{Username: "u", Password: "p"}}

	// First postgres request: both limiters have room → 200.
	resp := postJSON(t, srv.URL, "/api/check/postgres", pgBody)
	_, _ = readAndCloseBody(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first postgres = %d, want 200", resp.StatusCode)
	}

	// Second postgres request: the postgres limiter's single token is spent →
	// 429, even though the general limiter (burst 5) still has plenty left.
	resp = postJSON(t, srv.URL, "/api/check/postgres", pgBody)
	_, _ = readAndCloseBody(resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second postgres = %d, want 429 (postgres limiter should have tripped)", resp.StatusCode)
	}

	// A TCP request from the same identity right after: the postgres limiter
	// never gates /api/check/tcp, and the general limiter still has budget
	// left (2 of 5 spent above) → 200. Proves the postgres trip didn't spend
	// the general bucket, and the general bucket alone still admits requests.
	tcpResp := postTCPCheck(t, srv.URL, "example", 80)
	defer tcpResp.Body.Close() //nolint:errcheck // best-effort close
	if tcpResp.StatusCode != http.StatusOK {
		t.Fatalf("tcp after postgres throttle = %d, want 200 (limiters must be independent)", tcpResp.StatusCode)
	}
}

// TestPostgresRateLimitAutoOnByDefault proves New auto-builds the
// postgres-specific limiter with its built-in burst the moment postgres is
// enabled, with no explicit WithPostgresLimiter call — exhausting the burst
// (3) throttles the 4th rapid request from the same client.
func TestPostgresRateLimitAutoOnByDefault(t *testing.T) {
	agent := fakeAgent(t, "n", true)
	defer agent.Close()
	disc := staticList{{Addr: addr(agent)}}

	srv := httptest.NewServer(New(disc, time.Second, WithEnabledChecks(mustEnabled(t, "postgres"))).Handler())
	defer srv.Close()

	body := checkapi.PostgresCheckRequest{Host: "db", Port: 5432, Credentials: checkapi.Credentials{Username: "u", Password: "p"}}

	var codes []int
	for i := 0; i < uiPostgresLimiterTargetBurst+1; i++ {
		resp := postJSON(t, srv.URL, "/api/check/postgres", body)
		codes = append(codes, resp.StatusCode)
		_, _ = readAndCloseBody(resp)
	}
	last := codes[len(codes)-1]
	if last != http.StatusTooManyRequests {
		t.Fatalf("codes = %v, want the request past the built-in burst (%d) to 429", codes, uiPostgresLimiterTargetBurst)
	}
}

// TestPostgresRateLimitDisableOptOut proves WithDisablePostgresRateLimit(true)
// leaves the postgres route unlimited even with postgres enabled — the only
// supported way to opt out of the auto-built limiter.
func TestPostgresRateLimitDisableOptOut(t *testing.T) {
	agent := fakeAgent(t, "n", true)
	defer agent.Close()
	disc := staticList{{Addr: addr(agent)}}

	srv := httptest.NewServer(New(disc, time.Second,
		WithDisablePostgresRateLimit(true), WithEnabledChecks(mustEnabled(t, "postgres"))).Handler())
	defer srv.Close()

	body := checkapi.PostgresCheckRequest{Host: "db", Port: 5432, Credentials: checkapi.Credentials{Username: "u", Password: "p"}}
	for i := 0; i < uiPostgresLimiterTargetBurst+3; i++ {
		resp := postJSON(t, srv.URL, "/api/check/postgres", body)
		_, _ = readAndCloseBody(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d = %d, want 200 (rate limit disabled)", i, resp.StatusCode)
		}
	}
}

// TestPostgresDiscoveryErrorAudited proves a discovery failure on the
// postgres route is audited (outcome "error", a safe reason) before the 502
// is written — mirroring the TCP path's discovery-error handling.
func TestPostgresDiscoveryErrorAudited(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	srv := httptest.NewServer(New(failingDisc{}, time.Second, WithLogger(logger), WithEnabledChecks(mustEnabled(t, "postgres"))).Handler())
	defer srv.Close()

	body := checkapi.PostgresCheckRequest{Host: "db", Port: 5432, Credentials: checkapi.Credentials{Username: "u", Password: canaryPassword}}
	resp := postJSON(t, srv.URL, "/api/check/postgres", body)
	respBody, err := readAndCloseBody(resp)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body %s)", resp.StatusCode, respBody)
	}
	if strings.Contains(string(respBody), canaryPassword) || strings.Contains(logBuf.String(), canaryPassword) {
		t.Fatalf("password leaked on discovery-error path (body=%s log=%s)", respBody, logBuf.String())
	}
	if !strings.Contains(logBuf.String(), `"outcome":"error"`) {
		t.Errorf("expected an error-outcome postgres_check audit event, got:\n%s", logBuf.String())
	}
}

// TestPostgresDiscoveryTimeoutAudited proves the shared-budget-expired-during-
// discovery case reports a clean 504 (not the generic 502) and is audited,
// mirroring the TCP path's discovery-timeout handling.
func TestPostgresDiscoveryTimeoutAudited(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	srv := httptest.NewServer(New(timeoutDisc{}, 50*time.Millisecond, WithLogger(logger), WithEnabledChecks(mustEnabled(t, "postgres"))).Handler())
	defer srv.Close()

	body := checkapi.PostgresCheckRequest{Host: "db", Port: 5432, Credentials: checkapi.Credentials{Username: "u", Password: canaryPassword}}
	resp := postJSON(t, srv.URL, "/api/check/postgres", body)
	respBody, err := readAndCloseBody(resp)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504 (body %s)", resp.StatusCode, respBody)
	}
	if !strings.Contains(string(respBody), "deadline exceeded during discovery") {
		t.Errorf("body = %s, want discovery deadline message", respBody)
	}
	if strings.Contains(string(respBody), canaryPassword) || strings.Contains(logBuf.String(), canaryPassword) {
		t.Fatalf("password leaked on discovery-timeout path (body=%s log=%s)", respBody, logBuf.String())
	}
}

// TestPostgresRequestWithExplicitTimeout proves a caller-supplied timeout
// survives the durationString round-trip (checkapi.Duration -> Target.Timeout
// string) and reaches clampTimeout, rather than only ever exercising the
// zero/default path.
func TestPostgresRequestWithExplicitTimeout(t *testing.T) {
	var captured capturedRequest
	agent := capturingPostgresAgent(t, "n1", true, true, &captured)
	defer agent.Close()

	disc := staticList{{Addr: addr(agent)}}
	srv := httptest.NewServer(New(disc, 5*time.Second, WithEnabledChecks(mustEnabled(t, "postgres"))).Handler())
	defer srv.Close()

	body := checkapi.PostgresCheckRequest{
		Host:        "db.internal",
		Port:        5432,
		Timeout:     checkapi.Duration(2 * time.Second),
		Credentials: checkapi.Credentials{Username: "u", Password: "p"},
	}
	resp := postJSON(t, srv.URL, "/api/check/postgres", body)
	respBody, err := readAndCloseBody(resp)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, respBody)
	}
	if captured.PG.Timeout <= 0 {
		t.Errorf("agent saw timeout = %v, want a positive clamped value", captured.PG.Timeout)
	}
}

// readAndCloseBody reads and closes resp.Body, returning its bytes.
func readAndCloseBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
