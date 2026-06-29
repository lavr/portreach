package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lavr/portreach/internal/discovery"
	"github.com/lavr/portreach/internal/probe"
)

// fakeAgent builds an httptest server that answers /check like a real agent,
// reporting the given node and TCP outcome.
func fakeAgent(t *testing.T, node string, tcpOK bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := probe.Result{
			Host:  r.URL.Query().Get("host"),
			Proto: "tcp",
			TCP:   &probe.DialResult{OK: tcpOK},
		}
		if !tcpOK {
			res.TCP.Error = "connection refused"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Node string `json:"node"`
			probe.Result
		}{Node: node, Result: res})
	}))
}

// addr strips the http:// scheme so it can be used as a discovery.Agent.Addr.
func addr(s *httptest.Server) string {
	return strings.TrimPrefix(s.URL, "http://")
}

// staticList is a tiny Discoverer for tests.
type staticList []discovery.Agent

func (s staticList) Agents(ctx context.Context) ([]discovery.Agent, error) {
	return append([]discovery.Agent(nil), s...), nil
}

func newClient() *http.Client { return &http.Client{Timeout: 2 * time.Second} }

func TestCheckAllMixed(t *testing.T) {
	okAgent := fakeAgent(t, "node-ok", true)
	defer okAgent.Close()
	failAgent := fakeAgent(t, "node-fail", false)
	defer failAgent.Close()

	agents := []discovery.Agent{{Addr: addr(okAgent)}, {Addr: addr(failAgent)}}
	results := CheckAll(context.Background(), newClient(), agents, Target{Host: "example", Port: 80}, "")

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	sum := Summarize(results)
	if sum.OK != 1 || sum.Total != 2 {
		t.Errorf("summary = %+v, want ok=1 total=2", sum)
	}

	byNode := map[string]AgentResult{}
	for _, r := range results {
		byNode[r.Node] = r
	}
	if r := byNode["node-ok"]; r.Error != "" || r.TCP == nil || !r.TCP.OK {
		t.Errorf("node-ok = %+v, want TCP.OK and no error", r)
	}
	if r := byNode["node-fail"]; r.Error != "" || r.TCP == nil || r.TCP.OK {
		t.Errorf("node-fail = %+v, want TCP.OK=false and no error", r)
	}
}

func TestCheckAllPartialFailure(t *testing.T) {
	okAgent := fakeAgent(t, "node-ok", true)
	defer okAgent.Close()

	errAgent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer errAgent.Close()

	// An unreachable agent: a closed server address.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadAddr := addr(dead)
	dead.Close()

	agents := []discovery.Agent{
		{Addr: addr(okAgent)},
		{Addr: addr(errAgent)},
		{Addr: deadAddr},
	}
	results := CheckAll(context.Background(), newClient(), agents, Target{Host: "example", Port: 80}, "")

	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	sum := Summarize(results)
	if sum.OK != 1 || sum.Total != 3 {
		t.Errorf("summary = %+v, want ok=1 total=3", sum)
	}

	var errCount int
	for _, r := range results {
		if r.Error != "" {
			errCount++
		}
	}
	if errCount != 2 {
		t.Errorf("got %d error results, want 2: %+v", errCount, results)
	}
}

func TestCheckAllTimeout(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slow.Close()

	client := &http.Client{Timeout: 100 * time.Millisecond}
	agents := []discovery.Agent{{Addr: addr(slow)}}
	results := CheckAll(context.Background(), client, agents, Target{Host: "example", Port: 80}, "")

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Error == "" {
		t.Errorf("expected timeout error, got %+v", results[0])
	}
	if e := results[0].Error; !strings.Contains(e, "Timeout") && !strings.Contains(e, "deadline") {
		t.Errorf("expected a timeout/deadline error, got %q", e)
	}
	if Summarize(results).OK != 0 {
		t.Errorf("timed-out agent should not count as ok")
	}
}

func TestCheckAllEmpty(t *testing.T) {
	results := CheckAll(context.Background(), newClient(), nil, Target{Host: "x", Port: 80}, "")
	if len(results) != 0 {
		t.Fatalf("got %d results, want 0", len(results))
	}
	if s := Summarize(results); s.OK != 0 || s.Total != 0 {
		t.Errorf("summary = %+v, want zero", s)
	}
}

func TestCheckAllDecodeError(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "not-json")
	}))
	defer bad.Close()

	results := CheckAll(context.Background(), newClient(), []discovery.Agent{{Addr: addr(bad)}}, Target{Host: "x", Port: 80}, "")
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if !strings.Contains(results[0].Error, "decode response") {
		t.Errorf("expected decode error, got %+v", results[0])
	}
}

// capturingAgent records the Authorization header of the last /check request
// and answers with a successful probe result.
func capturingAgent(t *testing.T, got *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Node string `json:"node"`
			probe.Result
		}{Node: "n", Result: probe.Result{Proto: "tcp", TCP: &probe.DialResult{OK: true}}})
	}))
}

func TestCheckAllAttachesAgentToken(t *testing.T) {
	var got string
	srv := capturingAgent(t, &got)
	defer srv.Close()

	agents := []discovery.Agent{{Addr: addr(srv)}}
	CheckAll(context.Background(), newClient(), agents, Target{Host: "x", Port: 80}, "s3cret")
	if got != "Bearer s3cret" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer s3cret")
	}
}

func TestCheckAllNoTokenNoHeader(t *testing.T) {
	var got string
	srv := capturingAgent(t, &got)
	defer srv.Close()

	agents := []discovery.Agent{{Addr: addr(srv)}}
	CheckAll(context.Background(), newClient(), agents, Target{Host: "x", Port: 80}, "")
	if got != "" {
		t.Errorf("Authorization = %q, want empty (no header)", got)
	}
}

func TestClampTimeout(t *testing.T) {
	budget := 8 * time.Second
	cases := []struct {
		user string
		want string
	}{
		{"", (5 * time.Second).String()},           // default, under budget → unchanged
		{"2s", (2 * time.Second).String()},         // user value under budget → unchanged
		{"30s", (7 * time.Second).String()},        // over budget → clamped to budget-1s
		{"10ms", (10 * time.Millisecond).String()}, // small positive user value → unchanged (no floor)
		{"bogus", (5 * time.Second).String()},      // invalid → default, under budget
		{"0s", (5 * time.Second).String()},         // non-positive → default (parsed>0 guard)
		{"-5s", (5 * time.Second).String()},        // negative → default (parsed>0 guard)
	}
	for _, c := range cases {
		if got := clampTimeout(c.user, budget); got != c.want {
			t.Errorf("clampTimeout(%q, %v) = %q, want %q", c.user, budget, got, c.want)
		}
	}
	// Tiny budget: must still produce a positive, sub-budget timeout.
	if got := clampTimeout("30s", time.Second); got != (500 * time.Millisecond).String() {
		t.Errorf("clampTimeout with 1s budget = %q, want 500ms", got)
	}
	// Safety net for an exhausted/near-zero budget: it must never serialize as a
	// non-positive value, which probe.Validate would silently upgrade to its 5s
	// default and defeat the clamp; floor to minClampTimeout. Only an already-
	// exhausted budget (<= 0) reaches the floor — any positive remainder yields a
	// positive, sub-budget timeout, so the handlers fan out instead of bailing.
	for _, budget := range []time.Duration{0, -3 * time.Second, time.Nanosecond} {
		got := clampTimeout("30s", budget)
		d, err := time.ParseDuration(got)
		if err != nil {
			t.Fatalf("clampTimeout(%q, %v) = %q: not a duration: %v", "30s", budget, got, err)
		}
		if d <= 0 {
			t.Errorf("clampTimeout with %v budget = %q (%v), want positive", budget, got, d)
		}
		if d != minClampTimeout {
			t.Errorf("clampTimeout with %v budget = %q, want %v floor", budget, got, minClampTimeout)
		}
	}
}

func TestAPICheck(t *testing.T) {
	okAgent := fakeAgent(t, "node-ok", true)
	defer okAgent.Close()
	failAgent := fakeAgent(t, "node-fail", false)
	defer failAgent.Close()

	disc := staticList{{Addr: addr(okAgent)}, {Addr: addr(failAgent)}}
	srv := httptest.NewServer(New(disc, 2*time.Second).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/check?host=example&port=80")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var out Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Target.Host != "example" || out.Target.Port != 80 || out.Target.Proto != "tcp" {
		t.Errorf("target = %+v", out.Target)
	}
	if len(out.Agents) != 2 {
		t.Fatalf("got %d agents, want 2", len(out.Agents))
	}
	if out.Summary.OK != 1 || out.Summary.Total != 2 {
		t.Errorf("summary = %+v, want ok=1 total=2", out.Summary)
	}
}

// slowList is a Discoverer that burns part of the budget before returning,
// leaving a positive remainder for the probe fan-out.
type slowList struct {
	agents discovery.Agent
	delay  time.Duration
}

func (s slowList) Agents(ctx context.Context) ([]discovery.Agent, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
	}
	return []discovery.Agent{s.agents}, nil
}

// When discovery leaves only a small (sub-second) budget, the handler must still
// fan out: clampTimeout floors the per-agent timeout to a positive value strictly
// under the remaining deadline, so probing yields real per-node results instead
// of auto-failing. (A regression once bailed here below a 200ms budget.)
func TestAPICheckSmallBudgetStillProbes(t *testing.T) {
	okAgent := fakeAgent(t, "node-ok", true)
	defer okAgent.Close()

	// 500ms budget, discovery eats ~200ms → ~300ms remains for the fan-out.
	disc := slowList{agents: discovery.Agent{Addr: addr(okAgent)}, delay: 200 * time.Millisecond}
	srv := httptest.NewServer(New(disc, 500*time.Millisecond).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/check?host=example&port=80")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Agents) != 1 {
		t.Fatalf("got %d agents, want 1", len(out.Agents))
	}
	if out.Summary.OK != 1 || out.Summary.Total != 1 {
		t.Errorf("summary = %+v, want ok=1 total=1", out.Summary)
	}
}

func TestAPICheckBadInput(t *testing.T) {
	disc := staticList{{Addr: "127.0.0.1:1"}}
	srv := httptest.NewServer(New(disc, time.Second).Handler())
	defer srv.Close()

	cases := []string{
		"/api/check?host=example",          // missing port
		"/api/check?host=example&port=abc", // non-numeric port
		"/api/check?host=&port=80",         // empty host
		"/api/check?host=example&port=99999",
		"/api/check?host=example&port=80&proto=udp",
		"/api/check?host=example&port=80&timeout=bogus",
	}
	for _, c := range cases {
		resp, err := http.Get(srv.URL + c)
		if err != nil {
			t.Fatalf("GET %s: %v", c, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", c, resp.StatusCode)
		}
	}
}

func TestAPICheckDiscoveryError(t *testing.T) {
	srv := httptest.NewServer(New(failingDisc{}, time.Second).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/check?host=example&port=80")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

type failingDisc struct{}

func (failingDisc) Agents(ctx context.Context) ([]discovery.Agent, error) {
	return nil, fmt.Errorf("no agents")
}

// timeoutDisc models the DNS discoverer's behavior: a slow lookup surfaces the
// shared-budget deadline as an error (not a nil result) once ctx expires.
type timeoutDisc struct{}

func (timeoutDisc) Agents(ctx context.Context) ([]discovery.Agent, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A discovery error caused by the shared budget expiring must read as a clean 504
// timeout, not a generic 502 — the DNS discoverer returns LookupHost's deadline
// error directly rather than a nil result.
func TestAPICheckDiscoveryTimeout(t *testing.T) {
	srv := httptest.NewServer(New(timeoutDisc{}, 50*time.Millisecond).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/check?host=example&port=80")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(out["error"], "deadline exceeded during discovery") {
		t.Errorf("error = %q, want discovery deadline message", out["error"])
	}
}

func TestHealthz(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
