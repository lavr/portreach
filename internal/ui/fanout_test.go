package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lavr/portreach/internal/discovery"
)

func TestFanoutConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     FanoutConfig
		wantErr bool
	}{
		{"zero is unlimited", FanoutConfig{}, false},
		{"positive caps", FanoutConfig{MaxAgentsPerCheck: 3, MaxConcurrentFanout: 2}, false},
		{"negative agents rejected", FanoutConfig{MaxAgentsPerCheck: -1}, true},
		{"negative concurrency rejected", FanoutConfig{MaxConcurrentFanout: -1}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.cfg.Validate(); (err != nil) != c.wantErr {
				t.Fatalf("Validate() err = %v, wantErr = %v", err, c.wantErr)
			}
		})
	}
}

func TestSelectAgentsUnlimited(t *testing.T) {
	agents := []discovery.Agent{{Addr: "c"}, {Addr: "a"}, {Addr: "b"}}
	got, dropped := selectAgents(agents, 0)
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
	// Unlimited returns the input untouched (no sort, no copy semantics asserted).
	if len(got) != 3 {
		t.Fatalf("got %d agents, want 3", len(got))
	}
}

func TestSelectAgentsCapsDeterministically(t *testing.T) {
	agents := []discovery.Agent{{Addr: "d"}, {Addr: "b"}, {Addr: "a"}, {Addr: "c"}}
	got, dropped := selectAgents(agents, 2)
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2", dropped)
	}
	if len(got) != 2 || got[0].Addr != "a" || got[1].Addr != "b" {
		t.Errorf("selected = %+v, want the two lowest addrs [a b]", got)
	}
	// The input slice must not be mutated by the deterministic sort.
	if agents[0].Addr != "d" {
		t.Errorf("input was mutated: %+v", agents)
	}
}

func TestSelectAgentsFewerThanCap(t *testing.T) {
	agents := []discovery.Agent{{Addr: "a"}, {Addr: "b"}}
	got, dropped := selectAgents(agents, 5)
	if dropped != 0 || len(got) != 2 {
		t.Errorf("got %d agents, dropped %d; want 2 agents, 0 dropped", len(got), dropped)
	}
}

// countingAgent answers /check OK while tracking how many requests are in flight
// at once, so a bounded pool can be asserted against the configured cap.
func countingAgent(t *testing.T, inFlight, maxSeen *int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt64(inFlight, 1)
		for {
			prev := atomic.LoadInt64(maxSeen)
			if cur <= prev || atomic.CompareAndSwapInt64(maxSeen, prev, cur) {
				break
			}
		}
		// Hold the request briefly so concurrent calls actually overlap.
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt64(inFlight, -1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"node": "n", "tcp": map[string]any{"ok": true}})
	}))
}

func TestCheckAllBoundsConcurrency(t *testing.T) {
	var inFlight, maxSeen int64
	srv := countingAgent(t, &inFlight, &maxSeen)
	defer srv.Close()

	a := addr(srv)
	agents := make([]discovery.Agent, 6)
	for i := range agents {
		agents[i] = discovery.Agent{Addr: a}
	}

	results := CheckAll(context.Background(), newClient(), agents, Target{Host: "x", Port: 80}, "", 2)
	if len(results) != 6 {
		t.Fatalf("got %d results, want 6", len(results))
	}
	if got := atomic.LoadInt64(&maxSeen); got > 2 {
		t.Errorf("max concurrent requests = %d, want <= 2", got)
	}
}

func TestCheckAllUnlimitedConcurrency(t *testing.T) {
	var inFlight, maxSeen int64
	srv := countingAgent(t, &inFlight, &maxSeen)
	defer srv.Close()

	a := addr(srv)
	agents := make([]discovery.Agent, 5)
	for i := range agents {
		agents[i] = discovery.Agent{Addr: a}
	}

	// maxConcurrent = 0 means a goroutine per agent: all five should overlap.
	CheckAll(context.Background(), newClient(), agents, Target{Host: "x", Port: 80}, "", 0)
	if got := atomic.LoadInt64(&maxSeen); got != 5 {
		t.Errorf("max concurrent requests = %d, want 5 (unlimited)", got)
	}
}

// TestAPICheckReportsFanoutCounts proves the cap surfaces explicit
// discovered/queried/dropped counts (and Summary.Total = queried) over /api/check.
func TestAPICheckReportsFanoutCounts(t *testing.T) {
	// Three distinct fake agents so discovery returns three addrs.
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
		WithFanout(FanoutConfig{MaxAgentsPerCheck: 2})).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/check?host=example&port=80")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	var got Response
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Discovered != 3 || got.Queried != 2 || got.Dropped != 1 {
		t.Errorf("counts = discovered %d queried %d dropped %d, want 3/2/1", got.Discovered, got.Queried, got.Dropped)
	}
	if len(got.Agents) != 2 || got.Summary.Total != 2 {
		t.Errorf("agents = %d, summary.total = %d, want 2 and 2", len(got.Agents), got.Summary.Total)
	}
}

// TestAPICheckUnlimitedQueriesAll proves the default (no cap) queries every
// discovered agent with discovered == queried and zero drops (compat).
func TestAPICheckUnlimitedQueriesAll(t *testing.T) {
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

	srv := httptest.NewServer(New(staticList(agents), time.Second).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/check?host=example&port=80")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	var got Response
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Discovered != 3 || got.Queried != 3 || got.Dropped != 0 {
		t.Errorf("counts = discovered %d queried %d dropped %d, want 3/3/0", got.Discovered, got.Queried, got.Dropped)
	}
}
