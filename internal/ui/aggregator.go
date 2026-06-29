// Package ui implements the aggregator that fans out a single target check to
// all discovered agents and serves the web form, using only the standard library.
package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"

	"github.com/lavr/portreach/internal/discovery"
	"github.com/lavr/portreach/internal/probe"
)

// Target is the host:port to check from every agent.
type Target struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Timeout string `json:"timeout,omitempty"`
}

// AgentResult is one agent's answer for the target. Error is set when the agent
// could not be reached or returned a malformed/non-200 response; in that case
// the embedded probe Result is empty.
type AgentResult struct {
	Agent string `json:"agent"`
	Node  string `json:"node,omitempty"`
	probe.Result
	Error string `json:"error,omitempty"`
}

// agentCheckResponse mirrors the agent /check JSON: a node label plus the probe
// result fields.
type agentCheckResponse struct {
	Node string `json:"node"`
	probe.Result
}

// FanoutConfig bounds the per-check fan-out. Both fields default to 0 =
// unlimited, preserving the "from every node" promise; set either one to bound
// the blast radius (MaxAgentsPerCheck) or the concurrency (MaxConcurrentFanout)
// of a single check.
type FanoutConfig struct {
	// MaxAgentsPerCheck caps how many discovered agents a single check queries.
	// 0 = unlimited (query every discovered agent — today's behaviour). When the
	// cap is exceeded, agents are selected deterministically (sorted by Addr) and
	// the rest are reported as dropped, never silently truncated.
	MaxAgentsPerCheck int
	// MaxConcurrentFanout bounds how many agents are queried concurrently.
	// 0 = unlimited (a goroutine per agent — today's behaviour); >0 runs a bounded
	// worker pool of that size. A zero-size pool would hang, so it is never spawned.
	MaxConcurrentFanout int
}

// Validate rejects negative caps; both fields are otherwise valid (0 = unlimited).
func (c FanoutConfig) Validate() error {
	if c.MaxAgentsPerCheck < 0 {
		return fmt.Errorf("maxAgentsPerCheck must be >= 0, got %d", c.MaxAgentsPerCheck)
	}
	if c.MaxConcurrentFanout < 0 {
		return fmt.Errorf("maxConcurrentFanout must be >= 0, got %d", c.MaxConcurrentFanout)
	}
	return nil
}

// selectAgents applies the optional MaxAgentsPerCheck cap, returning the agents
// to query and the number dropped. With max <= 0 (unlimited) or fewer agents than
// the cap, every agent is queried and nothing is dropped. When the cap is hit,
// agents are sorted by Addr first so the selected subset is deterministic and
// reproducible — Addr is the only stable key known before a request (Node only
// appears in an agent's response). The input slice is never mutated.
func selectAgents(agents []discovery.Agent, max int) (selected []discovery.Agent, dropped int) {
	if max <= 0 || len(agents) <= max {
		return agents, 0
	}
	sorted := append([]discovery.Agent(nil), agents...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Addr < sorted[j].Addr })
	return sorted[:max], len(agents) - max
}

// CheckAll queries every agent's /check endpoint in parallel for the target and
// returns one AgentResult per agent. A failing agent yields a result with Error
// set rather than aborting the whole fan-out. Results are ordered by agent addr
// for stable output. The caller's ctx bounds the overall fan-out; client should
// carry a per-request timeout. token, when non-empty, is sent as the agent
// bearer token on every /check call; empty means no header (backward compatible).
// maxConcurrent bounds the worker pool: 0 (or >= len(agents)) means a goroutine
// per agent (today's behaviour); a positive value runs that many concurrently.
func CheckAll(ctx context.Context, client *http.Client, agents []discovery.Agent, target Target, token string, maxConcurrent int) []AgentResult {
	results := make([]AgentResult, len(agents))
	// A nil semaphore means unlimited concurrency; a positive cap caps in-flight
	// probes. We never build a zero-capacity channel (it would deadlock).
	var sem chan struct{}
	if maxConcurrent > 0 && maxConcurrent < len(agents) {
		sem = make(chan struct{}, maxConcurrent)
	}
	var wg sync.WaitGroup
	for i, a := range agents {
		wg.Add(1)
		if sem != nil {
			sem <- struct{}{} // block until a worker slot frees
		}
		go func(i int, a discovery.Agent) {
			defer wg.Done()
			if sem != nil {
				defer func() { <-sem }()
			}
			results[i] = checkOne(ctx, client, a, target, token)
		}(i, a)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Agent < results[j].Agent })
	return results
}

// checkOne queries a single agent, normalizing transport and decode failures
// into the Error field. A non-empty token is attached as the agent bearer token.
func checkOne(ctx context.Context, client *http.Client, a discovery.Agent, target Target, token string) AgentResult {
	out := AgentResult{Agent: a.Addr}

	q := url.Values{}
	q.Set("host", target.Host)
	q.Set("port", strconv.Itoa(target.Port))
	if target.Proto != "" {
		q.Set("proto", target.Proto)
	}
	if target.Timeout != "" {
		q.Set("timeout", target.Timeout)
	}
	endpoint := "http://" + a.Addr + "/check?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	// Authenticate to the agent when a shared token is configured; an empty
	// token leaves the request unauthenticated (today's open-agent behaviour).
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	if resp.StatusCode != http.StatusOK {
		// Surface the agent's structured reason when present (e.g. a policy
		// denial returns 403 with {"error":"target denied by policy"}) so the
		// UI shows why rather than a bare status code.
		out.Error = fmt.Sprintf("agent returned status %d", resp.StatusCode)
		var er struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(resp.Body).Decode(&er) == nil && er.Error != "" {
			out.Error = fmt.Sprintf("agent returned status %d: %s", resp.StatusCode, er.Error)
		}
		return out
	}

	var acr agentCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&acr); err != nil {
		out.Error = "decode response: " + err.Error()
		return out
	}

	out.Node = acr.Node
	out.Result = acr.Result
	return out
}

// Summary counts how many agents reported a successful TCP connection.
type Summary struct {
	OK    int `json:"ok"`
	Total int `json:"total"`
}

// Response is the aggregated /api/check payload. Discovered/Queried/Dropped make
// partial results unambiguous when a MaxAgentsPerCheck cap is in effect: with no
// cap they are equal (Discovered == Queried, Dropped == 0) and Summary.Total
// equals the number of agents queried.
type Response struct {
	Target     Target        `json:"target"`
	Agents     []AgentResult `json:"agents"`
	Summary    Summary       `json:"summary"`
	Discovered int           `json:"discovered"`
	Queried    int           `json:"queried"`
	Dropped    int           `json:"dropped"`
}

// Summarize tallies the OK/total counts for a set of agent results.
func Summarize(results []AgentResult) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		if r.Error == "" && r.TCP != nil && r.TCP.OK {
			s.OK++
		}
	}
	return s
}
