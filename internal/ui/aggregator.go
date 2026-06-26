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

// CheckAll queries every agent's /check endpoint in parallel for the target and
// returns one AgentResult per agent. A failing agent yields a result with Error
// set rather than aborting the whole fan-out. Results are ordered by agent addr
// for stable output. The caller's ctx bounds the overall fan-out; client should
// carry a per-request timeout.
func CheckAll(ctx context.Context, client *http.Client, agents []discovery.Agent, target Target) []AgentResult {
	results := make([]AgentResult, len(agents))
	var wg sync.WaitGroup
	for i, a := range agents {
		wg.Add(1)
		go func(i int, a discovery.Agent) {
			defer wg.Done()
			results[i] = checkOne(ctx, client, a, target)
		}(i, a)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Agent < results[j].Agent })
	return results
}

// checkOne queries a single agent, normalizing transport and decode failures
// into the Error field.
func checkOne(ctx context.Context, client *http.Client, a discovery.Agent, target Target) AgentResult {
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

// Response is the aggregated /api/check payload.
type Response struct {
	Target  Target        `json:"target"`
	Agents  []AgentResult `json:"agents"`
	Summary Summary       `json:"summary"`
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
