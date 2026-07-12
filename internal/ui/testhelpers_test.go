package ui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lavr/portreach/internal/checkapi"
)

// mustEnabled parses csv into an EnabledChecks set, failing the test on error.
// Test-only convenience so callers don't repeat the error-check boilerplate
// checkapi.ParseEnabledChecks requires in production code.
func mustEnabled(t *testing.T, csv string) checkapi.EnabledChecks {
	t.Helper()
	ec, err := checkapi.ParseEnabledChecks(csv)
	if err != nil {
		t.Fatalf("ParseEnabledChecks(%q): %v", csv, err)
	}
	return ec
}

// postJSON marshals body and POSTs it to base+path over a real listener,
// returning the raw response (caller must close the body). Used by tests that
// only need the end-to-end status/body and don't need to manipulate the
// request further.
func postJSON(t *testing.T, base, path string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp, err := http.Post(base+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// postTCPCheck POSTs a TCPCheckRequest for host:port to base's /api/check/tcp.
func postTCPCheck(t *testing.T, base, host string, port int) *http.Response {
	t.Helper()
	return postJSON(t, base, "/api/check/tcp", checkapi.TCPCheckRequest{Host: host, Port: port})
}

// newPostRequest builds an in-process POST request with a JSON body for tests
// that need to manipulate the request further (RemoteAddr, headers, an
// injected identity context) before calling Handler().ServeHTTP directly
// rather than going through a real listener.
func newPostRequest(t *testing.T, path string, body any) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	return req
}
