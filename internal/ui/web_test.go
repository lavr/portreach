package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// get fetches a path from the server and returns status and body.
func get(t *testing.T, base, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func TestIndexEmptyForm(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second).Handler())
	defer srv.Close()

	code, body := get(t, srv.URL, "/")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !strings.Contains(body, `name="host"`) {
		t.Errorf("page is missing host input:\n%s", body)
	}
	// No results table when the form has not been submitted.
	if strings.Contains(body, "<table") {
		t.Errorf("unsubmitted page should not render a results table")
	}
}

func TestIndexWithResults(t *testing.T) {
	okAgent := fakeAgent(t, "node-ok", true)
	defer okAgent.Close()
	failAgent := fakeAgent(t, "node-fail", false)
	defer failAgent.Close()

	disc := staticList{{Addr: addr(okAgent)}, {Addr: addr(failAgent)}}
	srv := httptest.NewServer(New(disc, 2*time.Second).Handler())
	defer srv.Close()

	code, body := get(t, srv.URL, "/?host=example&port=80")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	for _, want := range []string{"node-ok", "node-fail", "open", "closed", "1/2 agents"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q:\n%s", want, body)
		}
	}
}

func TestIndexEmptyHost(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second).Handler())
	defer srv.Close()

	code, body := get(t, srv.URL, "/?host=&port=80")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if !strings.Contains(body, "host is required") {
		t.Errorf("expected host-required message:\n%s", body)
	}
	if strings.Contains(body, "<table") {
		t.Errorf("error page should not render a results table")
	}
}

func TestIndexBadPort(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second).Handler())
	defer srv.Close()

	code, body := get(t, srv.URL, "/?host=example&port=abc")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if !strings.Contains(body, "class=\"err\"") {
		t.Errorf("expected an error message on the page:\n%s", body)
	}
}

func TestIndexEscapesInput(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second).Handler())
	defer srv.Close()

	// A bad-port submit echoes the host back into the form value; ensure it is
	// HTML-escaped rather than injected raw.
	code, body := get(t, srv.URL, "/?host=%3Cscript%3E&port=abc")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if strings.Contains(body, "<script>") {
		t.Errorf("user input was not escaped:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected escaped host echoed back:\n%s", body)
	}
}

func TestIndexNotFound(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second).Handler())
	defer srv.Close()

	code, _ := get(t, srv.URL, "/nope")
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
}
