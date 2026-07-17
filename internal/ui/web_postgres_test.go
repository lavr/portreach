package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// postForm submits an application/x-www-form-urlencoded POST to path and
// returns the status and body — the no-JavaScript submission path the web form
// relies on.
func postForm(t *testing.T, base, path string, form url.Values) (int, string) {
	t.Helper()
	resp, err := http.Post(base+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("post form: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// TestIndexPostgresFieldsRenderWhenEnabled proves the check-type selector and
// the Postgres credential fields appear only when postgres is enabled, and that
// the password input is a masked field that never carries a value attribute.
func TestIndexPostgresFieldsRenderWhenEnabled(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second, WithEnabledChecks(mustEnabled(t, "tcp,postgres"))).Handler())
	defer srv.Close()

	code, body := get(t, srv.URL, "/")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	for _, want := range []string{`name="check"`, `value="postgres"`, `name="username"`, `type="password"`, `name="database"`, `name="tls"`, `name="tls_skip_verify"`} {
		if !strings.Contains(body, want) {
			t.Errorf("postgres-enabled form missing %q:\n%s", want, body)
		}
	}
	// The password input must never render a value= that could echo a secret.
	if strings.Contains(body, `name="password" value="`) && !strings.Contains(body, `name="password" value=""`) {
		t.Errorf("password input rendered a non-empty value:\n%s", body)
	}
}

// TestIndexPostgresFormSubmitRendersAuth drives a full no-JS Postgres form
// submission through the fan-out and asserts the Auth outcome is rendered and
// the password (a canary) never appears in the returned HTML, while the agent
// still received it — proving the secret is used but not reflected.
func TestIndexPostgresFormSubmitRendersAuth(t *testing.T) {
	var captured capturedRequest
	agent := capturingPostgresAgent(t, "node-a", true, true, &captured)
	defer agent.Close()

	disc := staticList{{Addr: addr(agent)}}
	srv := httptest.NewServer(New(disc, time.Second, WithAgentToken("tok"), WithEnabledChecks(mustEnabled(t, "tcp,postgres"))).Handler())
	defer srv.Close()

	form := url.Values{
		"check":    {"postgres"},
		"host":     {"db.internal"},
		"port":     {"5432"},
		"username": {"alice"},
		"password": {canaryPassword},
		"database": {"app"},
		"tls":      {"1"},
	}
	code, body := postForm(t, srv.URL, "/", form)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200:\n%s", code, body)
	}
	// The agent received the password (it was used), ...
	if captured.PG.Credentials.Password != canaryPassword {
		t.Errorf("agent saw password = %q, want the canary", captured.PG.Credentials.Password)
	}
	// ... but it must never appear in the rendered page.
	if strings.Contains(body, canaryPassword) {
		t.Errorf("password leaked into rendered HTML:\n%s", body)
	}
	// Non-secret fields are echoed and the auth outcome is shown.
	if !strings.Contains(body, "alice") {
		t.Errorf("username not echoed:\n%s", body)
	}
	if !strings.Contains(body, ">auth<") && !strings.Contains(body, "auth") {
		t.Errorf("auth column not rendered:\n%s", body)
	}
}

// TestIndexPostgresFormValidationErrorRedactsPassword ensures a submission that
// fails field validation (missing username) returns 400 with a localized error
// and still never echoes the submitted password.
func TestIndexPostgresFormValidationErrorRedactsPassword(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second, WithEnabledChecks(mustEnabled(t, "tcp,postgres"))).Handler())
	defer srv.Close()

	form := url.Values{
		"check":    {"postgres"},
		"host":     {"db.internal"},
		"port":     {"5432"},
		"username": {""}, // missing → validation error
		"password": {canaryPassword},
	}
	code, body := postForm(t, srv.URL, "/", form)
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400:\n%s", code, body)
	}
	if strings.Contains(body, canaryPassword) {
		t.Errorf("password leaked into error page:\n%s", body)
	}
	if !strings.Contains(body, "username is required") {
		t.Errorf("expected username-required error:\n%s", body)
	}
}
