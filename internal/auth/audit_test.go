package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureLogger returns an slog.Logger writing JSON to buf, plus a decode helper
// returning the parsed events in order.
func captureLogger() (*slog.Logger, func(t *testing.T) []map[string]any) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	decode := func(t *testing.T) []map[string]any {
		t.Helper()
		var events []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var ev map[string]any
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("decode log line %q: %v", line, err)
			}
			events = append(events, ev)
		}
		return events
	}
	return logger, decode
}

// onlyEvent asserts exactly one audit event was emitted and returns it.
func onlyEvent(t *testing.T, events []map[string]any) map[string]any {
	t.Helper()
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1: %v", len(events), events)
	}
	return events[0]
}

func wantField(t *testing.T, ev map[string]any, key, want string) {
	t.Helper()
	if got, _ := ev[key].(string); got != want {
		t.Errorf("event[%q] = %q, want %q", key, got, want)
	}
}

// jsonReq builds a POST request with a JSON body and the JSON content type.
func jsonReq(path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestAuditCheckTCPPostAnonymous(t *testing.T) {
	logger, decode := captureLogger()
	h := AuditCheck(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := jsonReq(apiCheckTCPPath, `{"host":"db.internal","port":5432,"timeout":"5s"}`)
	req.RemoteAddr = "203.0.113.7:5555"
	h.ServeHTTP(httptest.NewRecorder(), req)

	ev := onlyEvent(t, decode(t))
	wantField(t, ev, "event", "check")
	wantField(t, ev, "user", "anonymous")
	wantField(t, ev, "provider", "")
	wantField(t, ev, "auth_method", "") // no credential → empty, never a stray value
	wantField(t, ev, "target", "db.internal:5432/tcp")
	wantField(t, ev, "remote", "203.0.113.7:5555")
}

func TestAuditCheckCarriesIdentity(t *testing.T) {
	logger, decode := captureLogger()
	h := AuditCheck(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := jsonReq(apiCheckTCPPath, `{"host":"svc","port":80}`)
	req.RemoteAddr = "198.51.100.9:1234"
	ctx := WithIdentity(req.Context(), Session{User: "alice", Provider: "gh"})
	h.ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx))

	ev := onlyEvent(t, decode(t))
	wantField(t, ev, "event", "check")
	wantField(t, ev, "user", "alice")
	wantField(t, ev, "provider", "gh")
	wantField(t, ev, "target", "svc:80/tcp")
	wantField(t, ev, "remote", "198.51.100.9:1234")
}

// TestAuditCheckPostgresNoPassword proves the postgres endpoint is audited with
// the right proto and target, that the password never reaches the audit event,
// and that the buffered body is restored so the downstream handler still reads
// the full request (credentials intact).
func TestAuditCheckPostgresNoPassword(t *testing.T) {
	logger, decode := captureLogger()
	const canary = "CANARY-pw-7f3"
	var gotBody string
	h := AuditCheck(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))

	body := `{"host":"pg.internal","port":5432,"credentials":{"username":"u","password":"` + canary + `"}}`
	h.ServeHTTP(httptest.NewRecorder(), jsonReq(apiCheckPostgresPath, body))

	ev := onlyEvent(t, decode(t))
	wantField(t, ev, "event", "check")
	wantField(t, ev, "target", "pg.internal:5432/postgres")
	for k, v := range ev {
		if s, ok := v.(string); ok && strings.Contains(s, canary) {
			t.Errorf("password leaked into audit event field %q: %q", k, s)
		}
	}
	if gotBody != body {
		t.Errorf("handler saw body %q, want the original %q (body not restored)", gotBody, body)
	}
}

func TestAuditCheckIndexGetOnlyOnSubmit(t *testing.T) {
	logger, decode := captureLogger()
	h := AuditCheck(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// Bare "/" (no target) must not emit a check event.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, indexPath, nil))
	if events := decode(t); len(events) != 0 {
		t.Fatalf("bare / emitted %d events, want 0: %v", len(events), events)
	}

	// A shareable "/" GET link with a target still emits a check event.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, indexPath+"?host=h&port=22&proto=tcp", nil))
	ev := onlyEvent(t, decode(t))
	wantField(t, ev, "event", "check")
	wantField(t, ev, "target", "h:22/tcp")
}

func TestAuditCheckFormPostPostgres(t *testing.T) {
	logger, decode := captureLogger()
	h := AuditCheck(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	form := "check=postgres&host=pg&port=5432&username=u&password=secret"
	req := httptest.NewRequest(http.MethodPost, indexPath, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(httptest.NewRecorder(), req)

	ev := onlyEvent(t, decode(t))
	wantField(t, ev, "target", "pg:5432/postgres")
	for k, v := range ev {
		if s, ok := v.(string); ok && strings.Contains(s, "secret") {
			t.Errorf("password leaked into audit event field %q: %q", k, s)
		}
	}
}

func TestAuditCheckIgnoresHealthz(t *testing.T) {
	logger, decode := captureLogger()
	h := AuditCheck(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, healthzPath, nil))
	if events := decode(t); len(events) != 0 {
		t.Fatalf("/healthz emitted %d events, want 0", len(events))
	}
}

func TestAuditCheckDefaultProtoTCP(t *testing.T) {
	logger, decode := captureLogger()
	h := AuditCheck(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	h.ServeHTTP(httptest.NewRecorder(), jsonReq(apiCheckTCPPath, `{"host":"h","port":53}`))
	ev := onlyEvent(t, decode(t))
	wantField(t, ev, "target", "h:53/tcp")
}

func TestAuditCheckNilLoggerDoesNotPanic(t *testing.T) {
	// slog.Default() is used; just assert no panic and next runs.
	called := false
	h := AuditCheck(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), jsonReq(apiCheckTCPPath, `{"host":"h","port":1}`))
	if !called {
		t.Fatal("next handler not called")
	}
}

func TestAuditLoginOK(t *testing.T) {
	logger, decode := captureLogger()
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub}}
	a := newTestAuth(nil, pcs, &fakeProvider{
		id: "gh", ptype: TypeGitHub,
		identity: Identity{Login: "alice", Groups: []string{"myorg"}},
	})
	a.logger = logger

	state, sc := beginLogin(t, a, "gh")
	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&code=c", nil)
	req.RemoteAddr = "10.0.0.5:40000"
	req.AddCookie(sc)
	a.handleCallback(httptest.NewRecorder(), req)

	ev := onlyEvent(t, decode(t))
	wantField(t, ev, "event", "login")
	wantField(t, ev, "user", "alice")
	wantField(t, ev, "provider", "gh")
	wantField(t, ev, "result", "ok")
	wantField(t, ev, "remote", "10.0.0.5:40000")
}

func TestAuditLoginDenied(t *testing.T) {
	logger, decode := captureLogger()
	pcs := []ProviderConfig{{ID: "gh", Type: TypeGitHub, AllowedOrgs: []string{"infra"}}}
	a := newTestAuth(nil, pcs, &fakeProvider{
		id: "gh", ptype: TypeGitHub,
		identity: Identity{Login: "mallory", Groups: []string{"outsiders"}},
	})
	a.logger = logger

	state, sc := beginLogin(t, a, "gh")
	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&code=c", nil)
	req.RemoteAddr = "10.0.0.9:1"
	req.AddCookie(sc)
	rec := httptest.NewRecorder()
	a.handleCallback(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied callback status = %d, want 403", rec.Code)
	}
	ev := onlyEvent(t, decode(t))
	wantField(t, ev, "event", "login")
	wantField(t, ev, "user", "mallory")
	wantField(t, ev, "provider", "gh")
	wantField(t, ev, "result", "denied")
	wantField(t, ev, "remote", "10.0.0.9:1")
}

// TestAuditActorAnonymous documents the fallback used when no identity is on the
// context (auth disabled or a public path).
func TestAuditActorAnonymous(t *testing.T) {
	user, provider := auditActor(context.Background())
	if user != "anonymous" || provider != "" {
		t.Fatalf("auditActor() = %q,%q, want anonymous,\"\"", user, provider)
	}
}
