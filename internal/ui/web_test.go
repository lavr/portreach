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
	return getLang(t, base, path, "")
}

// getLang fetches a path with an optional Accept-Language header and returns
// status and body.
func getLang(t *testing.T, base, path, accept string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatalf("new request %s: %v", path, err)
	}
	if accept != "" {
		req.Header.Set("Accept-Language", accept)
	}
	resp, err := http.DefaultClient.Do(req)
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

func TestIndexLocalizedFormEnglishDefault(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second).Handler())
	defer srv.Close()

	// No Accept-Language → English default.
	code, body := get(t, srv.URL, "/")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !strings.Contains(body, `lang="en"`) {
		t.Errorf("expected English <html lang>:\n%s", body)
	}
	for _, want := range []string{">host\n", ">port\n", ">proto\n", ">timeout\n", ">check<"} {
		if !strings.Contains(body, want) {
			t.Errorf("English form missing %q:\n%s", want, body)
		}
	}
}

func TestIndexLocalizedFormRussian(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second).Handler())
	defer srv.Close()

	code, body := getLang(t, srv.URL, "/", "ru-RU,ru;q=0.9")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !strings.Contains(body, `lang="ru"`) {
		t.Errorf("expected Russian <html lang>:\n%s", body)
	}
	for _, want := range []string{"хост", "порт", "протокол", "таймаут", "проверить", "доступность с каждого узла"} {
		if !strings.Contains(body, want) {
			t.Errorf("Russian form missing %q:\n%s", want, body)
		}
	}
	// English labels must not leak into the Russian render.
	if strings.Contains(body, ">check<") {
		t.Errorf("Russian page leaked English button label:\n%s", body)
	}
}

func TestIndexLocalizedResultsRussian(t *testing.T) {
	okAgent := fakeAgent(t, "node-ok", true)
	defer okAgent.Close()
	failAgent := fakeAgent(t, "node-fail", false)
	defer failAgent.Close()

	disc := staticList{{Addr: addr(okAgent)}, {Addr: addr(failAgent)}}
	srv := httptest.NewServer(New(disc, 2*time.Second).Handler())
	defer srv.Close()

	code, body := getLang(t, srv.URL, "/?host=example&port=80", "ru")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	// Localized table headers, open/closed cells and summary line.
	for _, want := range []string{"узел", "задержка", "открыт", "закрыт", "1/2 агентов достигли example:80/tcp"} {
		if !strings.Contains(body, want) {
			t.Errorf("Russian results missing %q:\n%s", want, body)
		}
	}
}

func TestIndexLocalizedErrorRussian(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second).Handler())
	defer srv.Close()

	// Missing host → localized required-field message.
	code, body := getLang(t, srv.URL, "/?host=&port=80", "ru")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if !strings.Contains(body, "требуется хост") {
		t.Errorf("expected Russian host-required message:\n%s", body)
	}

	// Bad port → localized invalid-port message.
	code, body = getLang(t, srv.URL, "/?host=example&port=abc", "ru")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if !strings.Contains(body, "неверный порт") {
		t.Errorf("expected Russian invalid-port message:\n%s", body)
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

func TestIndexBrandingTriStateAndHTML(t *testing.T) {
	customTitle := `<span>Prod</span> — <b>EU</b>`
	srv := httptest.NewServer(New(staticList{}, time.Second, WithBranding(Branding{
		Title:       &customTitle,
		Description: `<strong>trusted</strong> description`,
		Footer:      `<em>trusted</em> footer`,
	})).Handler())
	defer srv.Close()

	code, body := get(t, srv.URL, "/")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	for _, want := range []string{`<title>Prod — EU</title>`, `<h1><span>Prod</span> — <b>EU</b></h1>`, `<strong>trusted</strong> description`, `<em>trusted</em> footer`} {
		if !strings.Contains(body, want) {
			t.Errorf("branded page missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `&lt;strong&gt;trusted`) {
		t.Errorf("branding HTML was escaped:\n%s", body)
	}
}

func TestIndexBrandingUnsetLocalizedAndEmptySuppressesHeading(t *testing.T) {
	srv := httptest.NewServer(New(staticList{}, time.Second).Handler())
	defer srv.Close()
	_, en := get(t, srv.URL, "/")
	if !strings.Contains(en, `<title>portreach</title>`) || !strings.Contains(en, `portreach — reachability from every node`) {
		t.Fatalf("unset branding did not keep English defaults:\n%s", en)
	}
	_, ru := getLang(t, srv.URL, "/", "ru")
	if !strings.Contains(ru, `portreach — доступность с каждого узла`) {
		t.Fatalf("unset branding did not keep Russian heading:\n%s", ru)
	}

	empty := ""
	srv2 := httptest.NewServer(New(staticList{}, time.Second, WithBranding(Branding{Title: &empty})).Handler())
	defer srv2.Close()
	_, body := get(t, srv2.URL, "/")
	if strings.Contains(body, "<h1>") {
		t.Errorf("empty explicit title should suppress h1:\n%s", body)
	}
	if !strings.Contains(body, `<title>portreach</title>`) {
		t.Errorf("empty explicit title should keep non-blank tab title:\n%s", body)
	}
}
