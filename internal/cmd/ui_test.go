package cmd

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeAuthConfig writes contents to a temp file and returns its path.
func writeAuthConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write auth config: %v", err)
	}
	return path
}

// validGitHubConfig is an enabled single-provider config (GitHub does no network
// at construction, unlike GitLab's OIDC discovery).
const validGitHubConfig = `auth:
  redirectURL: https://portreach.corp/auth/callback
  cookieKey: 0000000000000000000000000000000000000000000000000000000000000000
  providers:
    - id: gh
      type: github
      clientID: cid
      clientSecret: secret
`

func TestBuildUIHandlerNoAuthConfig(t *testing.T) {
	var out bytes.Buffer
	h, err := buildUIHandler(nil, time.Second, "", "", &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200 (auth off = open UI)", rec.Code)
	}
	if out.Len() != 0 {
		t.Errorf("auth-off should print no startup notice, got %q", out.String())
	}
}

func TestBuildUIHandlerDisabledConfigIsOpen(t *testing.T) {
	// A config file with no providers is valid and leaves the UI unauthenticated.
	path := writeAuthConfig(t, "auth:\n  allowedUsers: []\n")
	var out bytes.Buffer
	h, err := buildUIHandler(nil, time.Second, path, "", &out)
	if err != nil {
		t.Fatalf("disabled config should not error: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200 for disabled auth", rec.Code)
	}
}

func TestBuildUIHandlerInvalidConfigErrors(t *testing.T) {
	// Enabled provider missing clientSecret → Validate (via auth.New) fails.
	path := writeAuthConfig(t, `auth:
  redirectURL: https://portreach.corp/auth/callback
  cookieKey: 0000000000000000000000000000000000000000000000000000000000000000
  providers:
    - id: gh
      type: github
      clientID: cid
`)
	if _, err := buildUIHandler(nil, time.Second, path, "", &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for invalid (enabled) auth config")
	}
}

func TestBuildUIHandlerMissingConfigFileErrors(t *testing.T) {
	if _, err := buildUIHandler(nil, time.Second, "/no/such/auth.yaml", "", &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for missing auth config file")
	}
}

func TestBuildUIHandlerEnabledGatesAndAnnounces(t *testing.T) {
	path := writeAuthConfig(t, validGitHubConfig)
	var out bytes.Buffer
	h, err := buildUIHandler(nil, time.Second, path, "", &out)
	if err != nil {
		t.Fatalf("valid config should not error: %v", err)
	}

	// Startup notice lists the provider id (no secrets).
	if !strings.Contains(out.String(), "gh") {
		t.Errorf("startup notice missing provider id, got %q", out.String())
	}
	if strings.Contains(out.String(), "secret") {
		t.Errorf("startup notice must not leak secrets, got %q", out.String())
	}

	// /healthz stays public.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200 (public)", rec.Code)
	}

	// A protected path redirects to login.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("protected path status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/auth/login") {
		t.Errorf("redirect = %q, want /auth/login", loc)
	}
}

// TestBuildUIHandlerAPIOnlyEnablesBearerGate verifies the bearer-only wiring: a
// config with an `api` entry and no `providers` (and no cookieKey) still enables
// auth, gating /api/* behind a token while keeping /healthz public.
func TestBuildUIHandlerAPIOnlyEnablesBearerGate(t *testing.T) {
	// Minimal OIDC issuer: discovery is all auth.New needs at startup (JWKS is
	// fetched lazily on the first token verification, which this test never does).
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/jwks")
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	path := writeAuthConfig(t, "auth:\n  api:\n    - id: ci\n      issuer: "+srv.URL+"\n      audience: portreach\n")
	var out bytes.Buffer
	h, err := buildUIHandler(nil, time.Second, path, "", &out)
	if err != nil {
		t.Fatalf("bearer-only config should build: %v", err)
	}
	// Startup banner records the api entry id, no secrets.
	if !strings.Contains(out.String(), "ci") {
		t.Errorf("startup notice missing api id, got %q", out.String())
	}

	// /healthz stays public.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", rec.Code)
	}

	// /api/check without a token → 401 JSON (never a redirect to a login page).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/check", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/api/check no token = %d, want 401", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("API-only mode must not redirect, got Location=%q", loc)
	}
}

// TestRunUIInvalidAuthConfigExits2 covers the cmd-level wiring: an invalid auth
// config makes runUI fail fast with exit code 2 before serving.
func TestRunUIInvalidAuthConfigExits2(t *testing.T) {
	path := writeAuthConfig(t, `auth:
  cookieKey: zzzz
  providers:
    - id: gh
      type: github
`)
	assertExit(t, []string{"ui", "--agents=a:1", "--auth-config=" + path}, 2)
}

func TestBrandingFlagEnvResolutionAndExpansion(t *testing.T) {
	t.Setenv("PORTREACH_UI_TITLE", "env")
	t.Setenv("PORTREACH_UI_DESCRIPTION", "env-desc")
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	title := fs.String("ui-title", "", "")
	desc := fs.String("ui-description", "", "")
	if err := fs.Parse([]string{`--ui-title=`, `--ui-description=flag-desc`}); err != nil {
		t.Fatal(err)
	}
	gotTitle := resolveOptionalString(fs, "ui-title", title, "PORTREACH_UI_TITLE")
	if gotTitle == nil || *gotTitle != "" {
		t.Fatalf("explicit empty title = %#v, want pointer to empty", gotTitle)
	}
	if gotDesc := resolveString(fs, "ui-description", desc, "PORTREACH_UI_DESCRIPTION"); gotDesc != "flag-desc" {
		t.Fatalf("description = %q, want flag-desc", gotDesc)
	}

	fs = flag.NewFlagSet("test", flag.ContinueOnError)
	title = fs.String("ui-title", "", "")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	gotTitle = resolveOptionalString(fs, "ui-title", title, "PORTREACH_UI_TITLE")
	if gotTitle == nil || *gotTitle != "env" {
		t.Fatalf("env title = %#v, want env", gotTitle)
	}

	t.Setenv("PORTREACH_UI_TITLE", "")
	gotTitle = resolveOptionalString(fs, "ui-title", title, "PORTREACH_UI_TITLE")
	if gotTitle == nil || *gotTitle != "" {
		t.Fatalf("present empty env title = %#v, want pointer to empty", gotTitle)
	}

	t.Setenv("NAME", "<b>prod</b>")
	if got := expandEnv(`hello ${NAME} $NAME $$ $MISSING`); got != `hello <b>prod</b> <b>prod</b> $ ` {
		t.Fatalf("expandEnv = %q", got)
	}
	if expandOptionalEnv(nil) != nil {
		t.Fatal("nil optional expansion should stay nil")
	}
}
