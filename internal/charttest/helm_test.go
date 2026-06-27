// Package charttest renders the Helm chart with `helm template`/`helm lint` and
// asserts the optional UI auth wiring is correct. It is hermetic apart from
// requiring the `helm` binary on PATH; without it the tests skip.
package charttest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/lavr/portreach/internal/auth"
)

// chartDir is the chart path relative to this package directory.
const chartDir = "../../charts/portreach"

// requireHelm skips the test when the helm binary is unavailable.
func requireHelm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed; skipping chart render tests")
	}
}

// helmTemplate runs `helm template` with the given extra args and returns
// stdout, failing the test on error.
func helmTemplate(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"template", "rel", chartDir}, args...)
	out, err := exec.Command("helm", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	return string(out)
}

// writeValues writes content to a temp values file and returns its path.
func writeValues(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write values: %v", err)
	}
	return p
}

const authOnValues = `
ui:
  auth:
    enabled: true
    redirectURL: https://portreach.corp/auth/callback
    allowedUsers: [alice]
    existingSecret: my-auth-secret
    providers:
      - id: github
        type: github
        clientID: ghid
        clientSecretEnv: GITHUB_CLIENT_SECRET
        clientSecretKey: githubClientSecret
        allowedOrgs: [myorg]
      - id: corp-gitlab
        type: gitlab
        displayName: "Corporate GitLab"
        baseURL: https://gitlab.corp
        clientID: glid
        clientSecretEnv: GITLAB_CLIENT_SECRET
        clientSecretKey: gitlabClientSecret
        allowedGroups: [infra, sre]
      - id: keycloak
        type: oidc
        displayName: "Corporate SSO"
        issuer: https://keycloak.corp/realms/main
        clientID: kcid
        clientSecretEnv: OIDC_CLIENT_SECRET
        clientSecretKey: oidcClientSecret
        groupsClaim: groups
        usernameClaim: preferred_username
        scopes: [openid, profile, email]
        allowedGroups: [sre, infra]
      - id: google
        type: google
        displayName: "Google"
        clientID: ggid
        clientSecretEnv: GOOGLE_CLIENT_SECRET
        clientSecretKey: googleClientSecret
        hostedDomain: corp.com
`

func TestChartAuthOn(t *testing.T) {
	requireHelm(t)
	vals := writeValues(t, authOnValues)

	dep := helmTemplate(t, "-f", vals, "--show-only", "templates/deployment-ui.yaml")
	for _, want := range []string{
		"--auth-config",
		"/etc/portreach/auth/auth.yaml",
		"name: PORTREACH_AUTH_COOKIE_KEY",
		"name: my-auth-secret",
		"key: cookieKey",
		"name: GITHUB_CLIENT_SECRET",
		"key: githubClientSecret",
		"name: GITLAB_CLIENT_SECRET",
		"key: gitlabClientSecret",
		"name: OIDC_CLIENT_SECRET",
		"key: oidcClientSecret",
		"name: GOOGLE_CLIENT_SECRET",
		"key: googleClientSecret",
		"mountPath: /etc/portreach/auth",
		"configMap:",
	} {
		if !strings.Contains(dep, want) {
			t.Errorf("deployment missing %q\n---\n%s", want, dep)
		}
	}

	cm := helmTemplate(t, "-f", vals, "--show-only", "templates/configmap-ui-auth.yaml")
	for _, want := range []string{
		"cookieKey: ${PORTREACH_AUTH_COOKIE_KEY}",
		"clientSecret: ${GITHUB_CLIENT_SECRET}",
		"clientSecret: ${GITLAB_CLIENT_SECRET}",
		"clientSecret: ${OIDC_CLIENT_SECRET}",
		"clientSecret: ${GOOGLE_CLIENT_SECRET}",
		"id: github",
		"id: corp-gitlab",
		"displayName: Corporate GitLab",
		"baseURL: https://gitlab.corp",
		"id: keycloak",
		"issuer: https://keycloak.corp/realms/main",
		"groupsClaim: groups",
		"usernameClaim: preferred_username",
		"id: google",
		"hostedDomain: corp.com",
	} {
		if !strings.Contains(cm, want) {
			t.Errorf("configmap missing %q\n---\n%s", want, cm)
		}
	}
}

// TestChartConfigRoundTrips renders the auth ConfigMap and feeds the embedded
// auth.yaml back through auth.LoadConfig + Validate to prove the chart emits a
// config the binary actually accepts (with the ${ENV} secrets populated).
func TestChartConfigRoundTrips(t *testing.T) {
	requireHelm(t)
	vals := writeValues(t, authOnValues)
	cm := helmTemplate(t, "-f", vals, "--show-only", "templates/configmap-ui-auth.yaml")

	var doc struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal([]byte(cm), &doc); err != nil {
		t.Fatalf("parse configmap: %v", err)
	}
	authYAML, ok := doc.Data["auth.yaml"]
	if !ok {
		t.Fatalf("configmap has no auth.yaml key\n%s", cm)
	}

	// Populate the ${ENV} secret placeholders the config references.
	t.Setenv("PORTREACH_AUTH_COOKIE_KEY", strings.Repeat("a", 64)) // 32 bytes hex
	t.Setenv("GITHUB_CLIENT_SECRET", "gh-secret")
	t.Setenv("GITLAB_CLIENT_SECRET", "gl-secret")
	t.Setenv("OIDC_CLIENT_SECRET", "oidc-secret")
	t.Setenv("GOOGLE_CLIENT_SECRET", "google-secret")

	f := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(f, []byte(authYAML), 0o600); err != nil {
		t.Fatalf("write auth.yaml: %v", err)
	}
	cfg, err := auth.LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig on rendered config: %v\n%s", err, authYAML)
	}
	if !cfg.Enabled() {
		t.Fatal("rendered config should be enabled")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("rendered config failed Validate: %v", err)
	}
	if len(cfg.Providers) != 4 {
		t.Fatalf("want 4 providers, got %d", len(cfg.Providers))
	}
}

func TestChartAuthOff(t *testing.T) {
	requireHelm(t)
	dep := helmTemplate(t, "--show-only", "templates/deployment-ui.yaml")
	for _, unwanted := range []string{"--auth-config", "secretKeyRef", "auth-config", "auth.yaml"} {
		if strings.Contains(dep, unwanted) {
			t.Errorf("auth-off deployment unexpectedly contains %q\n---\n%s", unwanted, dep)
		}
	}

	// The auth ConfigMap template must render to nothing when auth is off.
	all := helmTemplate(t)
	if strings.Contains(all, "kind: ConfigMap") && strings.Contains(all, "-ui-auth") {
		t.Errorf("auth-off render unexpectedly includes the auth ConfigMap\n%s", all)
	}
}

func TestChartLint(t *testing.T) {
	requireHelm(t)
	vals := writeValues(t, authOnValues)
	for _, args := range [][]string{
		{"lint", chartDir},
		{"lint", chartDir, "-f", vals},
	} {
		out, err := exec.Command("helm", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("helm %s failed: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
}
