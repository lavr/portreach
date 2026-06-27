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

// helmTemplateErr runs `helm template` and returns the combined output and the
// command error without failing the test, for asserting expected render failures.
func helmTemplateErr(t *testing.T, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"template", "rel", chartDir}, args...)
	out, err := exec.Command("helm", full...).CombinedOutput()
	return string(out), err
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

// chartAppVersion reads appVersion from Chart.yaml so the image assertions track
// the chart instead of hard-coding a version.
func chartAppVersion(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(chartDir, "Chart.yaml"))
	if err != nil {
		t.Fatalf("read Chart.yaml: %v", err)
	}
	var doc struct {
		AppVersion string `yaml:"appVersion"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse Chart.yaml: %v", err)
	}
	if doc.AppVersion == "" {
		t.Fatal("Chart.yaml has no appVersion")
	}
	return doc.AppVersion
}

// imageRefs extracts every `image: "..."` value from a rendered manifest.
func imageRefs(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "image:"); ok {
			out = append(out, strings.Trim(strings.TrimSpace(v), `"`))
		}
	}
	return out
}

// TestChartImage asserts image.tag is the single source of truth: empty defaults
// to the plain appVersion (no -rootless suffix) and any explicit tag is used
// verbatim, with the UI Deployment and agent DaemonSet always sharing one image.
func TestChartImage(t *testing.T) {
	requireHelm(t)
	appVersion := chartAppVersion(t)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"default-appVersion-no-rootless", nil, "ghcr.io/lavr/portreach:" + appVersion},
		{"rootless-opt-in-verbatim", []string{"--set", "image.tag=" + appVersion + "-rootless"}, "ghcr.io/lavr/portreach:" + appVersion + "-rootless"},
		{"sha-tag-verbatim", []string{"--set", "image.tag=sha-abc123"}, "ghcr.io/lavr/portreach:sha-abc123"},
		{"custom-repository", []string{"--set", "image.repository=ghcr.io/me/portreach"}, "ghcr.io/me/portreach:" + appVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ui := imageRefs(helmTemplate(t, append([]string{"--show-only", "templates/deployment-ui.yaml"}, tc.args...)...))
			ds := imageRefs(helmTemplate(t, append([]string{"--show-only", "templates/daemonset-agent.yaml"}, tc.args...)...))
			for label, got := range map[string][]string{"deployment-ui": ui, "daemonset-agent": ds} {
				if len(got) == 0 {
					t.Fatalf("%s: no image reference rendered", label)
				}
				for _, ref := range got {
					if ref != tc.want {
						t.Errorf("%s: image = %q, want %q", label, ref, tc.want)
					}
				}
			}
		})
	}
}

// agentsDNS extracts the PORTREACH_AGENTS_DNS env value from a rendered UI
// Deployment. The env block renders the name on one line and its value on the
// next, so we scan for the name line and read the following value line.
func agentsDNS(t *testing.T, s string) string {
	t.Helper()
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if strings.Contains(line, "name: PORTREACH_AGENTS_DNS") && i+1 < len(lines) {
			v := strings.TrimSpace(lines[i+1])
			v = strings.TrimPrefix(v, "value:")
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	t.Fatalf("PORTREACH_AGENTS_DNS not found in render\n%s", s)
	return ""
}

// TestChartDiscoveryDNS asserts the agent-discovery name priority chain:
// ui.agentsDnsName override wins verbatim; otherwise ui.discovery.mode picks
// between relative (default), fqdn (uses clusterDomain) and bare. The namespace
// is substituted from --namespace, and relative is independent of clusterDomain.
func TestChartDiscoveryDNS(t *testing.T) {
	requireHelm(t)
	const svc = "rel-portreach-agent"

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"default-relative", []string{"--namespace", "demo"}, svc + ".demo.svc"},
		{"relative-ignores-clusterDomain", []string{"--namespace", "demo", "--set", "clusterDomain=example.com"}, svc + ".demo.svc"},
		{"fqdn-uses-clusterDomain", []string{"--namespace", "demo", "--set", "ui.discovery.mode=fqdn", "--set", "clusterDomain=example.com"}, svc + ".demo.svc.example.com"},
		{"fqdn-default-cluster-local", []string{"--namespace", "demo", "--set", "ui.discovery.mode=fqdn"}, svc + ".demo.svc.cluster.local"},
		{"bare", []string{"--namespace", "demo", "--set", "ui.discovery.mode=bare"}, svc},
		{"override-wins", []string{"--namespace", "demo", "--set", "ui.discovery.mode=fqdn", "--set", "ui.agentsDnsName=foo.bar"}, "foo.bar"},
		{"namespace-substitution", []string{"--namespace", "other-ns"}, svc + ".other-ns.svc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := helmTemplate(t, append([]string{"--show-only", "templates/deployment-ui.yaml"}, tc.args...)...)
			if got := agentsDNS(t, out); got != tc.want {
				t.Errorf("PORTREACH_AGENTS_DNS = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestChartDiscoveryModeValidation asserts an unknown/typo'd discovery mode
// fails the render loudly instead of silently falling back to relative, and that
// a null ui.discovery block falls back to the relative default rather than
// panicking on a nil-pointer deref.
func TestChartDiscoveryModeValidation(t *testing.T) {
	requireHelm(t)
	const svc = "rel-portreach-agent"

	// Wrong case is a typo, not one of relative|fqdn|bare: must fail the render.
	if out, err := helmTemplateErr(t, "--namespace", "demo", "--set", "ui.discovery.mode=Fqdn"); err == nil {
		t.Errorf("unknown discovery mode should fail render, got success:\n%s", out)
	}

	// ui.discovery: null must fall back to the relative default, not panic.
	vals := writeValues(t, "ui:\n  discovery: null\n")
	out := helmTemplate(t, "-f", vals, "--namespace", "demo", "--show-only", "templates/deployment-ui.yaml")
	if got := agentsDNS(t, out); got != svc+".demo.svc" {
		t.Errorf("null discovery: PORTREACH_AGENTS_DNS = %q, want %q", got, svc+".demo.svc")
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
