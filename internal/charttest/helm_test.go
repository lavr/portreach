// Package charttest renders the Helm chart with `helm template`/`helm lint` and
// asserts the chart wiring matches the binary configuration contract.
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

const chartDir = "../../charts/portreach"

func requireHelm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed; skipping chart render tests")
	}
}

func helmTemplate(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"template", "rel", chartDir}, args...)
	out, err := exec.Command("helm", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	return string(out)
}

func helmTemplateErr(t *testing.T, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"template", "rel", chartDir}, args...)
	out, err := exec.Command("helm", full...).CombinedOutput()
	return string(out), err
}

func writeValues(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write values: %v", err)
	}
	return p
}

const authExternalValues = `
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
        allowedGroups: [infra, sre]
        groupMatch: subtree
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
`

const authInlineValues = `
ui:
  auth:
    enabled: true
    redirectURL: https://portreach.corp/auth/callback
    cookieKey: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    providers:
      - id: github
        type: github
        clientID: ghid
        clientSecret: gh-secret
      - id: corp-gitlab
        type: gitlab
        baseURL: https://gitlab.corp
        clientID: glid
        clientSecret: gl-secret
`

func TestChartAuthExternalSecret(t *testing.T) {
	requireHelm(t)
	vals := writeValues(t, authExternalValues)

	dep := helmTemplate(t, "-f", vals, "--show-only", "templates/deployment-ui.yaml")
	for _, want := range []string{
		"--auth-config",
		"/etc/portreach/auth/auth.yaml",
		"name: PORTREACH_AUTH_COOKIE_KEY",
		"name: my-auth-secret",
		"key: cookieKey",
		"name: GITHUB_CLIENT_SECRET",
		"key: githubClientSecret",
		"name: PORTREACH_AUTH_CORP_GITLAB_CLIENT_SECRET",
		"key: corp-gitlabClientSecret",
		"name: OIDC_CLIENT_SECRET",
		"key: oidcClientSecret",
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
		"clientSecret: ${PORTREACH_AUTH_CORP_GITLAB_CLIENT_SECRET}",
		"clientSecret: ${OIDC_CLIENT_SECRET}",
		"id: github",
		"id: corp-gitlab",
		"displayName: Corporate GitLab",
		"baseURL: https://gitlab.corp",
		"groupMatch: subtree",
		"id: keycloak",
		"issuer: https://keycloak.corp/realms/main",
		"groupsClaim: groups",
		"usernameClaim: preferred_username",
	} {
		if !strings.Contains(cm, want) {
			t.Errorf("configmap missing %q\n---\n%s", want, cm)
		}
	}

	all := helmTemplate(t, "-f", vals)
	if strings.Contains(all, "kind: Secret") && strings.Contains(all, "gh-secret") {
		t.Errorf("external-secret mode should not render inline secret material\n%s", all)
	}
}

func TestChartAuthInlineSecret(t *testing.T) {
	requireHelm(t)
	vals := writeValues(t, authInlineValues)

	secret := helmTemplate(t, "-f", vals, "--show-only", "templates/secret-ui-auth.yaml")
	for _, want := range []string{
		"kind: Secret",
		"name: rel-portreach-ui-auth",
		"cookieKey: \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
		"githubClientSecret: \"gh-secret\"",
		"corp-gitlabClientSecret: \"gl-secret\"",
	} {
		if !strings.Contains(secret, want) {
			t.Errorf("inline Secret missing %q\n---\n%s", want, secret)
		}
	}

	cm := helmTemplate(t, "-f", vals, "--show-only", "templates/configmap-ui-auth.yaml")
	for _, unwanted := range []string{"gh-secret", "gl-secret"} {
		if strings.Contains(cm, unwanted) {
			t.Errorf("configmap leaked inline secret %q\n---\n%s", unwanted, cm)
		}
	}
	for _, want := range []string{
		"clientSecret: ${PORTREACH_AUTH_GITHUB_CLIENT_SECRET}",
		"clientSecret: ${PORTREACH_AUTH_CORP_GITLAB_CLIENT_SECRET}",
	} {
		if !strings.Contains(cm, want) {
			t.Errorf("configmap missing %q\n---\n%s", want, cm)
		}
	}
}

func TestChartConfigRoundTrips(t *testing.T) {
	requireHelm(t)
	vals := writeValues(t, authExternalValues)
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

	t.Setenv("PORTREACH_AUTH_COOKIE_KEY", strings.Repeat("a", 64))
	t.Setenv("GITHUB_CLIENT_SECRET", "gh-secret")
	t.Setenv("PORTREACH_AUTH_CORP_GITLAB_CLIENT_SECRET", "gl-secret")
	t.Setenv("OIDC_CLIENT_SECRET", "oidc-secret")

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
	if len(cfg.Providers) != 3 {
		t.Fatalf("want 3 providers, got %d", len(cfg.Providers))
	}
}

const authHostDerivedValues = `
ui:
  auth:
    enabled: true
    redirectURL: ""
    allowedRedirectHosts: [portreach.cluster-one.k8s, portreach.shared.k8s]
    forwardedHostHeader: X-Original-Host
    cookieKey: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    providers:
      - id: github
        type: github
        clientID: ghid
        clientSecret: gh-secret
`

func TestChartAuthHostDerived(t *testing.T) {
	requireHelm(t)
	vals := writeValues(t, authHostDerivedValues)
	cm := helmTemplate(t, "-f", vals, "--show-only", "templates/configmap-ui-auth.yaml")

	// Host-derived mode: no redirectURL key, but the derivation knobs are present.
	if strings.Contains(cm, "redirectURL:") {
		t.Errorf("host-derived config should omit redirectURL\n---\n%s", cm)
	}
	for _, want := range []string{
		"allowedRedirectHosts:",
		"portreach.cluster-one.k8s",
		"forwardedHostHeader: X-Original-Host",
	} {
		if !strings.Contains(cm, want) {
			t.Errorf("configmap missing %q\n---\n%s", want, cm)
		}
	}
	// cookieSecure is unset in these values → must be omitted from the config.
	if strings.Contains(cm, "cookieSecure:") {
		t.Errorf("unset cookieSecure should be omitted\n---\n%s", cm)
	}

	// The rendered config must load and validate (empty redirectURL is allowed).
	var doc struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal([]byte(cm), &doc); err != nil {
		t.Fatalf("parse configmap: %v", err)
	}
	t.Setenv("PORTREACH_AUTH_COOKIE_KEY", strings.Repeat("a", 64))
	t.Setenv("PORTREACH_AUTH_GITHUB_CLIENT_SECRET", "gh-secret")

	f := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(f, []byte(doc.Data["auth.yaml"]), 0o600); err != nil {
		t.Fatalf("write auth.yaml: %v", err)
	}
	cfg, err := auth.LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig on host-derived config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("host-derived config failed Validate: %v", err)
	}
	if cfg.RedirectURL != "" {
		t.Errorf("RedirectURL = %q, want empty (host-derived)", cfg.RedirectURL)
	}
	if len(cfg.AllowedRedirectHosts) != 2 || cfg.ForwardedHostHeader != "X-Original-Host" {
		t.Errorf("derivation knobs not threaded: hosts=%v header=%q",
			cfg.AllowedRedirectHosts, cfg.ForwardedHostHeader)
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

	all := helmTemplate(t)
	if strings.Contains(all, "kind: ConfigMap") && strings.Contains(all, "-ui-auth") {
		t.Errorf("auth-off render unexpectedly includes the auth ConfigMap\n%s", all)
	}
	if strings.Contains(all, "kind: Secret") && strings.Contains(all, "-ui-auth") {
		t.Errorf("auth-off render unexpectedly includes the auth Secret\n%s", all)
	}
}

const authAPIOnlyValues = `
ui:
  auth:
    api:
      enabled: true
      entries:
        - id: ci
          issuer: https://keycloak.corp/realms/main
          audience: portreach
          type: gitlab
          usernameClaim: preferred_username
          groupsClaim: groups
          allowedGroups: [ci]
          groupMatch: subtree
        - id: entra
          issuer: https://login.microsoftonline.com/abc123/v2.0
          audience: api://portreach
`

// TestChartAuthAPIOnly: the bearer-only path renders auth config + mount with no
// browser providers (the API-only deployment must not require providers/cookie).
func TestChartAuthAPIOnly(t *testing.T) {
	requireHelm(t)
	vals := writeValues(t, authAPIOnlyValues)

	dep := helmTemplate(t, "-f", vals, "--show-only", "templates/deployment-ui.yaml")
	for _, want := range []string{"--auth-config", "/etc/portreach/auth/auth.yaml", "mountPath: /etc/portreach/auth", "configMap:"} {
		if !strings.Contains(dep, want) {
			t.Errorf("api-only deployment missing %q\n---\n%s", want, dep)
		}
	}
	// No browser providers → no cookie key / provider secret env wiring.
	for _, unwanted := range []string{"PORTREACH_AUTH_COOKIE_KEY", "CLIENT_SECRET"} {
		if strings.Contains(dep, unwanted) {
			t.Errorf("api-only deployment unexpectedly contains %q\n---\n%s", unwanted, dep)
		}
	}

	cm := helmTemplate(t, "-f", vals, "--show-only", "templates/configmap-ui-auth.yaml")
	for _, want := range []string{
		"api:",
		"id: ci",
		"issuer: https://keycloak.corp/realms/main",
		"audience: portreach",
		"type: gitlab",
		"groupMatch: subtree",
		"id: entra",
		"audience: api://portreach",
	} {
		if !strings.Contains(cm, want) {
			t.Errorf("api-only configmap missing %q\n---\n%s", want, cm)
		}
	}
	// API-only must not iterate browser providers or set a cookie key.
	for _, unwanted := range []string{"providers:", "cookieKey:"} {
		if strings.Contains(cm, unwanted) {
			t.Errorf("api-only configmap unexpectedly contains %q\n---\n%s", unwanted, cm)
		}
	}

	// The chart-rendered API-only config must load + validate in the binary.
	var doc struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal([]byte(cm), &doc); err != nil {
		t.Fatalf("parse configmap: %v", err)
	}
	f := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(f, []byte(doc.Data["auth.yaml"]), 0o600); err != nil {
		t.Fatalf("write auth.yaml: %v", err)
	}
	cfg, err := auth.LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig on api-only config: %v\n%s", err, doc.Data["auth.yaml"])
	}
	if !cfg.Enabled() {
		t.Fatal("api-only config should be enabled")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("api-only config failed Validate: %v", err)
	}
	if len(cfg.Providers) != 0 {
		t.Fatalf("api-only config should have no browser providers, got %d", len(cfg.Providers))
	}
	if len(cfg.API) != 2 {
		t.Fatalf("want 2 API entries, got %d", len(cfg.API))
	}

	// API-only mode renders no auth Secret (no cookie key / client secrets).
	all := helmTemplate(t, "-f", vals)
	if strings.Contains(all, "kind: Secret") && strings.Contains(all, "-ui-auth") {
		t.Errorf("api-only render unexpectedly includes the auth Secret\n%s", all)
	}
}

// TestChartAuthAPIEnabledNoEntries: enabling the API path with no entries would
// render `api: []`, which the UI reads as api-disabled and leaves the endpoint
// open. The chart must fail closed instead, mirroring the browser-providers guard.
func TestChartAuthAPIEnabledNoEntries(t *testing.T) {
	requireHelm(t)
	out, err := helmTemplateErr(t, "--set", "ui.auth.api.enabled=true")
	if err == nil {
		t.Fatalf("api enabled with no entries should fail to render, got:\n%s", out)
	}
	if !strings.Contains(out, "ui.auth.api.entries is empty") {
		t.Errorf("expected an empty-entries failure message, got:\n%s", out)
	}
}

// TestChartAuthLegacyToggle: a bare `ui.auth.enabled: true` keeps rendering the
// browser path (back-compat) via the portreach.auth.browser.enabled helper.
func TestChartAuthLegacyToggle(t *testing.T) {
	requireHelm(t)
	vals := writeValues(t, authInlineValues) // uses ui.auth.enabled: true

	cm := helmTemplate(t, "-f", vals, "--show-only", "templates/configmap-ui-auth.yaml")
	for _, want := range []string{"providers:", "id: github", "cookieKey: ${PORTREACH_AUTH_COOKIE_KEY}"} {
		if !strings.Contains(cm, want) {
			t.Errorf("legacy-toggle configmap missing %q\n---\n%s", want, cm)
		}
	}
	dep := helmTemplate(t, "-f", vals, "--show-only", "templates/deployment-ui.yaml")
	if !strings.Contains(dep, "--auth-config") {
		t.Errorf("legacy-toggle deployment missing --auth-config\n---\n%s", dep)
	}
}

// TestChartAgentToken: a literal token renders the shared Secret, injects
// PORTREACH_AGENT_TOKEN into both workloads via tokenSecretKey, and stamps a
// checksum annotation so a rotation rolls the pods. An existingSecret is
// referenced verbatim with no checksum (manual rollout).
func TestChartAgentToken(t *testing.T) {
	requireHelm(t)
	const tokenKey = "agent-token"

	secret := helmTemplate(t, "-f", writeValues(t, "agent:\n  auth:\n    token: s3cr3t-token\n"), "--show-only", "templates/secret-agent-token.yaml")
	for _, want := range []string{"kind: Secret", "name: rel-portreach-agent-token", tokenKey + ": \"s3cr3t-token\""} {
		if !strings.Contains(secret, want) {
			t.Errorf("agent-token Secret missing %q\n---\n%s", want, secret)
		}
	}

	for _, show := range []string{"templates/deployment-ui.yaml", "templates/daemonset-agent.yaml"} {
		out := helmTemplate(t, "--set", "agent.auth.token=s3cr3t-token", "--show-only", show)
		for _, want := range []string{
			"name: PORTREACH_AGENT_TOKEN",
			"name: rel-portreach-agent-token",
			"key: " + tokenKey,
			"checksum/agent-token:",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s missing %q\n---\n%s", show, want, out)
			}
		}
	}

	// Custom tokenSecretKey threads through to the secretKeyRef and Secret.
	custom := helmTemplate(t, "--set", "agent.auth.token=s3cr3t-token", "--set", "agent.auth.tokenSecretKey=tok", "--show-only", "templates/daemonset-agent.yaml")
	if !strings.Contains(custom, "key: tok") {
		t.Errorf("custom tokenSecretKey not threaded\n---\n%s", custom)
	}

	// existingSecret: referenced verbatim, no chart Secret, no checksum.
	ext := helmTemplate(t, "--set", "agent.auth.existingSecret=ext-tok", "--show-only", "templates/daemonset-agent.yaml")
	if !strings.Contains(ext, "name: ext-tok") {
		t.Errorf("existingSecret not referenced\n---\n%s", ext)
	}
	if strings.Contains(ext, "checksum/agent-token") {
		t.Errorf("externally-managed Secret should not get a checksum annotation\n---\n%s", ext)
	}
	if _, err := helmTemplateErr(t, "--set", "agent.auth.existingSecret=ext-tok", "--show-only", "templates/secret-agent-token.yaml"); err == nil {
		t.Error("existingSecret should not render a chart-managed token Secret")
	}

	// metricsPublic toggles the agent flag.
	mp := helmTemplate(t, "--set", "agent.metricsPublic=true", "--show-only", "templates/daemonset-agent.yaml")
	if !strings.Contains(mp, "--metrics-public") {
		t.Errorf("metricsPublic should add --metrics-public\n---\n%s", mp)
	}
	def := helmTemplate(t, "--show-only", "templates/daemonset-agent.yaml")
	if strings.Contains(def, "--metrics-public") || strings.Contains(def, "PORTREACH_AGENT_TOKEN") {
		t.Errorf("token/metrics default-off agent unexpectedly wired\n---\n%s", def)
	}
}

// TestChartAgentTokenOff: no token configured → no env, no checksum, no Secret.
func TestChartAgentTokenOff(t *testing.T) {
	requireHelm(t)
	dep := helmTemplate(t, "--show-only", "templates/deployment-ui.yaml")
	for _, unwanted := range []string{"PORTREACH_AGENT_TOKEN", "checksum/agent-token"} {
		if strings.Contains(dep, unwanted) {
			t.Errorf("token-off deployment unexpectedly contains %q\n---\n%s", unwanted, dep)
		}
	}
	all := helmTemplate(t)
	if strings.Contains(all, "kind: Secret") && strings.Contains(all, "-agent-token") {
		t.Errorf("token-off render unexpectedly includes the agent-token Secret\n%s", all)
	}
}

// TestChartNetworkPolicy: opt-in NP renders ingress/egress selectors binding the
// UI and agent pods (best-effort second layer; off by default).
func TestChartNetworkPolicy(t *testing.T) {
	requireHelm(t)
	out := helmTemplate(t, "--set", "networkPolicy.enabled=true", "--show-only", "templates/networkpolicy.yaml")
	for _, want := range []string{
		"kind: NetworkPolicy",
		"name: rel-portreach-ui",
		"name: rel-portreach-agent",
		"app.kubernetes.io/component: ui",
		"app.kubernetes.io/component: agent",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("networkpolicy missing %q\n---\n%s", want, out)
		}
	}
	// Off by default.
	if _, err := helmTemplateErr(t, "--show-only", "templates/networkpolicy.yaml"); err == nil {
		t.Error("networkPolicy should be off by default")
	}
}

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

func TestChartImage(t *testing.T) {
	requireHelm(t)
	appVersion := chartAppVersion(t)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"default-appVersion", nil, "ghcr.io/lavr/portreach:" + appVersion},
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
		{"fqdn-uses-clusterDomain", []string{"--namespace", "demo", "--set", "ui.agentDiscovery.mode=fqdn", "--set", "clusterDomain=example.com"}, svc + ".demo.svc.example.com"},
		{"bare", []string{"--namespace", "demo", "--set", "ui.agentDiscovery.mode=bare"}, svc},
		{"override-wins", []string{"--namespace", "demo", "--set", "ui.agentDiscovery.mode=fqdn", "--set", "ui.agentDiscovery.dnsName=foo.bar"}, "foo.bar"},
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

func TestChartValidationFailures(t *testing.T) {
	requireHelm(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "unknown discovery mode",
			args: []string{"--namespace", "demo", "--set", "ui.agentDiscovery.mode=Fqdn"},
			want: "/ui/agentDiscovery/mode",
		},
		{
			name: "ingress without hosts",
			args: []string{"--set", "ui.ingress.enabled=true"},
			want: "ui/ingress/hosts",
		},
		{
			name: "inline provider secret without cookie key",
			args: []string{
				"--set", "ui.auth.enabled=true",
				"--set", "ui.auth.redirectURL=https://portreach.corp/auth/callback",
				"--set", "ui.auth.providers[0].id=github",
				"--set", "ui.auth.providers[0].type=github",
				"--set", "ui.auth.providers[0].clientID=ghid",
				"--set", "ui.auth.providers[0].clientSecret=gh-secret",
			},
			want: "ui.auth.cookieKey is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplateErr(t, tc.args...)
			if err == nil {
				t.Fatalf("expected render failure, got success:\n%s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("render error missing %q\n---\n%s", tc.want, out)
			}
		})
	}
}

func TestChartHostNetworkCanBeDisabled(t *testing.T) {
	requireHelm(t)
	out := helmTemplate(t,
		"--set", "agent.network.hostNetwork=false",
		"--set", "agent.network.hostPort.enabled=false",
		"--show-only", "templates/daemonset-agent.yaml",
	)
	for _, unwanted := range []string{"hostNetwork: true", "dnsPolicy: ClusterFirstWithHostNet", "hostPort:"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("daemonset unexpectedly contains %q\n---\n%s", unwanted, out)
		}
	}
}

func TestChartExtraExtensions(t *testing.T) {
	requireHelm(t)
	vals := writeValues(t, `
extraSecrets:
  - name: custom-secret
    stringData:
      release: "{{ .Release.Name }}"
      password: "s3cr3t"
extraManifests:
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: "{{ include \"portreach.fullname\" . }}-extra"
    data:
      release: "{{ .Release.Name }}"
`)

	secret := helmTemplate(t, "-f", vals, "--show-only", "templates/extra-secrets.yaml")
	for _, want := range []string{"name: custom-secret", "release: 'rel'", "password: s3cr3t"} {
		if !strings.Contains(secret, want) {
			t.Errorf("extra secret missing %q\n---\n%s", want, secret)
		}
	}

	extra := helmTemplate(t, "-f", vals, "--show-only", "templates/extra-manifests.yaml")
	for _, want := range []string{"kind: ConfigMap", "name: 'rel-portreach-extra'", "release: 'rel'"} {
		if !strings.Contains(extra, want) {
			t.Errorf("extra manifest missing %q\n---\n%s", want, extra)
		}
	}
}

func TestChartLint(t *testing.T) {
	requireHelm(t)
	external := writeValues(t, authExternalValues)
	inline := writeValues(t, authInlineValues)
	apiOnly := writeValues(t, authAPIOnlyValues)
	for _, args := range [][]string{
		{"lint", chartDir},
		{"lint", chartDir, "-f", external},
		{"lint", chartDir, "-f", inline},
		{"lint", chartDir, "-f", apiOnly},
		{"lint", chartDir, "--set", "agent.auth.token=s3cr3t-token", "--set", "agent.metricsPublic=true"},
	} {
		out, err := exec.Command("helm", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("helm %s failed: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
}

func TestUIBrandingEnvRendering(t *testing.T) {
	requireHelm(t)

	out := helmTemplate(t)
	for _, name := range []string{"PORTREACH_UI_TITLE", "PORTREACH_UI_DESCRIPTION", "PORTREACH_UI_FOOTER", "PORTREACH_LOGIN_TITLE", "PORTREACH_LOGIN_HEADER", "PORTREACH_LOGIN_FOOTER"} {
		if strings.Contains(out, "name: "+name) {
			t.Fatalf("default null branding should omit %s\n%s", name, out)
		}
	}

	values := writeValues(t, `
ui:
  branding:
    title: "Prod"
    description: ""
    footer: "<b>foot</b>"
  loginBranding:
    title: "Login Prod"
    header: ""
    footer: "<i>login foot</i>"
`)
	out = helmTemplate(t, "-f", values)
	for _, want := range []string{
		"name: PORTREACH_UI_TITLE\n              value: \"Prod\"",
		"name: PORTREACH_UI_DESCRIPTION\n              value: \"\"",
		"name: PORTREACH_UI_FOOTER\n              value: \"<b>foot</b>\"",
		"name: PORTREACH_LOGIN_TITLE\n              value: \"Login Prod\"",
		"name: PORTREACH_LOGIN_HEADER\n              value: \"\"",
		"name: PORTREACH_LOGIN_FOOTER\n              value: \"<i>login foot</i>\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q\n%s", want, out)
		}
	}
}
