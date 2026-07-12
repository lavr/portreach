package charttest

import (
	"strings"
	"testing"
)

// TestChartEnabledChecksDefaultTCPOnly proves the default render wires
// --enabled-checks tcp on both workloads and never enables postgres.
func TestChartEnabledChecksDefaultTCPOnly(t *testing.T) {
	requireHelm(t)

	ui := helmTemplate(t, "--show-only", "templates/deployment-ui.yaml")
	agent := helmTemplate(t, "--show-only", "templates/daemonset-agent.yaml")
	for name, out := range map[string]string{"ui": ui, "agent": agent} {
		if !strings.Contains(out, "--enabled-checks") || !strings.Contains(out, "tcp") {
			t.Errorf("%s: default should render --enabled-checks tcp:\n%s", name, out)
		}
		if strings.Contains(out, "postgres") {
			t.Errorf("%s: default render must not enable postgres:\n%s", name, out)
		}
	}
}

// TestChartEnabledChecksPostgresRendersBothWorkloads proves enabling postgres
// (with an agent token) renders --enabled-checks tcp,postgres on both workloads.
func TestChartEnabledChecksPostgresRendersBothWorkloads(t *testing.T) {
	requireHelm(t)

	args := []string{
		"--set", "ui.enabledChecks={tcp,postgres}",
		"--set", "agent.enabledChecks={tcp,postgres}",
		"--set", "agent.auth.token=deadbeefdeadbeef",
	}
	ui := helmTemplate(t, append(args, "--show-only", "templates/deployment-ui.yaml")...)
	agent := helmTemplate(t, append(args, "--show-only", "templates/daemonset-agent.yaml")...)
	for name, out := range map[string]string{"ui": ui, "agent": agent} {
		if !strings.Contains(out, "tcp,postgres") {
			t.Errorf("%s: should render --enabled-checks tcp,postgres:\n%s", name, out)
		}
	}
}

// TestChartPostgresWithoutTokenFails proves the render fails closed when
// postgres is enabled but no agent shared token is configured.
func TestChartPostgresWithoutTokenFails(t *testing.T) {
	requireHelm(t)

	out, err := helmTemplateErr(t,
		"--set", "ui.enabledChecks={tcp,postgres}",
		"--set", "agent.enabledChecks={tcp,postgres}",
	)
	if err == nil {
		t.Fatalf("expected render to fail (postgres without agent token); got success:\n%s", out)
	}
	if !strings.Contains(out, "no agent shared token") {
		t.Errorf("expected token-required error, got:\n%s", out)
	}
}

// TestChartPostgresWithExistingSecretTokenRenders proves an out-of-band token
// Secret satisfies the token requirement for postgres.
func TestChartPostgresWithExistingSecretTokenRenders(t *testing.T) {
	requireHelm(t)

	out, err := helmTemplateErr(t,
		"--set", "ui.enabledChecks={tcp,postgres}",
		"--set", "agent.enabledChecks={tcp,postgres}",
		"--set", "agent.auth.existingSecret=my-agent-token",
	)
	if err != nil {
		t.Fatalf("existingSecret should satisfy the postgres token rule, got error:\n%s", out)
	}
}

// TestChartUICheckNotServedByAgentFails proves a check enabled on the UI but
// not the agent fails the render (the UI would fan out to a 404 endpoint).
func TestChartUICheckNotServedByAgentFails(t *testing.T) {
	requireHelm(t)

	out, err := helmTemplateErr(t,
		"--set", "ui.enabledChecks={tcp,postgres}",
		"--set", "agent.auth.token=deadbeefdeadbeef",
	)
	if err == nil {
		t.Fatalf("expected render to fail (UI offers postgres, agent does not); got success:\n%s", out)
	}
	if !strings.Contains(out, "does not serve") {
		t.Errorf("expected subset-mismatch error, got:\n%s", out)
	}
}

// TestChartDisablePostgresRateLimitFlag proves the disable toggle renders the
// flag on both workloads.
func TestChartDisablePostgresRateLimitFlag(t *testing.T) {
	requireHelm(t)

	args := []string{
		"--set", "ui.enabledChecks={tcp,postgres}",
		"--set", "agent.enabledChecks={tcp,postgres}",
		"--set", "agent.auth.token=deadbeefdeadbeef",
		"--set", "ui.disablePostgresRateLimit=true",
		"--set", "agent.disablePostgresRateLimit=true",
	}
	ui := helmTemplate(t, append(args, "--show-only", "templates/deployment-ui.yaml")...)
	agent := helmTemplate(t, append(args, "--show-only", "templates/daemonset-agent.yaml")...)
	for name, out := range map[string]string{"ui": ui, "agent": agent} {
		if !strings.Contains(out, "--disable-postgres-rate-limit") {
			t.Errorf("%s: should render --disable-postgres-rate-limit:\n%s", name, out)
		}
	}
}
