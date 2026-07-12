package checkapi

import (
	"strings"
	"testing"
)

func TestParseEnabledChecksDefault(t *testing.T) {
	e, err := ParseEnabledChecks(DefaultEnabledChecks)
	if err != nil {
		t.Fatalf("ParseEnabledChecks(%q): %v", DefaultEnabledChecks, err)
	}
	if !e.Has(CheckTCP) {
		t.Error("default should enable tcp")
	}
	if e.Has(CheckPostgres) {
		t.Error("default should not enable postgres")
	}
}

func TestParseEnabledChecksCSV(t *testing.T) {
	cases := []struct {
		name       string
		csv        string
		wantTCP    bool
		wantPG     bool
		wantErrSub string // non-empty means an error is expected containing this substring
	}{
		{name: "tcp only", csv: "tcp", wantTCP: true},
		{name: "postgres only", csv: "postgres", wantPG: true},
		{name: "both", csv: "tcp,postgres", wantTCP: true, wantPG: true},
		{name: "spaces trimmed", csv: " tcp , postgres ", wantTCP: true, wantPG: true},
		{name: "duplicates collapse", csv: "tcp,tcp,postgres,postgres", wantTCP: true, wantPG: true},
		{name: "empty entries skipped", csv: "tcp,,postgres,", wantTCP: true, wantPG: true},
		{name: "all blank", csv: " , , "},
		{name: "empty string", csv: ""},
		{name: "unknown name", csv: "tcp,mysql", wantErrSub: `"mysql"`},
		{name: "unknown only", csv: "bogus", wantErrSub: `"bogus"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := ParseEnabledChecks(tc.csv)
			if tc.wantErrSub != "" {
				if err == nil {
					t.Fatalf("ParseEnabledChecks(%q): expected error, got nil", tc.csv)
				}
				if !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Fatalf("ParseEnabledChecks(%q) error = %q, want substring %q", tc.csv, err.Error(), tc.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEnabledChecks(%q): unexpected error: %v", tc.csv, err)
			}
			if got := e.Has(CheckTCP); got != tc.wantTCP {
				t.Errorf("ParseEnabledChecks(%q).Has(tcp) = %v, want %v", tc.csv, got, tc.wantTCP)
			}
			if got := e.Has(CheckPostgres); got != tc.wantPG {
				t.Errorf("ParseEnabledChecks(%q).Has(postgres) = %v, want %v", tc.csv, got, tc.wantPG)
			}
		})
	}
}

func TestEnabledChecksTCPCanBeDisabled(t *testing.T) {
	e, err := ParseEnabledChecks("postgres")
	if err != nil {
		t.Fatalf("ParseEnabledChecks: %v", err)
	}
	if e.Has(CheckTCP) {
		t.Error("tcp should be disabled when not listed")
	}
	if !e.Has(CheckPostgres) {
		t.Error("postgres should be enabled")
	}
}

func TestRequireNonEmpty(t *testing.T) {
	cases := []struct {
		name    string
		csv     string
		wantErr bool
	}{
		{"tcp only", "tcp", false},
		{"postgres only", "postgres", false},
		{"both", "tcp,postgres", false},
		{"empty string", "", true},
		{"all blank entries", " , , ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := ParseEnabledChecks(tc.csv)
			if err != nil {
				t.Fatalf("ParseEnabledChecks(%q): %v", tc.csv, err)
			}
			err = e.RequireNonEmpty()
			if (err != nil) != tc.wantErr {
				t.Fatalf("RequireNonEmpty() for %q: error = %v, wantErr %v", tc.csv, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "at least one check must be enabled") {
				t.Errorf("error should explain the requirement, got %q", err.Error())
			}
		})
	}
}

func TestRequireTokenForPostgres(t *testing.T) {
	tcpOnly, err := ParseEnabledChecks("tcp")
	if err != nil {
		t.Fatalf("ParseEnabledChecks: %v", err)
	}
	if err := tcpOnly.RequireTokenForPostgres("", "--auth-token", "PORTREACH_AGENT_TOKEN"); err != nil {
		t.Errorf("tcp-only should not require a token: %v", err)
	}

	withPG, err := ParseEnabledChecks("tcp,postgres")
	if err != nil {
		t.Fatalf("ParseEnabledChecks: %v", err)
	}
	if err := withPG.RequireTokenForPostgres("", "--auth-token", "PORTREACH_AGENT_TOKEN"); err == nil {
		t.Fatal("postgres enabled with empty token should error")
	} else {
		if !strings.Contains(err.Error(), "--auth-token") || !strings.Contains(err.Error(), "PORTREACH_AGENT_TOKEN") {
			t.Errorf("error should name the flag and env var, got %q", err.Error())
		}
	}
	if err := withPG.RequireTokenForPostgres("  ", "--auth-token", "PORTREACH_AGENT_TOKEN"); err == nil {
		t.Fatal("whitespace-only token should be treated as unset")
	}
	if err := withPG.RequireTokenForPostgres("s3cr3t", "--auth-token", "PORTREACH_AGENT_TOKEN"); err != nil {
		t.Errorf("postgres enabled with a token set should not error: %v", err)
	}
}
