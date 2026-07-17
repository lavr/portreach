package checkapi

import (
	"errors"
	"fmt"
	"strings"
)

// CheckName identifies a protocol check kind an agent can serve and a UI can
// request. Kept as a distinct type (rather than a bare string) so a typo'd
// literal doesn't silently compile where an EnabledChecks lookup is expected.
type CheckName string

// The full set of valid check names. Adding a new protocol means adding a
// name here and to validCheckNames below — everything else (CLI flag,
// fail-closed rules) is driven off this set.
const (
	CheckTCP      CheckName = "tcp"
	CheckPostgres CheckName = "postgres"
)

// validCheckNames is the membership test ParseEnabledChecks uses to reject an
// unknown name at startup rather than let it silently do nothing.
var validCheckNames = map[CheckName]bool{
	CheckTCP:      true,
	CheckPostgres: true,
}

// DefaultEnabledChecks is the --enabled-checks value both binaries use when
// the operator sets nothing: TCP-only, which is every previously-released
// version's sole behaviour, so upgrading a running deployment changes nothing
// until the operator opts into more.
const DefaultEnabledChecks = "tcp"

// EnabledChecks is the parsed, validated set of checks a binary was
// configured to enable via --enabled-checks. It gates which check endpoints
// an agent registers and which check kinds a UI will offer (Task 6/7) — it
// does not govern /healthz or /metrics, which stay available regardless.
type EnabledChecks struct {
	set map[CheckName]bool
}

// ParseEnabledChecks parses a comma-separated --enabled-checks value (e.g.
// "tcp,postgres") into an EnabledChecks set. Entries are trimmed; empty
// entries (from "", trailing/leading/doubled commas) and duplicates are
// dropped cleanly rather than erroring, since they carry no ambiguity about
// operator intent. An unknown name does carry that ambiguity — it is most
// likely a typo of a real check name — so it is a startup configuration
// error naming the bad value, rather than a silently-ignored no-op.
func ParseEnabledChecks(csv string) (EnabledChecks, error) {
	set := make(map[CheckName]bool)
	for _, raw := range strings.Split(csv, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		cn := CheckName(name)
		if !validCheckNames[cn] {
			return EnabledChecks{}, fmt.Errorf("enabled-checks: unknown check %q (valid: tcp, postgres)", name)
		}
		set[cn] = true
	}
	return EnabledChecks{set: set}, nil
}

// Has reports whether name is in the enabled set.
func (e EnabledChecks) Has(name CheckName) bool {
	return e.set[name]
}

// RequireNonEmpty enforces that at least one check is enabled. A blank
// --enabled-checks value (e.g. "" or a string of bare commas) parses without
// error — see ParseEnabledChecks, which drops empty entries as unambiguous
// rather than erroring — but Task 6 wired the agent's routing directly off
// Has(name): registering zero check endpoints is not a valid "serve nothing"
// deployment, it is almost certainly a configuration mistake (an operator
// meant to set a value and didn't), so it must fail fast at startup rather
// than silently come up with no check endpoint at all.
func (e EnabledChecks) RequireNonEmpty() error {
	if len(e.set) == 0 {
		return errors.New("enabled-checks: at least one check must be enabled")
	}
	return nil
}

// RequireTokenForPostgres enforces the fail-closed rule shared by both
// binaries: enabling the postgres check without a shared token configured
// would let a Postgres credential-probe request flow through un-authenticated
// end to end (the agent would accept it from anyone; the UI would forward
// credentials to an agent with nothing proving who's allowed to ask it to
// dial out). So rather than defaulting to "open" like the checks themselves,
// postgres demands the token be set explicitly — a startup configuration
// error names exactly which flag to set when it isn't. token is the
// caller's already-resolved value (agent: --auth-token; UI: --agent-token);
// flagName/envName are named in the error for whichever binary is calling.
func (e EnabledChecks) RequireTokenForPostgres(token, flagName, envName string) error {
	if !e.Has(CheckPostgres) {
		return nil
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("enabled-checks: postgres is enabled but %s (env %s) is not set — postgres checks require a shared token", flagName, envName)
	}
	return nil
}
