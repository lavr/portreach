// Package checkapi defines the JSON wire contract for protocol-specific
// reachability checks (POST /api/check/tcp, POST /api/check/postgres) shared
// by the UI and the agent. Neither side defines its own request/response
// structs — both import this package — so field names, JSON tags, and
// validation bounds cannot silently drift apart between them.
package checkapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MaxRequestBody caps the size of a check request body an HTTP handler will
// read. A check request is small (host/port/timeout, optionally postgres
// credentials); 64 KiB is generous headroom while still bounding how much an
// oversized or malicious POST body can make a handler goroutine buffer before
// rejecting it (resource-exhaustion DoS via request size).
const MaxRequestBody = 64 * 1024

// DefaultTimeout and MaxTimeout mirror internal/probe's bounds exactly (see
// probe.DefaultTimeout / probe.MaxTimeout) so a request validated here behaves
// identically once it reaches the probe. They are redefined rather than
// imported so this package stays independent of internal/probe's internals —
// only the numeric values need to match.
const (
	DefaultTimeout = 5 * time.Second
	MaxTimeout     = 30 * time.Second
)

// Duration wraps time.Duration so requests carry a human-readable duration
// string on the wire (e.g. "5s") instead of a bare integer of nanoseconds —
// friendlier for a client crafting requests by hand (curl, tests) and for
// reading captured traffic.
type Duration time.Duration

// MarshalJSON renders d as its time.Duration string form.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON parses a duration string. An empty string decodes to zero,
// leaving normalization (zero -> DefaultTimeout) to NormalizeTimeout rather
// than baking a default into the wire type itself.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid timeout %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Credentials holds the auth details for a Postgres check request. It is
// request-only: it must never be embedded in, or copied into, a response
// type (see the package-level note on AuthResult and the test in
// checkapi_test.go that guards this).
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// Database is optional: PostgreSQL defaults an unspecified database to
	// one named after the username, so an empty value is valid here and left
	// for the server to resolve.
	Database string `json:"database,omitempty"`
}

// Validate checks that c has what a Postgres auth attempt needs. Username is
// required to identify the role; Password is also required — SCRAM (postgres'
// default auth method) has no anonymous/passwordless mode this API supports.
// Database is intentionally not checked; see its doc comment.
func (c Credentials) Validate() error {
	if strings.TrimSpace(c.Username) == "" {
		return errors.New("username is required")
	}
	if c.Password == "" {
		return errors.New("password is required")
	}
	return nil
}

// TLSOptions configures how a Postgres check negotiates TLS. The zero value
// (nil Enabled, empty ServerName, false InsecureSkipVerify) is not itself the
// default — see ResolveTLS, which a nil *TLSOptions also resolves against the
// same secure-by-default rules.
type TLSOptions struct {
	// Enabled nil means "on": TLS is attempted with certificate verification.
	// Only an explicit `"enabled": false` turns TLS off, so a caller who omits
	// the field — or the whole TLS block — still gets the secure default.
	Enabled *bool `json:"enabled,omitempty"`
	// ServerName overrides the name used for certificate verification. Empty
	// resolves to the request's Host at check time (see ResolveTLS), so a
	// caller need not repeat the hostname in both fields.
	ServerName         string `json:"server_name,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

// ResolvedTLS is the effective TLS configuration for a check, after applying
// TLSOptions' defaults against the request host.
type ResolvedTLS struct {
	Enabled            bool
	ServerName         string
	InsecureSkipVerify bool
}

// ResolveTLS applies TLSOptions' defaults against host: a nil opts or a nil
// opts.Enabled means TLS is on, and an empty ServerName resolves to host.
// Callers building a *tls.Config should use this rather than reading
// TLSOptions' fields directly, so the "nil means on" and "empty means host"
// rules live in exactly one place.
func ResolveTLS(opts *TLSOptions, host string) ResolvedTLS {
	r := ResolvedTLS{Enabled: true, ServerName: host}
	if opts == nil {
		return r
	}
	if opts.Enabled != nil {
		r.Enabled = *opts.Enabled
	}
	if opts.ServerName != "" {
		r.ServerName = opts.ServerName
	}
	r.InsecureSkipVerify = opts.InsecureSkipVerify
	return r
}

// TCPCheckRequest is the body of POST /api/check/tcp.
type TCPCheckRequest struct {
	Host    string   `json:"host"`
	Port    int      `json:"port"`
	Timeout Duration `json:"timeout"`
}

// Validate checks Host and Port against the same bounds internal/probe.Validate
// enforces (see ValidateHostPort). Timeout has no invalid form — it is always
// normalized, never rejected — so it is not checked here; use EffectiveTimeout.
func (r TCPCheckRequest) Validate() error {
	return ValidateHostPort(r.Host, r.Port)
}

// EffectiveTimeout returns r.Timeout normalized per NormalizeTimeout.
func (r TCPCheckRequest) EffectiveTimeout() time.Duration {
	return NormalizeTimeout(time.Duration(r.Timeout))
}

// PostgresCheckRequest is the body of POST /api/check/postgres.
type PostgresCheckRequest struct {
	Host        string      `json:"host"`
	Port        int         `json:"port"`
	Timeout     Duration    `json:"timeout"`
	Credentials Credentials `json:"credentials"`
	// TLS is optional; a nil value resolves to the same defaults as an
	// empty TLSOptions (see ResolveTLS).
	TLS *TLSOptions `json:"tls,omitempty"`
}

// Validate checks Host, Port, and Credentials. See TCPCheckRequest.Validate
// for why Timeout is excluded.
func (r PostgresCheckRequest) Validate() error {
	if err := ValidateHostPort(r.Host, r.Port); err != nil {
		return err
	}
	return r.Credentials.Validate()
}

// EffectiveTimeout returns r.Timeout normalized per NormalizeTimeout.
func (r PostgresCheckRequest) EffectiveTimeout() time.Duration {
	return NormalizeTimeout(time.Duration(r.Timeout))
}

// EffectiveTLS resolves r.TLS against r.Host (see ResolveTLS).
func (r PostgresCheckRequest) EffectiveTLS() ResolvedTLS {
	return ResolveTLS(r.TLS, r.Host)
}

// ValidateHostPort checks host and port per the same rules
// internal/probe.Validate applies: host must be non-blank, port must be a
// valid TCP port number. Reimplemented here (rather than imported) to keep
// this package independent of internal/probe; the accepted ranges are kept
// identical by convention — see internal/probe.Validate.
func ValidateHostPort(host string, port int) error {
	if strings.TrimSpace(host) == "" {
		return errors.New("host is required")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port out of range: %d", port)
	}
	return nil
}

// NormalizeTimeout mirrors internal/probe.Validate's timeout handling: a
// non-positive value becomes DefaultTimeout, and anything over MaxTimeout is
// clamped down to it. It never errors — timeout has no invalid wire form.
func NormalizeTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultTimeout
	}
	if d > MaxTimeout {
		return MaxTimeout
	}
	return d
}

// Auth result codes. The set is stable (used by dashboards/alerting on the
// caller side), so treat it as part of the wire contract: add codes, never
// rename or repurpose an existing one.
const (
	CodeAuthRejected    = "auth_rejected"    // credentials were rejected by the server
	CodeUnsupportedAuth = "unsupported_auth" // server requested an auth method this client can't do
	CodeTLSError        = "tls_error"        // TLS negotiation or certificate verification failed
	CodeProtocolError   = "protocol_error"   // malformed/unexpected data on the wire
	CodeQueryFailed     = "query_failed"     // authenticated, but the post-auth probe query failed
)

// AuthResult reports the outcome of a protocol-level auth probe (e.g. a
// Postgres login attempt). It is a response type: it must never gain a
// password field, or embed Credentials — see the password-leak test in
// checkapi_test.go, which fails the build if that invariant is broken.
type AuthResult struct {
	OK bool `json:"ok"`
	// Code is one of the Code* constants above, empty on success (OK true).
	Code          string  `json:"code,omitempty"`
	Reason        string  `json:"reason,omitempty"`
	ServerVersion string  `json:"server_version,omitempty"`
	MS            float64 `json:"ms"`
}
