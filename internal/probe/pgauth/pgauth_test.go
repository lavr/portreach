package pgauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/lavr/portreach/internal/checkapi"
)

// canaryPassword is a distinctive secret used across the redaction tests: it must
// never appear in any Reason a mapped error produces.
const canaryPassword = "s3cr3t-canary-pw-8f21"

// --- error → code mapping (synthetic, pure) ----------------------------------

func TestClassifyConnectError(t *testing.T) {
	// A pgconn failure is normally reached wrapped several layers deep; wrap the
	// synthetic ones so the tests exercise the real errors.As unwrap chain
	// (pgconn's own wrappers implement Unwrap, so a %w chain is faithful here).
	wrap := func(err error) error {
		return fmt.Errorf("failed to connect to `user=u database=d`: %w", err)
	}

	cases := []struct {
		name     string
		err      error
		wantCode string
	}{
		{
			name:     "auth rejected 28P01",
			err:      wrap(&pgconn.PgError{Code: "28P01", Message: "password authentication failed for user \"u\""}),
			wantCode: checkapi.CodeAuthRejected,
		},
		{
			name:     "auth rejected 28000",
			err:      wrap(&pgconn.PgError{Code: "28000", Message: "no pg_hba.conf entry"}),
			wantCode: checkapi.CodeAuthRejected,
		},
		{
			// Any class-28 SQLSTATE is an authorization failure.
			name:     "auth rejected class 28 generic",
			err:      wrap(&pgconn.PgError{Code: "28123", Message: "invalid authorization"}),
			wantCode: checkapi.CodeAuthRejected,
		},
		{
			// A non-28 server error is a protocol-level failure, not a credential
			// rejection.
			name:     "non-28 server error",
			err:      wrap(&pgconn.PgError{Code: "3D000", Message: "database \"x\" does not exist"}),
			wantCode: checkapi.CodeProtocolError,
		},
		{
			name:     "tls certificate verification",
			err:      wrap(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}),
			wantCode: checkapi.CodeTLSError,
		},
		{
			name:     "x509 unknown authority",
			err:      wrap(x509.UnknownAuthorityError{}),
			wantCode: checkapi.CodeTLSError,
		},
		{
			name:     "server refused TLS",
			err:      wrap(errors.New("server refused TLS connection")),
			wantCode: checkapi.CodeTLSError,
		},
		{
			name:     "gss unsupported",
			err:      wrap(fmt.Errorf("failed GSS auth: %w", errors.New("kerberos error: no GSSAPI provider registered"))),
			wantCode: checkapi.CodeUnsupportedAuth,
		},
		{
			// A server credential rejection is authoritative even when its message
			// mentions a mechanism name — the typed class-28 SQLSTATE must win over
			// the client-side unsupported-auth substring heuristic.
			name:     "class-28 mentioning GSSAPI stays auth_rejected",
			err:      wrap(&pgconn.PgError{Code: "28000", Message: "GSSAPI authentication failed for user \"u\""}),
			wantCode: checkapi.CodeAuthRejected,
		},
		{
			name:     "generic dial error",
			err:      wrap(&net.OpError{Op: "dial", Err: errors.New("connection refused")}),
			wantCode: checkapi.CodeProtocolError,
		},
		{
			name:     "context deadline",
			err:      wrap(context.DeadlineExceeded),
			wantCode: checkapi.CodeProtocolError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, reason := classifyConnectError(tc.err)
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q (reason=%q)", code, tc.wantCode, reason)
			}
			if reason == "" {
				t.Errorf("reason must not be empty for %q", tc.wantCode)
			}
		})
	}
}

// TestClassifyRedaction: no reason a mapped error produces ever contains the
// canary password. classifyConnectError never receives the password (it is
// structurally decoupled from creds), so this guards against a future regression
// that starts interpolating a secret into a reason.
func TestClassifyRedaction(t *testing.T) {
	wrap := func(err error) error {
		return fmt.Errorf("failed to connect to `user=u database=d`: %w", err)
	}
	errsByCase := []error{
		wrap(&pgconn.PgError{Code: "28P01", Message: "password authentication failed"}),
		wrap(&pgconn.PgError{Code: "3D000", Message: "database does not exist"}),
		wrap(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}),
		wrap(errors.New("server refused TLS connection")),
		wrap(fmt.Errorf("failed GSS auth: %w", errors.New("kerberos error: no provider"))),
		wrap(&net.OpError{Op: "dial", Err: errors.New("connection refused")}),
	}
	for _, err := range errsByCase {
		_, reason := classifyConnectError(err)
		if strings.Contains(reason, canaryPassword) {
			t.Fatalf("reason leaked the password: %q", reason)
		}
	}
	// describeErr (used for the query_failed reason) must not leak it either.
	if got := describeErr(&pgconn.PgError{Code: "42601", Message: "syntax error"}); strings.Contains(got, canaryPassword) {
		t.Fatalf("describeErr leaked the password: %q", got)
	}
}

// --- TLS config construction --------------------------------------------------

func TestTLSConfigFor(t *testing.T) {
	t.Run("default is verify-on with ServerName from host", func(t *testing.T) {
		cfg := tlsConfigFor(nil, "db.internal")
		if cfg == nil {
			t.Fatal("nil TLSOptions must default TLS on")
		}
		if cfg.InsecureSkipVerify {
			t.Error("default must verify certificates")
		}
		if cfg.ServerName != "db.internal" {
			t.Errorf("ServerName = %q, want db.internal", cfg.ServerName)
		}
	})

	t.Run("disabled yields nil config", func(t *testing.T) {
		off := false
		if cfg := tlsConfigFor(&checkapi.TLSOptions{Enabled: &off}, "db.internal"); cfg != nil {
			t.Errorf("Enabled=false must yield a nil *tls.Config, got %+v", cfg)
		}
	})

	t.Run("insecure_skip_verify honored only when set", func(t *testing.T) {
		cfg := tlsConfigFor(&checkapi.TLSOptions{InsecureSkipVerify: true}, "db.internal")
		if cfg == nil || !cfg.InsecureSkipVerify {
			t.Fatalf("InsecureSkipVerify not honored: %+v", cfg)
		}
	})

	t.Run("explicit ServerName overrides host", func(t *testing.T) {
		cfg := tlsConfigFor(&checkapi.TLSOptions{ServerName: "override.example"}, "db.internal")
		if cfg == nil || cfg.ServerName != "override.example" {
			t.Fatalf("ServerName override not applied: %+v", cfg)
		}
	})
}

// --- real-pgconn wiring against loopback fakes --------------------------------
//
// These use the REAL pgconn client against a tiny in-process server speaking just
// enough of the wire protocol to drive one outcome. They are hermetic (loopback,
// no external DB) and prove the Connector's ConnectConfig / DialFunc / Exec
// plumbing, not the SCRAM math (a trust-auth server needs no password exchange).

// TestConnectorSuccessAndQueryPaths exercises the two post-connect outcomes.
func TestConnectorSuccessAndQueryPaths(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		host, port := startFakePG(t, fakePG{serverVersion: "16.4"})
		res := probeLocal(t, host, port)
		if !res.OK || res.Code != "" {
			t.Fatalf("expected auth OK, got %+v", res)
		}
		if res.ServerVersion != "16.4" {
			t.Errorf("ServerVersion = %q, want 16.4", res.ServerVersion)
		}
		if res.MS <= 0 {
			t.Errorf("expected positive MS, got %v", res.MS)
		}
	})

	t.Run("query failed", func(t *testing.T) {
		host, port := startFakePG(t, fakePG{serverVersion: "16.4", failQuery: true})
		res := probeLocal(t, host, port)
		if res.OK || res.Code != checkapi.CodeQueryFailed {
			t.Fatalf("expected query_failed, got %+v", res)
		}
		// server_version is still captured on a post-auth query failure.
		if res.ServerVersion != "16.4" {
			t.Errorf("ServerVersion = %q, want 16.4", res.ServerVersion)
		}
	})
}

// TestConnectorAuthRejected: a server that answers the startup with an
// ErrorResponse (28P01) surfaces as auth_rejected — and the canary password the
// client would have used never appears in the reason.
func TestConnectorAuthRejected(t *testing.T) {
	host, port := startFakePG(t, fakePG{rejectAuth: true})
	res := probeLocal(t, host, port)
	if res.OK || res.Code != checkapi.CodeAuthRejected {
		t.Fatalf("expected auth_rejected, got %+v", res)
	}
	if strings.Contains(res.Reason, canaryPassword) {
		t.Fatalf("auth_rejected reason leaked the password: %q", res.Reason)
	}
}

// TestConnectorTLSRefused: TLS is required (default) but the server refuses the
// SSLRequest → tls_error, with no silent plaintext fallback (Fallbacks nil).
func TestConnectorTLSRefused(t *testing.T) {
	host, port := startFakePG(t, fakePG{refuseSSL: true})
	// nil TLSOptions = secure default (TLS on + verify).
	res := Connector{}.Probe(context.Background(), host, port, credsWithCanary(), nil, plainDial(), time.Now().Add(2*time.Second))
	if res.OK || res.Code != checkapi.CodeTLSError {
		t.Fatalf("expected tls_error, got %+v", res)
	}
}

// TestConnectorDialRefused: a closed port → protocol_error (a dial failure is not
// an auth failure).
func TestConnectorDialRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close() // free the port

	res := probeLocal(t, "127.0.0.1", port)
	if res.OK || res.Code != checkapi.CodeProtocolError {
		t.Fatalf("expected protocol_error on a refused dial, got %+v", res)
	}
	if strings.Contains(res.Reason, canaryPassword) {
		t.Fatalf("protocol_error reason leaked the password: %q", res.Reason)
	}
}

// TestConnectorRespectsDialFunc: the Connector dials only through the supplied
// DialFunc. A DialFunc that always refuses must make the probe fail without any
// real network connection to the (live) server.
func TestConnectorRespectsDialFunc(t *testing.T) {
	host, port := startFakePG(t, fakePG{})
	sentinel := errors.New("dial refused by test")
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) { return nil, sentinel }

	res := Connector{}.Probe(context.Background(), host, port, credsWithCanary(),
		&checkapi.TLSOptions{Enabled: boolPtr(false)}, dial, time.Now().Add(2*time.Second))
	if res.OK {
		t.Fatalf("probe succeeded despite a refusing DialFunc: %+v", res)
	}
	if res.Code != checkapi.CodeProtocolError {
		t.Errorf("Code = %q, want protocol_error", res.Code)
	}
}

// --- helpers ------------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }

// plainDial is an unguarded net.Dialer.DialContext (net.Dialer.DialContext has a
// pointer receiver, so it needs an addressable value).
func plainDial() DialFunc {
	var d net.Dialer
	return d.DialContext
}

func credsWithCanary() checkapi.Credentials {
	return checkapi.Credentials{Username: "user", Password: canaryPassword, Database: "app"}
}

// probeLocal runs the Connector against a plaintext (TLS-disabled) loopback
// server with a short deadline.
func probeLocal(t *testing.T, host string, port int) checkapi.AuthResult {
	t.Helper()
	return Connector{}.Probe(context.Background(), host, port, credsWithCanary(),
		&checkapi.TLSOptions{Enabled: boolPtr(false)}, plainDial(), time.Now().Add(3*time.Second))
}
