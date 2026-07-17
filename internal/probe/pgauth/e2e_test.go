//go:build e2e

// This suite exercises the real pgconn-backed Connector against a REAL
// PostgreSQL server. It is excluded from the default build by the `e2e` tag, so
// `go test ./...` never needs Docker or a database. Run it with:
//
//	go test -tags e2e ./internal/probe/pgauth/    (or: make test-e2e)
//
// Point it at a server via the environment (a docker-run PostgreSQL is easiest):
//
//	PORTREACH_TEST_PG_HOST=127.0.0.1
//	PORTREACH_TEST_PG_PORT=5432
//	PORTREACH_TEST_PG_USER=postgres
//	PORTREACH_TEST_PG_PASSWORD=secret
//	PORTREACH_TEST_PG_DB=postgres              (optional; defaults to the user)
//
// Any test whose required variables are unset is skipped, so a partial
// environment still runs what it can. TLS assertions additionally need:
//
//	PORTREACH_TEST_PG_TLS=1                     (server presents a cert)
//	PORTREACH_TEST_PG_TLS_SERVERNAME=...        (name on the cert, optional)
package pgauth

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/lavr/portreach/internal/checkapi"
)

func pgEnv(t *testing.T) (host string, port int, user, password, db string) {
	t.Helper()
	host = os.Getenv("PORTREACH_TEST_PG_HOST")
	user = os.Getenv("PORTREACH_TEST_PG_USER")
	password = os.Getenv("PORTREACH_TEST_PG_PASSWORD")
	if host == "" || user == "" || password == "" {
		t.Skip("set PORTREACH_TEST_PG_HOST/USER/PASSWORD to run the pgauth e2e suite")
	}
	port = 5432
	if p := os.Getenv("PORTREACH_TEST_PG_PORT"); p != "" {
		v, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("invalid PORTREACH_TEST_PG_PORT: %v", err)
		}
		port = v
	}
	db = os.Getenv("PORTREACH_TEST_PG_DB")
	return host, port, user, password, db
}

func e2eDeadline() time.Time { return time.Now().Add(10 * time.Second) }

// TestE2EAuthSuccess: valid credentials authenticate and SELECT 1 succeeds; the
// server reports a non-empty server_version.
func TestE2EAuthSuccess(t *testing.T) {
	host, port, user, password, db := pgEnv(t)
	off := false
	res := Connector{}.Probe(context.Background(), host, port,
		checkapi.Credentials{Username: user, Password: password, Database: db},
		&checkapi.TLSOptions{Enabled: &off}, plainDial(), e2eDeadline())

	if !res.OK || res.Code != "" {
		t.Fatalf("expected auth OK, got %+v", res)
	}
	if res.ServerVersion == "" {
		t.Error("expected a non-empty server_version")
	}
}

// TestE2EWrongPassword: a bad password is rejected as auth_rejected.
func TestE2EWrongPassword(t *testing.T) {
	host, port, user, _, db := pgEnv(t)
	off := false
	res := Connector{}.Probe(context.Background(), host, port,
		checkapi.Credentials{Username: user, Password: "definitely-not-the-password", Database: db},
		&checkapi.TLSOptions{Enabled: &off}, plainDial(), e2eDeadline())

	if res.OK || res.Code != checkapi.CodeAuthRejected {
		t.Fatalf("expected auth_rejected, got %+v", res)
	}
}

// TestE2ETLSDisabled: an explicit TLS-off connection authenticates.
func TestE2ETLSDisabled(t *testing.T) {
	host, port, user, password, db := pgEnv(t)
	off := false
	res := Connector{}.Probe(context.Background(), host, port,
		checkapi.Credentials{Username: user, Password: password, Database: db},
		&checkapi.TLSOptions{Enabled: &off}, plainDial(), e2eDeadline())
	if !res.OK {
		t.Fatalf("expected auth OK with TLS disabled, got %+v", res)
	}
}

// TestE2ETLSValid: with TLS on and verification against the presented cert, the
// probe succeeds. Requires PORTREACH_TEST_PG_TLS=1 and a verifiable cert
// (server_name via PORTREACH_TEST_PG_TLS_SERVERNAME when it differs from host).
func TestE2ETLSValid(t *testing.T) {
	host, port, user, password, db := pgEnv(t)
	if os.Getenv("PORTREACH_TEST_PG_TLS") != "1" {
		t.Skip("set PORTREACH_TEST_PG_TLS=1 (with a verifiable server cert) to run the TLS-valid e2e test")
	}
	opts := &checkapi.TLSOptions{}
	if sn := os.Getenv("PORTREACH_TEST_PG_TLS_SERVERNAME"); sn != "" {
		opts.ServerName = sn
	}
	res := Connector{}.Probe(context.Background(), host, port,
		checkapi.Credentials{Username: user, Password: password, Database: db},
		opts, plainDial(), e2eDeadline())
	if !res.OK {
		t.Fatalf("expected auth OK over verified TLS, got %+v", res)
	}
}

// TestE2ETLSInvalidCert: verifying against the default trust store when the
// server presents an untrusted/self-signed cert fails as tls_error (no silent
// plaintext fallback). Uses a ServerName the cert will not match / a chain the
// system store will not trust.
func TestE2ETLSInvalidCert(t *testing.T) {
	host, port, user, password, db := pgEnv(t)
	if os.Getenv("PORTREACH_TEST_PG_TLS") != "1" {
		t.Skip("set PORTREACH_TEST_PG_TLS=1 to run the TLS-invalid e2e test")
	}
	// Force a verification failure by demanding a server name the cert cannot
	// present while keeping InsecureSkipVerify off.
	res := Connector{}.Probe(context.Background(), host, port,
		checkapi.Credentials{Username: user, Password: password, Database: db},
		&checkapi.TLSOptions{ServerName: "wrong.invalid.example"}, plainDial(), e2eDeadline())
	if res.OK || res.Code != checkapi.CodeTLSError {
		t.Fatalf("expected tls_error against an unverifiable cert, got %+v", res)
	}
}
