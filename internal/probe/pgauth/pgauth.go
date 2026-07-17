// Package pgauth performs a PostgreSQL authentication probe: it connects to a
// server with supplied credentials, runs a fixed SELECT 1 to confirm a usable
// session, and reports the outcome as a checkapi.AuthResult.
//
// The auth/TLS/wire handling is delegated to jackc/pgx's low-level pgconn
// (connect + auth + Exec only — not the query builder or the connection pool):
// maintaining a bespoke PostgreSQL wire protocol and tracking its CVEs is
// disproportionate maintenance for this project, so a battle-tested driver owns
// SCRAM-SHA-256 / MD5 auth, TLS, and server-version negotiation.
//
// The package is deliberately decoupled from internal/probe's SSRF DenyGuard:
// the caller passes in a DialFunc (which it can wrap with the guard's
// connect-time Control hook), so pgauth stays independently unit-testable and
// the guard remains owned by internal/probe.
package pgauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/lavr/portreach/internal/checkapi"
)

// DialFunc opens a TCP connection to a resolved address. It mirrors
// pgconn.DialFunc so the caller can supply a net.Dialer.DialContext (optionally
// carrying a connect-time DenyGuard Control hook) without importing pgconn.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Prober is the narrow seam the probe runner depends on. The real
// implementation is Connector; tests inject a fake so the runner's wiring can be
// exercised without a PostgreSQL server.
type Prober interface {
	// Probe authenticates to host:port with creds over an (optional) TLS
	// connection dialed through dial, runs SELECT 1, and returns the outcome.
	// deadline bounds the whole attempt (auth + query); it is the absolute time
	// the check must finish by, so a caller can hand the prober only the budget a
	// preceding reachability dial left. It never returns an error: every failure
	// lands in the AuthResult's Code/Reason.
	Probe(ctx context.Context, host string, port int, creds checkapi.Credentials, tlsOpts *checkapi.TLSOptions, dial DialFunc, deadline time.Time) checkapi.AuthResult
}

// Connector is the pgconn-backed Prober.
type Connector struct{}

// closeTimeout bounds the graceful Terminate + socket close after a probe. A
// fresh, short context is used (not the possibly-expired probe deadline) so a
// successful check can still send a clean Terminate, while a wedged socket can
// never make the close hang the caller.
const closeTimeout = 2 * time.Second

// Probe implements Prober against a real PostgreSQL server via pgconn.
func (Connector) Probe(ctx context.Context, host string, port int, creds checkapi.Credentials, tlsOpts *checkapi.TLSOptions, dial DialFunc, deadline time.Time) checkapi.AuthResult {
	// pgconn refuses a hand-built Config (it panics unless the config was created
	// by ParseConfig), so start from an empty DSN and override every field that
	// matters. We overwrite Host/Port/User/Password/Database/TLSConfig/DialFunc
	// explicitly, so an environment variable (PGHOST, PGPASSWORD, PGSSLMODE, …)
	// can never influence where we connect, as whom, or with what secret.
	cfg, err := pgconn.ParseConfig("")
	if err != nil {
		// ParseConfig("") only fails on a malformed environment (e.g. an invalid
		// PGCONNECT_TIMEOUT); treat that as an internal protocol error rather than
		// a server outcome.
		return checkapi.AuthResult{Code: checkapi.CodeProtocolError, Reason: "internal: could not build connection config"}
	}
	cfg.Host = host
	cfg.Port = uint16(port)
	cfg.User = creds.Username
	cfg.Password = creds.Password
	cfg.Database = creds.Database // empty is fine: PG defaults it to the user
	cfg.DialFunc = pgconn.DialFunc(dial)
	cfg.TLSConfig = tlsConfigFor(tlsOpts, host)
	// Never silently downgrade. pgconn's fallback chain is what retries a TLS
	// connection as plaintext (or a lower protocol); clearing it guarantees that a
	// TLS-requested probe fails closed with a tls_error instead of quietly
	// re-connecting without encryption.
	cfg.Fallbacks = nil
	// Bound the connect on the remaining budget from the probe deadline.
	cfg.ConnectTimeout = time.Until(deadline)

	connCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	start := time.Now()
	pgConn, err := pgconn.ConnectConfig(connCtx, cfg)
	if err != nil {
		code, reason := classifyConnectError(err)
		return checkapi.AuthResult{Code: code, Reason: reason, MS: msSince(start)}
	}
	defer func() {
		closeCtx, cancelClose := context.WithTimeout(context.Background(), closeTimeout)
		defer cancelClose()
		_ = pgConn.Close(closeCtx)
	}()

	// server_version is a startup ParameterStatus, available as soon as the
	// connection is authenticated.
	serverVersion := pgConn.ParameterStatus("server_version")

	// A fixed SELECT 1 confirms an authenticated session can actually run a query
	// (no user-supplied SQL, ever). A failure here is post-auth, so it is a query
	// failure, not an auth rejection.
	if _, err := pgConn.Exec(connCtx, "SELECT 1").ReadAll(); err != nil {
		return checkapi.AuthResult{Code: checkapi.CodeQueryFailed, Reason: "SELECT 1 failed: " + describeErr(err), ServerVersion: serverVersion, MS: msSince(start)}
	}
	return checkapi.AuthResult{OK: true, ServerVersion: serverVersion, MS: msSince(start)}
}

// tlsConfigFor derives pgconn's *tls.Config from the request's TLSOptions using
// checkapi's resolver, so the "nil means on", "empty ServerName means host", and
// "verify by default" rules live in exactly one place. A disabled block yields a
// nil *tls.Config (pgconn reads nil as "no TLS").
func tlsConfigFor(opts *checkapi.TLSOptions, host string) *tls.Config {
	r := checkapi.ResolveTLS(opts, host)
	if !r.Enabled {
		return nil
	}
	return &tls.Config{
		ServerName:         r.ServerName,
		InsecureSkipVerify: r.InsecureSkipVerify, //nolint:gosec // only when explicitly requested per-check; default keeps verification on
		MinVersion:         tls.VersionTLS12,
	}
}

// classifyConnectError maps a pgconn connect/auth failure to a stable
// AuthResult code and a secret-free reason. It is pure and unit-tested against
// synthetic errors. The password never reaches this function, and the reasons it
// builds are fixed strings plus server-supplied SQLSTATE/message text (which
// never echoes the client password), so no secret can leak through a reason.
func classifyConnectError(err error) (code, reason string) {
	// TLS first: startTLS hands back a tls.Conn without completing the handshake,
	// so a certificate/verification failure can surface under a later pgconn stage
	// (e.g. "failed to write startup message") rather than its "tls error" prefix.
	// Match the typed error through the unwrap chain, not the wording.
	if isTLSError(err) {
		return checkapi.CodeTLSError, "TLS handshake or certificate verification failed"
	}
	// A server-reported error carries a SQLSTATE and is authoritative — check it
	// before the client-side unsupported-auth heuristic below, so a class-28
	// credential rejection whose message happens to mention a mechanism (e.g.
	// "GSSAPI") is still reported as auth_rejected, not unsupported_auth. Class 28
	// ("invalid authorization specification", e.g. 28P01/28000) is a credential
	// rejection; any other SQLSTATE the server rejected during connect is a
	// protocol-level error.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if strings.HasPrefix(pgErr.Code, "28") {
			return checkapi.CodeAuthRejected, "authentication rejected (" + pgErr.Code + "): " + pgErr.Message
		}
		return checkapi.CodeProtocolError, "server error (" + pgErr.Code + "): " + pgErr.Message
	}
	// GSSAPI/SSPI (Kerberos) cannot be completed offline by pgconn: it needs a
	// registered provider. This is a client-side pgconn error (not a server
	// PgError), matched heuristically on the mechanism name, so it runs after the
	// authoritative SQLSTATE check above. Name the mechanism so the operator
	// knows why.
	if isUnsupportedAuth(err) {
		return checkapi.CodeUnsupportedAuth, "server requested an authentication mechanism this probe cannot complete (GSSAPI/SSPI)"
	}
	// Everything else — dial failure, framing error, timeout — is a protocol
	// error. pgconn never embeds the password in its error strings, so surfacing
	// the normalized text here is safe.
	return checkapi.CodeProtocolError, "connection failed: " + describeErr(err)
}

// isTLSError reports whether err is (or wraps) a TLS/certificate failure, or
// pgconn's plaintext-refusal sentinel.
func isTLSError(err error) bool {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}
	var recErr tls.RecordHeaderError
	if errors.As(err, &recErr) {
		return true
	}
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return true
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return true
	}
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		return true
	}
	// pgconn refuses a plaintext server for a TLS-required probe with a plain
	// error (no typed value to match), and lower-level tls package errors render
	// with a "tls:" prefix — catch both by wording as a fallback.
	msg := err.Error()
	return strings.Contains(msg, "server refused TLS connection") || strings.Contains(msg, "tls:")
}

// isUnsupportedAuth reports whether the failure was a GSSAPI/SSPI/Kerberos
// mechanism pgconn cannot complete offline. pgconn surfaces these with distinct
// wording ("failed GSS auth", "kerberos error: no GSSAPI provider registered")
// and no typed error, so this matches on the mechanism name.
func isUnsupportedAuth(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "GSS") || strings.Contains(msg, "kerberos") || strings.Contains(msg, "SSPI")
}

// describeErr renders err into a stable, secret-free string. A server PgError is
// reduced to its SQLSTATE + message; anything else uses its error text. pgconn
// keeps the client password out of every error it produces, so neither branch
// can leak it.
func describeErr(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code + " " + pgErr.Message
	}
	return err.Error()
}

// msSince returns elapsed milliseconds since t, rounded to 0.1ms — matching
// internal/probe's latency reporting.
func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}
