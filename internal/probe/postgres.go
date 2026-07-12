package probe

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/lavr/portreach/internal/checkapi"
	"github.com/lavr/portreach/internal/probe/pgauth"
)

// Postgres is the PostgreSQL runner. It shares the DNS-report + concurrent-dial
// core with the TCP runner (see connect) to establish reachability and enforce
// the metadata DenyGuard / operator policy, then, only if reachable, drives a
// PostgreSQL auth probe (login + SELECT 1) via pgauth. The dial/DNS reporting,
// the DenyGuard and the deadline discipline are identical to Run's; the addition
// is the auth handshake on a target Run would merely reach and drop.
//
// Prober is the auth seam. A zero Postgres uses the real pgconn-backed prober
// (pgauth.Connector); tests inject a fake so the wiring can be exercised without
// a PostgreSQL server.
type Postgres struct {
	Prober pgauth.Prober
}

// prober returns the configured prober or the real pgconn-backed default.
func (p Postgres) prober() pgauth.Prober {
	if p.Prober != nil {
		return p.Prober
	}
	return pgauth.Connector{}
}

// Run performs the PostgreSQL check. Its arguments mirror Run's shape (ctx,
// host, dialHosts, port, timeout, dns, guard) so a caller can invoke both
// uniformly, minus proto (fixed to "postgres") and plus the Postgres-specific
// creds/tls, which are threaded straight into the prober. It never panics:
// failures land in the returned Result rather than as an error (except invalid
// input).
//
// Result semantics:
//   - DNS failure or dial failure (no reachable address): NO auth attempt runs
//     and the Result is exactly what the TCP path would produce for that failure
//     — a connect failure is not an auth failure, so Auth stays nil.
//   - Policy/metadata denial: connect surfaces Result.Denied/DeniedReason exactly
//     as the TCP path does and returns no conn, so the prober is never invoked
//     (denial always precedes any handshake).
//   - Reachable: the pgauth prober authenticates over its own guarded dial and its
//     checkapi.AuthResult is placed in Result.Auth. The password is only threaded
//     into the prober; it is never logged and never embedded in Result (guaranteed
//     by the checkapi types).
//
// TLS defaults (nil tls → on + verify, ServerName ← host) live inside
// checkapi/pgauth; the runner passes creds/tls through untouched and never
// re-resolves TLS or logs the password.
func (p Postgres) Run(ctx context.Context, host string, dialHosts []string, port int, timeout time.Duration, dns *DNSResult, guard *DenyGuard, creds checkapi.Credentials, tls *checkapi.TLSOptions) Result {
	// Reuse the shared host/port/timeout validation and normalization. proto is
	// fixed to "postgres" for this runner; "tcp" here only satisfies Validate's
	// proto gate (Validate rejects anything else) — the returned proto is discarded.
	_, timeout, err := Validate(host, port, "tcp", timeout)
	res := Result{Host: host, Port: port, Proto: "postgres"}
	if err != nil {
		res.Error = err.Error()
		return res
	}

	// The overall probe deadline covers the whole check (reachability dial + auth).
	// connect recomputes an equivalent deadline internally for the dial; computing
	// it here too lets us hand the prober only the time the reachability dial left,
	// so pgauth runs under the same budget the TCP path honours.
	deadline := time.Now().Add(timeout)

	// Reachability + policy first: connect fills res.DNS/res.TCP/res.Denied and
	// enforces the metadata DenyGuard exactly as the TCP path does. A denied or
	// unreachable target returns no conn, so the prober is never reached.
	conn := connect(ctx, host, dialHosts, port, timeout, dns, guard, &res)
	if conn == nil {
		return res
	}
	// The reachability check only needed the fact that an address opened; the auth
	// probe dials its own (guarded) connection, so close this one immediately, just
	// as the TCP runner does.
	_ = conn.Close()

	// Defense-in-depth against DNS rebinding between the reachability dial and the
	// auth dial: hand the prober a DialFunc whose Control re-applies the same
	// metadata DenyGuard. pgconn resolves host itself and dials through this func,
	// so a name that rebinds to a denied IP after the reachability check still
	// fails closed (the dial is refused → protocol_error), never reaching a denied
	// address.
	dial := guardedDial(guard)
	auth := p.prober().Probe(ctx, host, port, creds, tls, dial, deadline)
	res.Auth = &auth
	return res
}

// RunPostgres runs a PostgreSQL check with the default pgconn-backed prober. It
// is the free-function entry point for callers that do not need to inject a
// fake (e.g. the agent); tests use Postgres{Prober: fake}.Run directly.
func RunPostgres(ctx context.Context, host string, dialHosts []string, port int, timeout time.Duration, dns *DNSResult, guard *DenyGuard, creds checkapi.Credentials, tls *checkapi.TLSOptions) Result {
	return Postgres{}.Run(ctx, host, dialHosts, port, timeout, dns, guard, creds, tls)
}

// guardedDial builds the DialFunc the prober dials through. With a guard, every
// connect re-applies the same connect-time DenyGuard Control hook the shared
// dial layer uses, so a denied IP is refused before the socket connects. The hit
// flag is discarded here: this dial is pure defense-in-depth (the reachability
// dial already reported any policy denial); a refusal simply fails the auth dial
// closed. Without a guard it is a plain net.Dialer.DialContext.
func guardedDial(guard *DenyGuard) pgauth.DialFunc {
	var d net.Dialer
	if guard != nil {
		var hit atomic.Bool // discarded: fail-closed refusal is all this dial needs
		d.Control = guard.control(&hit)
	}
	return d.DialContext
}
