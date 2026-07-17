package probe

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lavr/portreach/internal/checkapi"
	"github.com/lavr/portreach/internal/probe/pgauth"
)

// These runner tests prove WIRING, not protocol: pgauth's own tests cover the
// pgconn error→code mapping and TLS-config construction. Here we only confirm the
// runner runs the shared reachability dial first, invokes the prober with the
// right arguments on a reachable target, lands the AuthResult in Result.Auth, and
// never invokes the prober on denial or dial failure.

// fakeProber is an injectable Prober that records its arguments and returns a
// preset AuthResult (or one computed per call). It is concurrency-safe so the
// -race runner test can share one across goroutines.
type fakeProber struct {
	mu                sync.Mutex
	calls             int
	gotHost           string
	gotPort           int
	gotCreds          checkapi.Credentials
	gotTLS            *checkapi.TLSOptions
	gotDial           pgauth.DialFunc
	gotBudgetPositive bool

	result checkapi.AuthResult
}

func (f *fakeProber) Probe(ctx context.Context, host string, port int, creds checkapi.Credentials, tlsOpts *checkapi.TLSOptions, dial pgauth.DialFunc, deadline time.Time) checkapi.AuthResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.gotHost = host
	f.gotPort = port
	f.gotCreds = creds
	f.gotTLS = tlsOpts
	f.gotDial = dial
	f.gotBudgetPositive = time.Until(deadline) > 0
	return f.result
}

func (f *fakeProber) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func pgBoolPtr(b bool) *bool { return &b }

func pgCreds() checkapi.Credentials {
	return checkapi.Credentials{Username: "user", Password: "pencil", Database: "app"}
}

// pgDNS is a pre-resolved DNS report pinning the dial to host, mirroring how the
// agent passes an already-vetted result. Passing it keeps a test hermetic (no
// real resolver query) and deterministic — the system resolver's concurrency
// limit otherwise flakes tests that dial many connections at once.
func pgDNS(host string) *DNSResult { return &DNSResult{Resolved: []string{host}} }

// TestRunPostgresSuccess: a reachable target drives the prober and its AuthResult
// (OK, ServerVersion, MS) lands in Result.Auth. TCP/DNS are populated like the
// TCP path; no denial. The prober is invoked exactly once with the request's
// host/port/creds/tls and a positive time budget.
func TestRunPostgresSuccess(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	fp := &fakeProber{result: checkapi.AuthResult{OK: true, ServerVersion: "16.3", MS: 12.5}}
	tls := &checkapi.TLSOptions{Enabled: pgBoolPtr(false)}
	res := Postgres{Prober: fp}.Run(context.Background(), "127.0.0.1", []string{"127.0.0.1"}, port, 3*time.Second, pgDNS("127.0.0.1"), nil, pgCreds(), tls)

	if res.Proto != "postgres" {
		t.Errorf("Proto = %q, want postgres", res.Proto)
	}
	if res.TCP == nil || !res.TCP.OK {
		t.Fatalf("expected a successful TCP dial, got %+v", res.TCP)
	}
	if res.Denied {
		t.Errorf("unexpected denial: %+v", res)
	}
	if res.Auth == nil || !res.Auth.OK {
		t.Fatalf("expected auth OK in Result.Auth, got %+v", res.Auth)
	}
	if res.Auth.ServerVersion != "16.3" {
		t.Errorf("ServerVersion = %q, want 16.3", res.Auth.ServerVersion)
	}
	if fp.callCount() != 1 {
		t.Fatalf("prober invoked %d times, want 1", fp.callCount())
	}
	if fp.gotHost != "127.0.0.1" || fp.gotPort != port {
		t.Errorf("prober got host/port %q/%d, want 127.0.0.1/%d", fp.gotHost, fp.gotPort, port)
	}
	if fp.gotCreds != pgCreds() {
		t.Errorf("prober got creds %+v, want %+v", fp.gotCreds, pgCreds())
	}
	if fp.gotTLS != tls {
		t.Errorf("prober did not receive the request's TLS options")
	}
	if fp.gotDial == nil {
		t.Errorf("prober did not receive a DialFunc")
	}
	if !fp.gotBudgetPositive {
		t.Errorf("prober received a non-positive time budget")
	}
}

// TestRunPostgresFailureCodes: each AuthResult.Code the prober can return
// surfaces verbatim into Result.Auth (the runner does not reinterpret the code).
func TestRunPostgresFailureCodes(t *testing.T) {
	codes := []string{
		checkapi.CodeAuthRejected,
		checkapi.CodeTLSError,
		checkapi.CodeProtocolError,
		checkapi.CodeQueryFailed,
		checkapi.CodeUnsupportedAuth,
	}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			ln, port := listenLocal(t)
			defer ln.Close() //nolint:errcheck // best-effort close

			fp := &fakeProber{result: checkapi.AuthResult{Code: code, Reason: "r"}}
			res := Postgres{Prober: fp}.Run(context.Background(), "127.0.0.1", []string{"127.0.0.1"}, port, 3*time.Second, pgDNS("127.0.0.1"), nil, pgCreds(), nil)

			if res.TCP == nil || !res.TCP.OK {
				t.Fatalf("a reachable target still connected at TCP, got %+v", res.TCP)
			}
			if res.Auth == nil || res.Auth.OK || res.Auth.Code != code {
				t.Fatalf("expected Result.Auth.Code = %q, got %+v", code, res.Auth)
			}
		})
	}
}

// TestRunPostgresDenied: a denied-only target yields Result.Denied and never
// reaches the prober — a live listener accepts zero connections and Auth is nil.
func TestRunPostgresDenied(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	fp := &fakeProber{result: checkapi.AuthResult{OK: true}}
	guard := NewDenyGuard([]*net.IPNet{mustCIDR(t, "127.0.0.0/8")})
	res := Postgres{Prober: fp}.Run(context.Background(), "metadata.test", []string{"127.0.0.1"}, port, 2*time.Second, pgDNS("127.0.0.1"), guard, pgCreds(), nil)

	if !res.Denied || res.DeniedReason != DenyReason {
		t.Fatalf("expected Result.Denied with the guard reason, got %+v", res)
	}
	if res.Auth != nil {
		t.Errorf("denial must precede any handshake, but Auth was set: %+v", res.Auth)
	}
	if fp.callCount() != 0 {
		t.Errorf("prober invoked %d times on a denied target, want 0", fp.callCount())
	}
}

// TestRunPostgresDialFailure: no listener → a TCP-style failure with Auth nil and
// the prober never invoked (a connect failure is never an auth failure).
func TestRunPostgresDialFailure(t *testing.T) {
	ln, port := listenLocal(t)
	_ = ln.Close() // free the port so the dial is refused

	fp := &fakeProber{result: checkapi.AuthResult{OK: true}}
	res := Postgres{Prober: fp}.Run(context.Background(), "127.0.0.1", []string{"127.0.0.1"}, port, 2*time.Second, nil, nil, pgCreds(), nil)

	if res.TCP == nil || res.TCP.OK {
		t.Fatalf("expected a failed TCP dial, got %+v", res.TCP)
	}
	if res.Denied {
		t.Errorf("a refused connect is not a denial, got %+v", res)
	}
	if res.Auth != nil {
		t.Errorf("no auth may run without a reachable target, but Auth was set: %+v", res.Auth)
	}
	if fp.callCount() != 0 {
		t.Errorf("prober invoked %d times on a dial failure, want 0", fp.callCount())
	}
}

// TestRunPostgresInvalidInput: bad input errors out before any dial or prober
// call.
func TestRunPostgresInvalidInput(t *testing.T) {
	fp := &fakeProber{}
	res := Postgres{Prober: fp}.Run(context.Background(), "", nil, 0, time.Second, nil, nil, pgCreds(), nil)
	if res.Error == "" {
		t.Fatal("expected an input validation error")
	}
	if res.Auth != nil || res.TCP != nil {
		t.Errorf("invalid input must not dial or handshake, got %+v", res)
	}
	if fp.callCount() != 0 {
		t.Errorf("prober invoked %d times on invalid input, want 0", fp.callCount())
	}
}

// TestRunPostgresDefaultProber: a zero Postgres uses the real pgconn-backed
// prober. Pointed at a plain TCP listener (which speaks no PostgreSQL), the auth
// attempt fails, but the point is that Result.Auth is populated — proving the
// default prober is wired in when none is injected.
func TestRunPostgresDefaultProber(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close() //nolint:errcheck // best-effort close

	res := RunPostgres(context.Background(), "127.0.0.1", []string{"127.0.0.1"}, port, time.Second, pgDNS("127.0.0.1"), nil,
		pgCreds(), &checkapi.TLSOptions{Enabled: pgBoolPtr(false)})

	if res.TCP == nil || !res.TCP.OK {
		t.Fatalf("expected a successful TCP dial, got %+v", res.TCP)
	}
	if res.Auth == nil {
		t.Fatal("expected the default prober to populate Result.Auth")
	}
	if res.Auth.OK {
		t.Errorf("a plain TCP listener is not PostgreSQL; expected a failed auth, got %+v", res.Auth)
	}
}

// TestGuardedDialDeniesMetadataIP proves the runner's guarded DialFunc refuses a
// denied (metadata / link-local) address at connect time — before any socket
// connects — so a DNS rebind between the reachability dial and the auth dial
// still fails closed. It exercises the Control hook directly, without a real dial.
func TestGuardedDialDeniesMetadataIP(t *testing.T) {
	guard := NewDenyGuard([]*net.IPNet{mustCIDR(t, "169.254.0.0/16")})
	dial := guardedDial(guard)

	conn, err := dial(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("guarded dial connected to a denied metadata IP; want refusal")
	}

	// A non-denied address is not refused by the guard (it may still fail to
	// connect, but not with the guard's refusal).
	allowGuard := guardedDial(NewDenyGuard([]*net.IPNet{mustCIDR(t, "10.0.0.0/8")}))
	ln, port := listenLocal(t)
	defer ln.Close() //nolint:errcheck // best-effort close
	c, err := allowGuard(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("guarded dial refused an allowed address: %v", err)
	}
	_ = c.Close()
}

// TestRunPostgresConcurrentRaceClean drives many concurrent postgres runs sharing
// one fake prober. Its value is under `go test -race`: the shared dial layer, the
// guard atomic, and the prober are all touched across goroutines at once.
func TestRunPostgresConcurrentRaceClean(t *testing.T) {
	ln, port := listenLocal(t)
	defer ln.Close() //nolint:errcheck // best-effort close
	dns := pgDNS("127.0.0.1")
	guard := NewDenyGuard([]*net.IPNet{mustCIDR(t, "169.254.0.0/16")})

	fp := &fakeProber{result: checkapi.AuthResult{OK: true}}
	const n = 24
	var wg sync.WaitGroup
	var okCount atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := Postgres{Prober: fp}.Run(context.Background(), "127.0.0.1", []string{"127.0.0.1"}, port, 3*time.Second, dns, guard, pgCreds(), nil)
			if res.Auth != nil && res.Auth.OK {
				okCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if okCount.Load() != n {
		t.Fatalf("expected all %d concurrent runs to succeed, got %d", n, okCount.Load())
	}
}
