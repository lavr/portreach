package discovery

import (
	"context"
	"errors"
	"testing"
)

type fakeResolver struct {
	addrs []string
	err   error
}

func (f fakeResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return f.addrs, f.err
}

func TestStatic(t *testing.T) {
	d, err := Static("host1:9000, host2 ,host3:7", 8732)
	if err != nil {
		t.Fatalf("Static: %v", err)
	}
	agents, err := d.Agents(context.Background())
	if err != nil {
		t.Fatalf("Agents: %v", err)
	}
	want := []string{"host1:9000", "host2:8732", "host3:7"}
	if len(agents) != len(want) {
		t.Fatalf("got %d agents, want %d: %v", len(agents), len(want), agents)
	}
	for i, a := range agents {
		if a.Addr != want[i] {
			t.Errorf("agent %d = %q, want %q", i, a.Addr, want[i])
		}
	}
}

func TestStaticEmpty(t *testing.T) {
	if _, err := Static("  , ,", 8732); err == nil {
		t.Fatal("expected error for empty list")
	}
}

func TestStaticBadDefaultPort(t *testing.T) {
	if _, err := Static("host", 0); err == nil {
		t.Fatal("expected error for invalid default port")
	}
}

func TestStaticEmptyPort(t *testing.T) {
	if _, err := Static("host:", 8732); err == nil {
		t.Fatal("expected error for entry with empty port")
	}
	if _, err := Static(":8732", 8732); err == nil {
		t.Fatal("expected error for entry with empty host")
	}
}

func TestDNS(t *testing.T) {
	r := fakeResolver{addrs: []string{"10.0.0.1", "10.0.0.2"}}
	d, err := DNS("portreach-agent.ns.svc", 8732, r)
	if err != nil {
		t.Fatalf("DNS: %v", err)
	}
	agents, err := d.Agents(context.Background())
	if err != nil {
		t.Fatalf("Agents: %v", err)
	}
	want := []string{"10.0.0.1:8732", "10.0.0.2:8732"}
	if len(agents) != len(want) {
		t.Fatalf("got %d agents, want %d: %v", len(agents), len(want), agents)
	}
	for i, a := range agents {
		if a.Addr != want[i] {
			t.Errorf("agent %d = %q, want %q", i, a.Addr, want[i])
		}
	}
}

func TestDNSResolveError(t *testing.T) {
	r := fakeResolver{err: errors.New("nxdomain")}
	d, err := DNS("nope.svc", 8732, r)
	if err != nil {
		t.Fatalf("DNS: %v", err)
	}
	if _, err := d.Agents(context.Background()); err == nil {
		t.Fatal("expected resolve error")
	}
}

func TestDNSNoAddrs(t *testing.T) {
	r := fakeResolver{addrs: nil}
	d, err := DNS("empty.svc", 8732, r)
	if err != nil {
		t.Fatalf("DNS: %v", err)
	}
	if _, err := d.Agents(context.Background()); err == nil {
		t.Fatal("expected error for zero resolved addresses")
	}
}

func TestDNSBadArgs(t *testing.T) {
	if _, err := DNS("", 8732, nil); err == nil {
		t.Fatal("expected error for empty name")
	}
	if _, err := DNS("svc", 0, nil); err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestNew(t *testing.T) {
	r := fakeResolver{addrs: []string{"10.0.0.5"}}

	d, err := New("a:1,b:2", "", 8732, 8732, r)
	if err != nil {
		t.Fatalf("New static: %v", err)
	}
	if agents, _ := d.Agents(context.Background()); len(agents) != 2 {
		t.Errorf("static: got %d agents, want 2", len(agents))
	}

	d, err = New("", "svc", 8732, 9999, r)
	if err != nil {
		t.Fatalf("New dns: %v", err)
	}
	agents, _ := d.Agents(context.Background())
	if len(agents) != 1 || agents[0].Addr != "10.0.0.5:9999" {
		t.Errorf("dns: got %v, want [10.0.0.5:9999]", agents)
	}
}

func TestNewXOR(t *testing.T) {
	if _, err := New("a:1", "svc", 8732, 8732, nil); err == nil {
		t.Fatal("expected error when both set")
	}
	if _, err := New("", "", 8732, 8732, nil); err == nil {
		t.Fatal("expected error when neither set")
	}
}
