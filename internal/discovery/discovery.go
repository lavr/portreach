// Package discovery locates probe agents either from a static list or by
// resolving the A records of a headless service, using only the standard
// library.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Agent is a single probe endpoint addressed as host:port.
type Agent struct {
	Addr string `json:"addr"`
}

// Discoverer returns the current set of probe agents.
type Discoverer interface {
	Agents(ctx context.Context) ([]Agent, error)
}

// Resolver resolves a hostname to its addresses. *net.Resolver satisfies it;
// tests inject a fake.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Static builds a Discoverer from a comma-separated list of host[:port] entries.
// Entries without a port use defaultPort. An empty list is an error.
func Static(list string, defaultPort int) (Discoverer, error) {
	var agents []Agent
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		addr, err := normalizeAddr(item, defaultPort)
		if err != nil {
			return nil, err
		}
		agents = append(agents, Agent{Addr: addr})
	}
	if len(agents) == 0 {
		return nil, errors.New("empty agent list")
	}
	return staticDiscoverer(agents), nil
}

// normalizeAddr appends defaultPort to item when it carries no port.
func normalizeAddr(item string, defaultPort int) (string, error) {
	if h, p, err := net.SplitHostPort(item); err == nil {
		if strings.TrimSpace(h) == "" || strings.TrimSpace(p) == "" {
			return "", fmt.Errorf("invalid agent address %q: host and port required", item)
		}
		return item, nil
	}
	host := strings.TrimSpace(item)
	if host == "" {
		return "", errors.New("empty agent host")
	}
	if defaultPort < 1 || defaultPort > 65535 {
		return "", fmt.Errorf("invalid default port: %d", defaultPort)
	}
	return net.JoinHostPort(host, strconv.Itoa(defaultPort)), nil
}

type staticDiscoverer []Agent

func (s staticDiscoverer) Agents(ctx context.Context) ([]Agent, error) {
	return append([]Agent(nil), s...), nil
}

// DNS builds a Discoverer that resolves name's A records on each call, yielding
// one ip:port agent per address. A nil resolver uses net.DefaultResolver.
func DNS(name string, port int, resolver Resolver) (Discoverer, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("empty DNS name")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid agent port: %d", port)
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &dnsDiscoverer{name: name, port: port, resolver: resolver}, nil
}

type dnsDiscoverer struct {
	name     string
	port     int
	resolver Resolver
}

func (d *dnsDiscoverer) Agents(ctx context.Context) ([]Agent, error) {
	addrs, err := d.resolver.LookupHost(ctx, d.name)
	if err != nil {
		return nil, err
	}
	port := strconv.Itoa(d.port)
	agents := make([]Agent, 0, len(addrs))
	for _, ip := range addrs {
		agents = append(agents, Agent{Addr: net.JoinHostPort(ip, port)})
	}
	if len(agents) == 0 {
		return nil, fmt.Errorf("no agents resolved for %q", d.name)
	}
	return agents, nil
}

// New selects a Discoverer from the configured flags. Exactly one of agents or
// agentsDNS must be set; defaultPort applies to the static list and agentPort to
// DNS results.
func New(agents, agentsDNS string, defaultPort, agentPort int, resolver Resolver) (Discoverer, error) {
	agents = strings.TrimSpace(agents)
	agentsDNS = strings.TrimSpace(agentsDNS)
	switch {
	case agents != "" && agentsDNS != "":
		return nil, errors.New("set only one of --agents or --agents-dns")
	case agents != "":
		return Static(agents, defaultPort)
	case agentsDNS != "":
		return DNS(agentsDNS, agentPort, resolver)
	default:
		return nil, errors.New("set one of --agents or --agents-dns")
	}
}
