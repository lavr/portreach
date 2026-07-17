package ui

import "github.com/lavr/portreach/internal/checkapi"

// Branding customises operator-controlled HTML blocks on the main UI page.
// Title is tri-state: nil keeps the localized default, non-nil uses the value
// (including "" to suppress the heading). Description and Footer are omitted
// when empty.
type Branding struct {
	Title       *string
	Description string
	Footer      string
}

// Option customises a Server at construction time.
type Option func(*Server)

// WithBranding sets main-page branding. Branding strings are trusted operator
// input and are rendered as HTML by the page template.
func WithBranding(b Branding) Option {
	return func(s *Server) {
		s.branding = b
	}
}

// WithAgentToken sets the shared bearer token sent to agents on every /check
// call. An empty token leaves agent requests unauthenticated (backward
// compatible with agents that require no token).
func WithAgentToken(token string) Option {
	return func(s *Server) {
		s.agentToken = token
	}
}

// WithFanout sets the optional per-check fan-out bounds. The zero value
// (FanoutConfig{}) keeps the unlimited "from every node" behaviour.
func WithFanout(c FanoutConfig) Option {
	return func(s *Server) {
		s.fanoutCfg = c
	}
}

// WithEnabledChecks sets the --enabled-checks allowlist this UI offers. The
// zero value (checkapi.EnabledChecks{}) enables nothing; New does not
// substitute a default — cmd is responsible for resolving the "tcp" default
// via checkapi.ParseEnabledChecks before calling New.
func WithEnabledChecks(checks checkapi.EnabledChecks) Option {
	return func(s *Server) {
		s.enabledChecks = checks
	}
}
