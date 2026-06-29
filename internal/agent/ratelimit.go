package agent

import (
	"net"
	"strconv"
	"time"

	"github.com/lavr/portreach/internal/ratelimit"
)

// WithLimiter attaches an optional rate limiter that gates /check as
// defence-in-depth for direct calls. The UI fan-out already gates at the API,
// but an agent is reachable on the node (hostNetwork) and may be called
// directly, so a per-process/per-target cap bounds that path too. A nil limiter
// (the default) leaves /check unlimited — today's behaviour.
func WithLimiter(l *ratelimit.Limiter) Option {
	return func(s *Server) { s.limiter = l }
}

// allow gates one /check against the limiter, keyed per target (host:port) and
// the process global. The agent carries no per-user identity (internal cluster
// traffic), so the identity scope is left empty; only the target and global
// buckets apply. A nil limiter always allows (unlimited). Over limit it returns
// a bounded Retry-After hint and ok=false.
func (s *Server) allow(host string, port int) (retryAfter time.Duration, ok bool) {
	if s.limiter == nil {
		return 0, true
	}
	targetKey := net.JoinHostPort(host, strconv.Itoa(port))
	res := s.limiter.Reserve("", targetKey)
	if res.OK {
		return 0, true
	}
	return res.RetryAfter, false
}
