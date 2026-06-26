package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

var (
	errBadPort    = errors.New("invalid port")
	errBadTimeout = errors.New("invalid timeout")
)

// contextWithTimeout derives a context from the request bounded by timeout.
func contextWithTimeout(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), timeout)
}

// remainingBudget returns the time left before ctx's deadline, falling back to
// fallback when ctx carries no deadline. Used to clamp the per-agent probe
// timeout against the budget that actually remains after discovery, not the
// original fan-out budget.
func remainingBudget(ctx context.Context, fallback time.Duration) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		return time.Until(dl)
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
