package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// serveWithShutdown runs srv until an error occurs or an interrupt/SIGTERM is
// received, then drains in-flight requests with a bounded grace period.
func serveWithShutdown(srv *http.Server, deps Deps) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		_, _ = fmt.Fprintf(deps.Stdout, "listening on %s\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return &ExitError{Code: 1, Err: err}
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			return &ExitError{Code: 1, Err: err}
		}
		return nil
	}
}
