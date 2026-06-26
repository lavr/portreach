package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/lavr/portreach/internal/cmd"
	versionpkg "github.com/lavr/portreach/internal/version"
)

// version is set via -ldflags="-X main.version=...".
var version = "dev"

func main() {
	versionpkg.Set(version)

	err := cmd.Run(os.Args[1:], cmd.Deps{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	})
	if err != nil {
		var ee *cmd.ExitError
		if errors.As(err, &ee) {
			if ee.Err != nil {
				fmt.Fprintln(os.Stderr, "portreach:", ee.Err)
			}
			os.Exit(ee.Code)
		}
		fmt.Fprintln(os.Stderr, "portreach:", err)
		os.Exit(1)
	}
}
