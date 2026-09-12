// Command app is the host half of native cogbox browser previews.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"cogbox-app/internal/host"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := host.Run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "cogbox app:", err)
		os.Exit(1)
	}
}
