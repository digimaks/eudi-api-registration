// Command eudi-api-registration is the headless client-registration admin API of
// the EUDI verifier.
package main

import (
	"os"

	"azugo.io/core/cli"
)

// Version is overridden at build time via -ldflags.
var Version = "0.1.0-dev"

func main() {
	if _, ok := os.LookupEnv("SERVER_URLS"); !ok {
		_ = os.Setenv("SERVER_URLS", "http://0.0.0.0:8080")
	}
	cli.Run(cli.Options{
		Use:     "eudi-api-registration",
		Short:   "EUDI Wallet verifier registration API",
		Version: Version,
	})
}
