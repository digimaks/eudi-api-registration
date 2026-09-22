package main

import (
	eudiapiregistration "github.com/digimaks/eudi-api-registration"

	"azugo.io/azugo/server"
	"azugo.io/core/cli"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "Registration API",
		AppVer:        Version,
		Configuration: eudiapiregistration.NewConfiguration(),
	}))
}
