package main

import (
	eudiapiregistration "github.com/digimaks/eudi-api-registration"
	"github.com/digimaks/eudi-api-registration/routes"

	"azugo.io/azugo/server"
	"azugo.io/core/cli"
	"github.com/spf13/cobra"
)

func runWeb(cmd *cobra.Command, _ []string) error {
	a, err := eudiapiregistration.New(cmd, Version)
	if err != nil {
		return err
	}
	if err = routes.Init(a); err != nil {
		return err
	}
	server.RunContext(cmd.Context(), a)
	return nil
}

func init() {
	cli.Register(&cobra.Command{Use: "web", Short: "Start web server", RunE: runWeb}, cli.AsDefault())
}
