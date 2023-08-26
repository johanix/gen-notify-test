/*
 * Copyright (c) 2023 Johan Stenstam <johani@johani.org>
 */
package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	lib "github.com/johanix/gen-notify-test/lib"
)

var rootCmd = &cobra.Command{
	Use:   "notify",
	Short: "Test and demo of using the private NOTIFY RR to locate where to send generalised NOTIFY",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
        err := lib.RegisterNotifyRR()
	if err != nil {
	   log.Fatalf("Error: %v", err)
	}
	rootCmd.PersistentFlags().BoolVarP(&lib.Global.Verbose, "verbose", "v", false, "verbose mode")
	rootCmd.PersistentFlags().BoolVarP(&lib.Global.Debug, "debug", "d", false, "debug mode")
}

