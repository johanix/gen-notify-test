/*
 * Copyright (c) 2023 Johan Stenstam <johani@johani.org>
 */
package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	lib "github.com/johanix/gen-notify-test/lib"
)

var keyfile string

var rootCmd = &cobra.Command{
	Use:   "ddns-cli",
	Short: "Test and demo of using the private NOTIFY RR to locate where to send DDNS updates for synching parent delegation data",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:
to quickly create a Cobra application.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
        cobra.OnInitialize(initConfig)
        err := lib.RegisterNotifyRR()
	if err != nil {
	   log.Fatalf("Error: %v", err)
	}
	rootCmd.PersistentFlags().BoolVarP(&lib.Global.Verbose, "verbose", "v", false, "verbose mode")
	rootCmd.PersistentFlags().BoolVarP(&lib.Global.Debug, "debug", "d", false, "debug mode")
	rootCmd.PersistentFlags().StringVarP(&keyfile, "keyfile", "k", "", "name of file with private SIG(0) key")
}


func initConfig() {
        viper.SetConfigFile("ddns-cli.yaml")
        viper.AutomaticEnv() // read in environment variables that match

        // If a config file is found, read it in.
        if err := viper.ReadInConfig(); err != nil {
                log.Printf("Error reading config '%s': %v\n", viper.ConfigFileUsed(), err)
        }
}