// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package main

import (
	"os"
	"strings"

	"github.com/project-copacetic/copacetic/pkg/patch"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	k8sVersion "sigs.k8s.io/release-utils/version"
)

// Global for Debug logging flag.
var debug bool

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "copa",
		Short: "Container ptching tool",
		Long:  "Project Copacetic: Container patching tool",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if debug {
				log.SetLevel(log.DebugLevel)
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Usage()
		},
		SilenceUsage: true,
		Version:      k8sVersion.GetVersionInfo().GitVersion,
	}

	flags := rootCmd.PersistentFlags()
	flags.BoolVar(&debug, "debug", false, "enable debug level logging")

	rootCmd.AddCommand(patch.NewPatchCmd())
	rootCmd.AddCommand(k8sVersion.WithFont("speed"))
	return rootCmd
}

func initConfig() {
	viper.SetEnvPrefix("copa")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
}

func main() {
	cobra.OnInitialize(initConfig)
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
