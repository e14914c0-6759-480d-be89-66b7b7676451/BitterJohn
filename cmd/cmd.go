package cmd

import (
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	Version = "unknown"

	rootCmd = &cobra.Command{
		Use:   "BitterJohn",
		Short: "Server and relay side infrastructure for RDA.",
		Long: `BitterJohn is the server and relay side infrastructure for RDA.
It aims to provide a shared, self-managed, anonymous and untraceable bandwidth service cluster solution.`,
		Version: Version,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(runCmd)
}
