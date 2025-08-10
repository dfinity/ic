package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

func NewTestnetCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "testnet",
		Short: "Create dynamic testnets",
	}
	cmd.SetOut(os.Stdout)
	return cmd
}
