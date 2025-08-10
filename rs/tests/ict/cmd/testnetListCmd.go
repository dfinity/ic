package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func TestnetListCommand(cmd *cobra.Command, args []string) error {
	if targets, err := get_all_testnets(); err == nil {
		cmd.Printf("%sThe following %d testnets were found:\n%s%s\n", CYAN, len(targets), strings.Join(targets, "\n"), NC)
		return nil
	} else {
		return err
	}
}

func NewTestnetListCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "list",
		Short:   "List all existing IC testnets",
		Example: "ict testnet list",
		Args:    cobra.ExactArgs(0),
		RunE:    TestnetListCommand,
	}
	cmd.SetOut(os.Stdout)
	return cmd
}
