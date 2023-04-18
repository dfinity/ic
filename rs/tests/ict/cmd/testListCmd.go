package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func TestListCommand(cmd *cobra.Command, args []string) error {
	if targets, err := get_all_system_test_targets(); err == nil {
		cmd.Printf("%sThe following %d system_test targets were found:\n%s%s\n", CYAN, len(targets), strings.Join(targets, "\n"), NC)
		return nil
	} else {
		return err
	}
}

func NewTestListCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "list",
		Short:   "List all system_test targets with Bazel",
		Example: "ict test list",
		Args:    cobra.ExactArgs(0),
		RunE:    TestListCommand,
	}
	cmd.SetOut(os.Stdout)
	return cmd
}
