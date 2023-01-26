package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func ListCommand(cmd *cobra.Command, args []string) error {
	if targets, err := get_all_system_test_targets(); err == nil {
		cmd.Printf("%sThe following %d system_test targets were found:\n%s%s\n", CYAN, len(targets), strings.Join(targets, "\n"), NC)
		return nil
	} else {
		return err
	}
}

func NewListCmd() *cobra.Command {
	var testCmd = &cobra.Command{
		Use:     "list",
		Short:   "List all system_test targets with Bazel",
		Example: "ict list",
		Args:    cobra.ExactArgs(0),
		RunE:    ListCommand,
	}
	testCmd.SetOut(os.Stdout)
	return testCmd
}
