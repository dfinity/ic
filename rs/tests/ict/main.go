package main

import (
	"fmt"
	"os"

	"github.com/dfinity/ic/rs/tests/ict/cmd"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func AssembleAllCmds() *cobra.Command {
	var rootCmd = cmd.NewRootCmd()
	var testCmd = cmd.NewTestCmd()
	testCmd.AddCommand(cmd.NewListCmd())
	rootCmd.AddCommand(testCmd)
	return rootCmd
}

func main() {
	if err := AssembleAllCmds().Execute(); err != nil {
		color.New(color.FgRed, color.Bold).Fprintf(os.Stderr, "There was an error while executing CLI: ")
		fmt.Fprintf(os.Stderr, "'%s'\n", err)
		os.Exit(1)
	}
}
