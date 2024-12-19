package cmd

import (
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	var version = "0.1.2"
	var rootCmd = &cobra.Command{
		Version: version,
		Use:     "ict",
		Long:    "ict " + version + "\nA simple CLI for running system_tests in Bazel.",
		Example: "ict test //rs/tests/idx:basic_health_test",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Print help by default, i.e. if no args are provided.
			if len(args) == 0 {
				cmd.Help()
			}
			return nil
		},
	}
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:    "no-help",
		Hidden: true,
	})
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	cobra.AddTemplateFunc("StyleHeading", color.New(color.FgGreen).SprintFunc())
	usageTemplate := rootCmd.UsageTemplate()
	usageTemplate = strings.NewReplacer(
		`Usage:`, `{{StyleHeading "Usage:"}}`,
		`Examples:`, `{{StyleHeading "Examples:"}}`,
		`Aliases:`, `{{StyleHeading "Aliases:"}}`,
		`Available Commands:`, `{{StyleHeading "Available Commands:"}}`,
		`Global Flags:`, `{{StyleHeading "Global Flags:"}}`,
		// The following one steps on "Global Flags:"
		// `Flags:`, `{{StyleHeading "Flags:"}}`,
	).Replace(usageTemplate)
	re := regexp.MustCompile(`(?m)^Flags:\s*$`)
	usageTemplate = re.ReplaceAllLiteralString(usageTemplate, `{{StyleHeading "Flags:"}}`)
	rootCmd.SetUsageTemplate(usageTemplate)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	return rootCmd
}
