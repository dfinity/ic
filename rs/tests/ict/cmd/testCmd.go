package cmd

import (
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var RED = "\033[1;31m"
var GREEN = "\033[1;32m"
var CYAN = "\033[0;36m"
var NC = "\033[0m"

type Config struct {
	isCacheTestResult bool
	testTmpDir        string
	isDryRun          bool
}

func TestCommandWithConfig(cfg *Config) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		target := args[0]
		cache_test_results := "--cache_test_results="
		if cfg.isCacheTestResult {
			cache_test_results += "yes"
		} else {
			cache_test_results += "no"
		}
		command := []string{"bazel", "test", target, "--config=systest", cache_test_results}
		if cfg.testTmpDir != "" {
			command = append(command, "--test_tmpdir="+cfg.testTmpDir)
		}
		// Print Bazel command for debugging puroposes.
		cmd.Println(CYAN + "Raw Bazel command to be invoked: \n$ " + strings.Join(command, " ") + NC)
		if cfg.isDryRun {
			return nil
		} else {
			// Start Bazel test Command with stdout, stderr streaming.
			testCmd := exec.Command(command[0], command[1:]...)
			testCmd.Stdout = os.Stdout
			testCmd.Stderr = os.Stderr
			return testCmd.Run()
		}
	}
}

func NewTestCmd() *cobra.Command {
	var cfg = Config{}
	var testCmd = &cobra.Command{
		Use:     "test",
		Aliases: []string{"system_test", "t"},
		Short:   "Run system_test target with Bazel",
		Example: "ict test //rs/tests:basic_health_test",
		Args:    cobra.ExactArgs(1),
		RunE:    TestCommandWithConfig(&cfg),
	}
	testCmd.Flags().BoolVarP(&cfg.isDryRun, "dry-run", "n", false, "Print raw Bazel command to be invoked.")
	testCmd.Flags().BoolVarP(&cfg.isCacheTestResult, "cache_test_results", "c", false, "Bazel's cache_test_results, see --cache_test_results tag in Bazel docs.")
	testCmd.PersistentFlags().StringVarP(&cfg.testTmpDir, "test_tmpdir", "t", "", "Dir for storing test results, see --test-tmpdir tag in Bazel docs.")
	return testCmd
}
