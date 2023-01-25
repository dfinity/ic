package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var RED = "\033[1;31m"
var GREEN = "\033[1;32m"
var CYAN = "\033[0;36m"
var NC = "\033[0m"
var FUZZY_MATCHES_COUNT = 7

type Config struct {
	useCachedTestResult   bool
	testTmpDir            string
	isDryRun              bool
	useFuzzyMatchedTarget bool
}

func TestCommandWithConfig(cfg *Config) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		target := args[0]
		if res, err_target := check_target_exists(target); !res {
			if err_target != nil {
				return err_target
			} else if closest_matches, err_match := get_closest_target_matches(target); err_match != nil {
				return err_match
			} else if len(closest_matches) == 0 {
				return fmt.Errorf("No test target `%s` was found", target)
			} else if cfg.useFuzzyMatchedTarget {
				target = closest_matches[0]
			} else {
				return fmt.Errorf("No test target `%s` was found: \nDid you mean any of:\n%s", target, strings.Join(closest_matches, "\n"))
			}
		}
		cache_test_results := "--cache_test_results="
		if cfg.useCachedTestResult {
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
		Use:     "test <system_test_target_arg>",
		Aliases: []string{"system_test", "t"},
		Short:   "Run system_test target with Bazel",
		Example: "ict test //rs/tests:basic_health_test",
		Args:    cobra.ExactArgs(1),
		RunE:    TestCommandWithConfig(&cfg),
	}
	testCmd.Flags().BoolVarP(&cfg.useFuzzyMatchedTarget, "use-fuzzy-match", "f", false, "If test target is not found, use the closest fuzzy matched one.")
	testCmd.Flags().BoolVarP(&cfg.isDryRun, "dry-run", "n", false, "Print raw Bazel command to be invoked.")
	testCmd.Flags().BoolVarP(&cfg.useCachedTestResult, "cache_test_results", "c", false, "Bazel's cache_test_results, see --cache_test_results tag in Bazel docs.")
	testCmd.PersistentFlags().StringVarP(&cfg.testTmpDir, "test_tmpdir", "t", "", "Dir for storing test results, see --test-tmpdir tag in Bazel docs.")
	return testCmd
}
