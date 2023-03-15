package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var FUZZY_MATCHES_COUNT = 7

type Config struct {
	isFuzzyMatch bool
	isDryRun    bool
	keepAlive   bool
	filterTests string
	farmBaseUrl string
}

func TestCommandWithConfig(cfg *Config) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		target := args[0]
		if res, err_target := check_target_exists(target); !res {
			if err_target != nil {
				return err_target
			} else if !cfg.isFuzzyMatch {
				if targets, err := find_substring_matches(target); err != nil {
					return err
				} else if len(targets) == 0 {
					return fmt.Errorf("\nNone of test targets matches the substring `%s`.\nTry fuzzy match: 'ict test %s --fuzzy'",  target, target)
				} else if len(targets) == 1 {
					cmd.Printf("%sTarget `%s` doesn't exist, a single substring match `%s` was found, executing ...%s\n", CYAN, target, targets[0], NC)
					target = targets[0]
				} else {
					return fmt.Errorf("\nTarget `%s` doesn't exist, the following substring matches found:\n%s", target, strings.Join(targets, "\n"))
				}
			} else {
				if closest_matches, err_match := get_closest_target_matches(target); err_match != nil {
					return err_match
				} else if len(closest_matches) == 0 {
					return fmt.Errorf("\nNo fuzzy matches for test target `%s` were found.", target)
				} else if len(closest_matches) == 1 {
					cmd.Printf("%sTarget `%s` doesn't exist, a single fuzzy match `%s` was found, executing ...%s\n", CYAN, target, closest_matches[0], NC)
					target = closest_matches[0]
				} else {
					return fmt.Errorf("\nThe following fuzzy matches were found for `%s`:\n%s", target, strings.Join(closest_matches, "\n"))
				}
			}
		}
		command := []string{"bazel", "test", target, "--config=systest"}
		// Append all bazel args following the --, i.e. "ict test target -- --verbose_explanations ..."
		command = append(command, args[1:]...)
		if !any_contains_substring(command, "--cache_test_results") {
			command = append(command, "--cache_test_results=no")
		}
		if len(cfg.filterTests) > 0 {
			command = append(command, "--test_arg=--include-tests="+cfg.filterTests)
		}
		if len(cfg.farmBaseUrl) > 0 {
			command = append(command, "--test_arg=--farm-base-url="+cfg.farmBaseUrl)
		}
		if cfg.keepAlive {
			command = append(command, "--test_timeout=3600")
			command = append(command, "--test_arg=--debug-keepalive")
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
		Use:     "test <system_test_target> [flags] [-- <bazel_args>]",
		Aliases: []string{"system_test", "t"},
		Short:   "Run system_test target with Bazel",
		Example: "  ict test //rs/tests:basic_health_test\n  ict test //rs/tests:basic_health_test --dry-run -- --test_tmpdir=./tmp --test_output=errors",
		Args:    cobra.MinimumNArgs(1),
		RunE:    TestCommandWithConfig(&cfg),
	}
	testCmd.Flags().BoolVarP(&cfg.isFuzzyMatch, "fuzzy", "", false, "Use fuzzy matching to find similar target names. Default: substring match.")
	testCmd.Flags().BoolVarP(&cfg.isDryRun, "dry-run", "n", false, "Print raw Bazel command to be invoked without execution.")
	testCmd.Flags().BoolVarP(&cfg.keepAlive, "keepalive", "k", false, "Keep test system alive for 60 minutes.")
	testCmd.PersistentFlags().StringVarP(&cfg.filterTests, "include-tests", "i", "", "Execute only those test functions which contain a substring.")
	testCmd.PersistentFlags().StringVarP(&cfg.farmBaseUrl, "farm-url", "", "", "Use a custom url for the Farm webservice.")
	testCmd.SetOut(os.Stdout)
	return testCmd
}
