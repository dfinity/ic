package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var DEFAULT_TESTNET_LIFETIME_MINS = 60
var MAX_TESTNET_LIFETIME_MINS = 180

type TestnetConfig struct {
	lifetime     int
	isFuzzyMatch bool
	isDryRun     bool
}

func ValidateTestnetCommand(cfg *TestnetConfig) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if cfg.lifetime > MAX_TESTNET_LIFETIME_MINS {
			return fmt.Errorf("option --lifetime should be <= %d mins", MAX_TESTNET_LIFETIME_MINS)
		}
		return nil
	}
}

func TestnetCommand(cfg *TestnetConfig) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		// If the target name is not fully qualified, we make it to be such.
		target, err := make_fully_qualified_target(args[0])
		if err != nil {
			return err
		}
		all_targets, err := get_all_testnets()
		if err != nil {
			return err
		}
		if !any_equals(all_targets, target) {
			if match_target, msg, err := find_matching_target(all_targets, target, cfg.isFuzzyMatch); err == nil {
				if len(msg) > 0 {
					cmd.Printf(CYAN + msg + NC)
				}
				target = match_target
			} else {
				return err
			}
		}
		command := []string{"bazel", "test", target, "--config=systest"}
		// Append all bazel args following the --, i.e. "ict test target -- --verbose_explanations ..."
		command = append(command, args[1:]...)
		command = append(command, "--cache_test_results=no")
		lifetime := fmt.Sprintf("--test_timeout=%s", strconv.Itoa(cfg.lifetime*60))
		command = append(command, lifetime)
		command = append(command, "--test_arg=--debug-keepalive")
		// Print Bazel command for debugging puroposes.
		cmd.Println(CYAN + "Raw Bazel command to be invoked: \n$ " + strings.Join(command, " ") + NC)
		if cfg.isDryRun {
			return nil
		} else {
			// Start Bazel test Command with stdout, stderr streaming.
			testnetCmd := exec.Command(command[0], command[1:]...)
			testnetCmd.Stdout = os.Stdout
			testnetCmd.Stderr = os.Stderr
			return testnetCmd.Run()
		}
	}
}

func NewTestnetCmd() *cobra.Command {
	var cfg = TestnetConfig{}
	var cmd = &cobra.Command{
		Use:               "testnet <testnet_name> [flags] [-- <bazel_args>]",
		Short:             "Spawn IC testnets for desired time periods. This command blocks the terminal.",
		Example:           "ict testnet small\nict testnet small --lifetime=50 -- --test_tmpdir=./tmp (store artifacts, such as SSH keys)",
		Args:              cobra.MinimumNArgs(1),
		PersistentPreRunE: ValidateTestnetCommand(&cfg),
		RunE:              TestnetCommand(&cfg),
	}
	cmd.Flags().IntVar(&cfg.lifetime, "lifetime", DEFAULT_TESTNET_LIFETIME_MINS, "Keep testnet alive for this duration in mins.")
	cmd.Flags().BoolVarP(&cfg.isFuzzyMatch, "fuzzy", "", false, "Use fuzzy matching to find similar testnet names. Default: substring match.")
	cmd.Flags().BoolVarP(&cfg.isDryRun, "dry-run", "n", false, "Print raw Bazel command to be invoked without execution.")
	cmd.SetOut(os.Stdout)
	return cmd
}
