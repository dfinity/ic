package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var DEFAULT_TEST_KEEPALIVE_MINS = 60

type Config struct {
	isFuzzyMatch         bool
	isDryRun             bool
	keepAlive            bool
	filterTests          string
	farmBaseUrl          string
	requiredHostFeatures string
	k8sBranch            string
}

func TestCommandWithConfig(cfg *Config) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		target := args[0]
		all_targets, err := get_all_system_test_targets()
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
		command := []string{"bazel", "test", target, "--test_output=streamed"}
		command = append(command, "--cache_test_results=no")
		// Try and sync k8s dashboards
		cmd.Println(GREEN + "Will try to sync dashboards from k8s branch: " + cfg.k8sBranch)
		icDashboardsDir, err := sparse_checkout("git@github.com:dfinity-ops/k8s.git", "", []string{"bases/apps/ic-dashboards"}, cfg.k8sBranch)
		if err != nil {
			cmd.PrintErrln(YELLOW + "Failed to sync k8s dashboards. Received the following error: " + err.Error())
		} else {
			cmd.PrintErrln(GREEN + "Successfully synced dashboards to path " + icDashboardsDir)
			icDashboardsDir = filepath.Join(icDashboardsDir, "bases", "apps", "ic-dashboards")
			cmd.Println(GREEN + "Will use " + icDashboardsDir + " as a root for dashboards")

			command = append(command, fmt.Sprintf("--test_env=IC_DASHBOARDS_DIR=%s", icDashboardsDir))
			command = append(command, fmt.Sprintf("--sandbox_add_mount_pair=%s", icDashboardsDir))
		}
		if len(cfg.filterTests) > 0 {
			command = append(command, "--test_arg=--include-tests="+cfg.filterTests)
		}
		if len(cfg.farmBaseUrl) > 0 {
			command = append(command, "--test_arg=--farm-base-url="+cfg.farmBaseUrl)
		}
		if len(cfg.requiredHostFeatures) > 0 {
			command = append(command, "--test_arg=--set-required-host-features="+cfg.requiredHostFeatures)
		}
		if cfg.keepAlive {
			keepAlive := fmt.Sprintf("--test_timeout=%s", strconv.Itoa(DEFAULT_TEST_KEEPALIVE_MINS*60))
			command = append(command, keepAlive)
			command = append(command, "--test_arg=--keepalive")
		}
		// Append all bazel args following the --, i.e. "ict test target -- --verbose_explanations --test_timeout=20 ..."
		// Note: arguments provided by the user might override the ones above, i.e. test_timeout, cache_test_results, etc.
		command = append(command, args[1:]...)
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
		Example: "  ict test //rs/tests/idx:basic_health_test\n  ict test basic_health_test --dry-run -- --test_tmpdir=./tmp --test_output=errors\n  ict test //rs/tests/idx:basic_health_test --set-required-host-features \"performance,host=dm1-dll01.dm1.dfinity.network\"",
		Args:    cobra.MinimumNArgs(1),
		RunE:    TestCommandWithConfig(&cfg),
	}
	testCmd.Flags().BoolVarP(&cfg.isFuzzyMatch, "fuzzy", "", false, "Use fuzzy matching to find similar target names. Default: substring match.")
	testCmd.Flags().BoolVarP(&cfg.isDryRun, "dry-run", "n", false, "Print raw Bazel command to be invoked without execution.")
	testCmd.Flags().BoolVarP(&cfg.keepAlive, "keepalive", "k", false, fmt.Sprintf("Keep test system alive for %d minutes.", DEFAULT_TEST_KEEPALIVE_MINS))
	testCmd.PersistentFlags().StringVarP(&cfg.filterTests, "include-tests", "i", "", "Execute only those test functions which contain a substring.")
	testCmd.PersistentFlags().StringVarP(&cfg.farmBaseUrl, "farm-url", "", "", "Use a custom url for the Farm webservice.")
	testCmd.PersistentFlags().StringVarP(&cfg.requiredHostFeatures, "set-required-host-features", "", "", "Set and override required host features of all hosts spawned.\nFeatures must be one or more of [dc=<dc-name>, host=<host-name>, AMD-SEV-SNP, performance, io-performance, dll, spm, dmz], separated by comma (see Examples).")
	testCmd.PersistentFlags().StringVarP(&cfg.k8sBranch, "k8s-branch", "", "main", "Override the branch from which the dashboards are being synced. Default: main")
	testCmd.SetOut(os.Stdout)
	return testCmd
}
