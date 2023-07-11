package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// This restriction is defined in an ad-hoc way to avoid accidental resources abuse.
var MAX_TESTNET_LIFETIME_MINS = 180

// All output files are saved in this folder, if output-dir is not provided.
var DEFAULT_RESULTS_DIR = "dynamic_testnets"

// Logs are streamed into this file during testnet deployment.
var SUFFIX_LOG_FILE = "log.txt"

// Filenames are prefixed with this datetime format up to milliseconds.
var DATE_TIME_FORMAT = "2006-01-02_15-04-05.000"

// These events are collected from test-driver logs during the testnet deployment.
const FARM_GROUP_NAME_CREATED_EVENT = "farm_group_name_created_event"
const KIBANA_URL_CREATED_EVENT = "kibana_url_created_event"
const FARM_VM_CREATED_EVENT = "farm_vm_created_event"
const BN_AAAA_RECORDS_CREATED_EVENT = "bn_aaaa_records_created_event"
const PROMETHEUS_VM_CREATED_EVENT = "prometheus_vm_created_event"
const GRAFANA_INSTANCE_CREATED_EVENT = "grafana_instance_created_event"
const IC_PROGRESS_CLOCK_CREATED_EVENT = "ic_progress_clock_created_event"
const IC_TOPOLOGY_EVENT = "ic_topology_created_event"
const VM_CONSOLE_LINK_CREATED_EVENT = "vm_console_link_created_event"

// This event signals the end of testnet deployment.
const JSON_REPORT_CREATED_EVENT = "json_report_created_event"

// Definition of this event is aligned with rs/tests/src/driver/log_events.rs
type TestDriverEvent struct {
	EventName string      `json:"event_name"`
	Body      interface{} `json:"body"`
}

type OutputFilepath struct {
	logPath string
}

func NewOutputFilepath(outputDir string, time time.Time) *OutputFilepath {
	return &OutputFilepath{
		logPath: filepath.Join(outputDir, fmt.Sprintf("%s_%s", time.Format(DATE_TIME_FORMAT), SUFFIX_LOG_FILE)),
	}
}

type TestnetConfig struct {
	outputDir    string
	verbose      bool
	lifetimeMins int
	isFuzzyMatch bool
	isDryRun     bool
}

// Testnet config summary published to json file.
type Summary struct {
	FarmGroupName   interface{}   `json:"farm"`
	KibanaUrl       interface{}   `json:"kibana_url"`
	IcTopology      interface{}   `json:"ic_topology"`
	VmConsoleLinks  []interface{} `json:"vm_console_links"`
	BnAAAARecords   interface{}   `json:"bn_aaaa_records"`
	PrometheusVm    interface{}   `json:"prometheus"`
	GrafanaLink     interface{}   `json:"grafana"`
	IcProgressClock interface{}   `json:"progress_clock"`
	FarmVMs         []interface{} `json:"farm_vms"`
}

func (summary *Summary) add_event(event *TestDriverEvent) {
	if event.EventName == IC_TOPOLOGY_EVENT {
		summary.IcTopology = event.Body
	} else if event.EventName == VM_CONSOLE_LINK_CREATED_EVENT {
		summary.VmConsoleLinks = append(summary.VmConsoleLinks, event.Body)
	} else if event.EventName == BN_AAAA_RECORDS_CREATED_EVENT {
		summary.BnAAAARecords = event.Body
	} else if event.EventName == PROMETHEUS_VM_CREATED_EVENT {
		summary.PrometheusVm = event.Body
	} else if event.EventName == GRAFANA_INSTANCE_CREATED_EVENT {
		summary.GrafanaLink = event.Body
	} else if event.EventName == IC_PROGRESS_CLOCK_CREATED_EVENT {
		summary.IcProgressClock = event.Body
	} else if event.EventName == FARM_VM_CREATED_EVENT {
		summary.FarmVMs = append(summary.FarmVMs, event.Body)
	} else if event.EventName == FARM_GROUP_NAME_CREATED_EVENT {
		summary.FarmGroupName = event.Body
	} else if event.EventName == KIBANA_URL_CREATED_EVENT {
		summary.KibanaUrl = event.Body
	}
}

func ValidateTestnetCommand(cfg *TestnetConfig) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		err := cmd.MarkFlagRequired("lifetime_mins")
		if err != nil {
			return err
		}
		if cfg.lifetimeMins <= 0 || cfg.lifetimeMins > MAX_TESTNET_LIFETIME_MINS {
			return fmt.Errorf("flag --lifetime_mins should be in range 0 < lifetime_mins <= %d mins", MAX_TESTNET_LIFETIME_MINS)
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
					cmd.PrintErrln(CYAN + msg + NC)
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
		lifetimeMins := fmt.Sprintf("--test_timeout=%s", strconv.Itoa(cfg.lifetimeMins*60))
		command = append(command, lifetimeMins)
		command = append(command, "--test_arg=--debug-keepalive")
		// Print Bazel command for debugging puroposes.
		cmd.PrintErrln(CYAN + "Raw Bazel command to be invoked: \n$ " + strings.Join(command, " ") + NC)
		if cfg.isDryRun {
			return nil
		} else {
			timeNow := time.Now()
			outputDir, err := CreateOutputDir(cfg.outputDir)
			if err != nil {
				return fmt.Errorf("couldn't create output directory %s, err: %v", cfg.outputDir, err)
			}
			OutputFilepath := NewOutputFilepath(outputDir, timeNow)
			cmd.PrintErrln(GREEN + "Testnet is being deployed, please wait ... " + NC + "(check deployment progress in " + OutputFilepath.logPath + ")")
			testnetExpirationTime := timeNow.Add(time.Minute * time.Duration(cfg.lifetimeMins))
			testnetCmd := exec.Command(command[0], command[1:]...)
			// Create buffer to capture both stdout and stderr.
			stdoutPipe, err := testnetCmd.StderrPipe()
			if err != nil {
				return err
			}
			// Redirect stdout to the same pipe as stderr.
			testnetCmd.Stdout = testnetCmd.Stderr
			err = testnetCmd.Start()
			if err != nil {
				return err
			}
			if err := ProcessLogs(stdoutPipe, cmd, OutputFilepath, cfg, testnetExpirationTime); err != nil {
				return err
			}
			return testnetCmd.Wait()
		}
	}
}

func NewTestnetCmd() *cobra.Command {
	var cfg = TestnetConfig{}
	var cmd = &cobra.Command{
		Use:               "testnet <testnet_name> [flags] [-- <bazel_args>]",
		Short:             "Spawn IC testnets for desired time periods. This command blocks the terminal.",
		Example:           "ict testnet small --lifetime_mins=20\nict testnet small --lifetime_mins=20 --verbose --output-dir=./tmp -- --test_tmpdir=./tmp (store artifacts, such as SSH keys)",
		Args:              cobra.MinimumNArgs(1),
		PersistentPreRunE: ValidateTestnetCommand(&cfg),
		RunE:              TestnetCommand(&cfg),
	}
	cmd.Flags().BoolVarP(&cfg.verbose, "verbose", "", false, "Print all testnet deployment log to stdout")
	cmd.Flags().StringVarP(&cfg.outputDir, "output-dir", "", "", fmt.Sprintf("Path to testnet deployment result files (default: %s)", os.TempDir()))
	cmd.Flags().IntVar(&cfg.lifetimeMins, "lifetime_mins", 0, fmt.Sprintf("Keep testnet alive for this duration in mins, max=%d", MAX_TESTNET_LIFETIME_MINS))
	cmd.Flags().BoolVarP(&cfg.isFuzzyMatch, "fuzzy", "", false, "Use fuzzy matching to find similar testnet names. Default: substring match")
	cmd.Flags().BoolVarP(&cfg.isDryRun, "dry-run", "n", false, "Print raw Bazel command to be invoked without execution")
	cmd.SetOut(os.Stdout)
	return cmd
}

func ProcessLogs(reader io.ReadCloser, cmd *cobra.Command, outputFiles *OutputFilepath, cfg *TestnetConfig, expiration time.Time) error {
	fullLogFile, err := os.Create(outputFiles.logPath)
	if err != nil {
		return fmt.Errorf("creating log file %s failed with err: %v", outputFiles.logPath, err)
	}
	defer fullLogFile.Close()
	scanner := bufio.NewScanner(reader)
	var summary Summary
	for scanner.Scan() {
		line := scanner.Text()
		if cfg.verbose {
			cmd.PrintErrln(line)
		}
		fullLogFile.WriteString(line + "\n")
		event, err := TryExtractEvent(line)
		if err != nil {
			return fmt.Errorf("couldn't extract an event from test-driver log, err: %v", err)
		}
		// We skip all non-event log lines.
		if event.EventName == JSON_REPORT_CREATED_EVENT {
			err = HasDeploymentSucceeded(event.Body)
			if err != nil {
				return fmt.Errorf("testnet deployment failed: %v", err)
			}
			// This event signifies the end of deployment.
			prettyJson, err := json.MarshalIndent(summary, "", "  ")
			if err != nil {
				return fmt.Errorf("marshalling summary failed with err: %v", err)
			}
			// Only this line goes to stdout, so that the command output can be piped to jq.
			cmd.Println(string(prettyJson))
			cmd.PrintErrln(GREEN + "Congrats, testnet was deployed successfully!" + NC)
			msg := fmt.Sprintf("%sTestnet will expire on %s or earlier if you close this terminal%s", PURPLE, expiration.Format(time.UnixDate), NC)
			cmd.PrintErrln(msg)
		} else {
			summary.add_event(&event)
		}
	}
	return nil
}

func HasDeploymentSucceeded(jsonReport interface{}) error {
	serializedMap := make(map[string]interface{})
	switch v := jsonReport.(type) {
	case map[string]interface{}:
		for key, value := range v {
			serializedMap[key] = value
		}
	default:
		return fmt.Errorf("json report is of an unsupported type")
	}
	failure := fmt.Sprintf("%v", serializedMap["failure"])
	if failure == "[]" {
		return nil
	}
	return fmt.Errorf("%s contains failure: %v", JSON_REPORT_CREATED_EVENT, failure)
}

func TryExtractEvent(logLine string) (TestDriverEvent, error) {
	startIdx := strings.Index(logLine, "{\"event_name\":")
	if startIdx != -1 {
		eventStr := logLine[startIdx:]
		var event TestDriverEvent
		if err := json.Unmarshal([]byte(eventStr), &event); err != nil {
			return TestDriverEvent{EventName: "", Body: ""}, fmt.Errorf("error when unmarshalling event err: %v", err)
		}
		return event, nil
	}
	return TestDriverEvent{EventName: "", Body: ""}, nil
}

func CreateOutputDir(outputDir string) (string, error) {
	if len(outputDir) == 0 {
		currentDir := os.TempDir()
		outputDir = filepath.Join(currentDir, DEFAULT_RESULTS_DIR)
	}
	if !filepath.IsAbs(outputDir) {
		currentDir, err := os.Getwd()
		if err != nil {
			return "", err
		}
		outputDir = filepath.Join(currentDir, outputDir)
	}
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		return "", err
	}
	return outputDir, nil
}
