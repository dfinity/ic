package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// This defines timeout on the Bazel level.
var TESTNET_DEPLOYMENT_TIMEOUT_SEC = 5400

var FARM_BASE_URL = "https://farm.dfinity.systems"
var FARM_API = FARM_BASE_URL + "/swagger-ui"
var FARM_GROUP_KEEPALIVE_TTL_SEC = 90
var KEEPALIVE_PERIOD = 30 * time.Second

// This restriction is defined in an ad-hoc way to avoid accidental resources abuse.
var MAX_TESTNET_LIFETIME_MINS = 1440 * 7

// All output files are saved in this folder, if output-dir is not provided explicitly.
var DEFAULT_RESULTS_DIR = "ict_testnets"

// Logs are streamed into this file during testnet deployment.
var SUFFIX_LOG_FILE = ".log"

// Filenames are prefixed with this datetime format up to milliseconds.
var DATE_TIME_FORMAT = "2006-01-02_15-04-05.000"

// Maximum size used to buffer a token from stdout pipe (max characters in line).
const MAX_TOKEN_CAPACITY = 1024 * 1024

// These events are collected from test-driver logs during the testnet deployment.
const INFRA_GROUP_NAME_CREATED_EVENT = "infra_group_name_created_event"
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

// This is the name of bazel target used to spawn a testnet from file configuration
const FROM_CONFIG = "from_config"

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
		logPath: filepath.Join(outputDir, fmt.Sprintf("%s%s", time.Format(DATE_TIME_FORMAT), SUFFIX_LOG_FILE)),
	}
}

type TestnetConfig struct {
	isDetached           bool
	outputDir            string
	verbose              bool
	lifetimeMins         int
	isFuzzyMatch         bool
	isDryRun             bool
	requiredHostFeatures string
	icConfigPath         string
}

// Testnet config summary published to json file.
type Summary struct {
	FarmGroup       interface{}   `json:"farm"`
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
	} else if event.EventName == INFRA_GROUP_NAME_CREATED_EVENT {
		summary.FarmGroup = event.Body
	} else if event.EventName == KIBANA_URL_CREATED_EVENT {
		summary.KibanaUrl = event.Body
	}
}

func ValidateTestnetCommand(cfg *TestnetConfig) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		err := cmd.MarkFlagRequired("lifetime-mins")
		if err != nil {
			return err
		}
		if cfg.lifetimeMins <= 0 || cfg.lifetimeMins > MAX_TESTNET_LIFETIME_MINS {
			return fmt.Errorf("flag --lifetime-mins should be in range 0 < lifetime-mins <= %d mins", MAX_TESTNET_LIFETIME_MINS)
		}
		if cfg.icConfigPath != "" {
			if _, err := os.Stat(cfg.icConfigPath); os.IsNotExist(err) {
				return fmt.Errorf("ic config path '%s' does not exist", cfg.icConfigPath)
			}
		}
		return nil
	}
}

func TestnetCommand(cfg *TestnetConfig) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		config := ""
		if cfg.icConfigPath != "" {
			if len(args) > 0 {
				return fmt.Errorf("Cannot provide both `--from-ic-config-path` and a name for testnet configuration: %s", args[0])
			}
			args = append(args, FROM_CONFIG)
			json_bytes, err := os.ReadFile(cfg.icConfigPath)
			if err != nil {
				return err
			}
			if !json.Valid(json_bytes) {
				return fmt.Errorf("File provided isn't valid json")
			}
			dst := &bytes.Buffer{}
			if err := json.Compact(dst, json_bytes); err != nil {
				return fmt.Errorf("Cannot minify json: %s", err)
			}
			config = dst.String()
		}

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
		command = append(command, "--cache_test_results=no")
		command = append(command, fmt.Sprintf("--test_timeout=%s", strconv.Itoa(TESTNET_DEPLOYMENT_TIMEOUT_SEC)))
		// We let the test-driver (and Bazel command) finish without deleting Farm group.
		// Afterwards, we interact with the group's ttl via Farm API.
		command = append(command, "--test_arg=--no-delete-farm-group")
		if len(cfg.requiredHostFeatures) > 0 {
			command = append(command, "--test_arg=--set-required-host-features="+cfg.requiredHostFeatures)
		}
		// If the user provided a special config path we add it as an environment variable
		if config != "" {
			command = append(command, fmt.Sprintf("--test_env=IC_CONFIG='%s'", config))
		}
		// Append all bazel args following the --, i.e. "ict test target -- --verbose_explanations --test_timeout=20 ..."
		// Note: arguments provided by the user might override the ones above, i.e. test_timeout, cache_test_results, etc.
		command = append(command, args[1:]...)
		// Print Bazel command for debugging puroposes.
		cmd.PrintErrln(CYAN + "Raw Bazel command to be invoked: \n$ " + strings.Join(command, " ") + NC)
		if cfg.isDryRun {
			return nil
		}
		outputDir, err := CreateOutputDir(cfg.outputDir)
		if err != nil {
			return fmt.Errorf("couldn't create output directory %s, err: %v", cfg.outputDir, err)
		}
		outputFilepath := NewOutputFilepath(outputDir, time.Now())
		cmd.PrintErrln(GREEN + "Testnet is being deployed, please wait ... " + NC + "(check progress in the docker dir " + outputFilepath.logPath + ")")
		testnetCmd := exec.Command(command[0], command[1:]...)
		// Create buffer to capture both stdout and stderr.
		stdoutPipe, err := testnetCmd.StderrPipe()
		if err != nil {
			return err
		}
		defer stdoutPipe.Close()
		// Redirect stdout to the same pipe as stderr.
		testnetCmd.Stdout = testnetCmd.Stderr
		if err := testnetCmd.Start(); err != nil {
			return err
		}
		// Process life logs output of the test-driver.
		group, err := ProcessLogs(stdoutPipe, cmd, outputFilepath, cfg)
		if err != nil {
			return err
		}
		if err = testnetCmd.Wait(); err != nil {
			return err
		}
		cmd.PrintErrf("%sCongrats, testnet with Farm group=%s was deployed successfully!%s\n", GREEN, group, NC)
		if cfg.isDetached {
			if err := SetTestnetLifetime(group, cfg.lifetimeMins*60); err != nil {
				return err
			}
			if expiration, err := GetTestnetExpiration(group); err != nil {
				return err
			} else {
				cmd.PrintErrf("%sTestnet will expire on %s%s\n", PURPLE, expiration, NC)
				cmd.PrintErrf("%sNOTE: All further interactions with testnet (e.g., increasing testnet lifetime), should be done manually via Farm API, see %s%s\n", YELLOW, FARM_API, NC)
			}
		} else {
			testnetExpirationTime := time.Now().Add(time.Minute * time.Duration(cfg.lifetimeMins))
			cmd.PrintErrf("%sTestnet will expire on %s or earlier if you close this terminal%s\n", PURPLE, testnetExpirationTime.Format(time.UnixDate), NC)
			if err = KeepTestnetAlive(group, testnetExpirationTime, outputFilepath, cfg, cmd); err != nil {
				return err
			}
			if err = DeleteTestnet(group); err != nil {
				cmd.PrintErrln("failed to delete testnet: %v", err)
				return err
			}
			cmd.PrintErrln(GREEN + "Testnet was deleted successfully" + NC)
		}
		return nil
	}
}

func NewTestnetCreateCmd() *cobra.Command {
	var cfg = TestnetConfig{}
	var cmd = &cobra.Command{
		Use:               "create <testnet_name> [flags] [-- <bazel_args>]",
		Short:             "Create IC testnet for the desired time period. This command blocks the terminal.",
		Example:           "ict testnet create small --lifetime-mins=20\nict testnet create small --lifetime-mins=20 --verbose --output-dir=./tmp -- --test_tmpdir=./tmp (store artifacts, such as SSH keys)",
		Args:              cobra.MinimumNArgs(0),
		PersistentPreRunE: ValidateTestnetCommand(&cfg),
		RunE:              TestnetCommand(&cfg),
	}
	cmd.Flags().BoolVarP(&cfg.verbose, "verbose", "", false, "Print all testnet deployment log to stdout")
	cmd.Flags().StringVarP(&cfg.outputDir, "output-dir", "", "", fmt.Sprintf("Docker path to testnet deployment result files (default: %s)", os.TempDir()))
	cmd.Flags().IntVar(&cfg.lifetimeMins, "lifetime-mins", 0, fmt.Sprintf("Keep testnet alive for this duration in mins, max=%d", MAX_TESTNET_LIFETIME_MINS))
	cmd.Flags().BoolVarP(&cfg.isFuzzyMatch, "fuzzy", "", false, "Use fuzzy matching to find similar testnet names. Default: substring match")
	cmd.Flags().BoolVarP(&cfg.isDryRun, "dry-run", "n", false, "Print raw Bazel command to be invoked without execution")
	cmd.Flags().BoolVarP(&cfg.isDetached, "experimental-detached", "", false, fmt.Sprintf("Create a testnet without blocking the console\nNOTE: extending testnet lifetime (ttl) should be done manually\nSee Farm API %s", FARM_API))
	cmd.Flags().StringVarP(&cfg.icConfigPath, "from-ic-config-path", "", "", "Provide a custom config describing the desired layout of the network to be deployed")
	cmd.PersistentFlags().StringVarP(&cfg.requiredHostFeatures, "set-required-host-features", "", "", "Set and override required host features of all hosts spawned.\nFeatures must be one or more of [dc=<dc-name>, host=<host-name>, AMD-SEV-SNP, SNS-load-test, performance], separated by comma (see Examples).")
	cmd.SetOut(os.Stdout)
	return cmd
}

func ProcessLogs(reader io.ReadCloser, cmd *cobra.Command, outputFiles *OutputFilepath, cfg *TestnetConfig) (string, error) {
	fullLogFile, err := os.Create(outputFiles.logPath)
	if err != nil {
		return "", fmt.Errorf("creating log file %s failed with err: %v", outputFiles.logPath, err)
	}
	defer fullLogFile.Close()
	scanner := bufio.NewScanner(reader)
	// Adjust the buffer capacity to read long log lines.
	buf := make([]byte, MAX_TOKEN_CAPACITY)
	scanner.Buffer(buf, MAX_TOKEN_CAPACITY)
	var summary Summary
	var group string
	for scanner.Scan() {
		line := scanner.Text()
		if cfg.verbose {
			cmd.PrintErrln(line)
		}
		fullLogFile.WriteString(line + "\n")
		event, err := TryExtractEvent(line)
		if err != nil {
			return "", fmt.Errorf("couldn't extract an event from test-driver log, err: %v", err)
		}
		if event.EventName == JSON_REPORT_CREATED_EVENT {
			// This event signifies the end of the testnet deployment.
			err = HasDeploymentSucceeded(event.Body)
			if err != nil {
				return "", fmt.Errorf("testnet deployment failed: %v", err)
			}
			var buffer bytes.Buffer
			encoder := json.NewEncoder(&buffer)
			// Here we change the default encoding behavior, as urls can contain special symbols like &. We don't want to escape those.
			encoder.SetEscapeHTML(false)
			encoder.SetIndent("", "  ")
			err = encoder.Encode(summary)
			if err != nil {
				return "", fmt.Errorf("marshalling summary failed with err: %v", err)
			} else {
				prettyJson := buffer.String()
				// Only this line goes to stdout, so that the command output can be piped to jq.
				cmd.Println(string(prettyJson))
			}
			group, err = ExtractFarmGroup(&summary)
			if err != nil {
				return "", err
			}
		} else {
			summary.add_event(&event)
		}
	}
	return group, nil
}

func DeleteTestnet(group string) error {
	url := FARM_BASE_URL + "/group/" + group
	request, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return err
	}
	client := http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, err := io.ReadAll((response.Body))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("failed to delete group via %s, status_code=%d, body={%s}", url, response.StatusCode, string(body))
	}
	return nil
}

func KeepTestnetAlive(group string, expiration time.Time, outputFiles *OutputFilepath, cfg *TestnetConfig, cmd *cobra.Command) error {
	file, err := os.OpenFile(outputFiles.logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	for time.Now().Before(expiration) {
		if err := SetTestnetLifetime(group, FARM_GROUP_KEEPALIVE_TTL_SEC); err != nil {
			return err
		}
		msg := fmt.Sprintf("Testnet lifetime was set to %d sec, next invocation in %.1f sec\n", FARM_GROUP_KEEPALIVE_TTL_SEC, KEEPALIVE_PERIOD.Seconds())
		file.WriteString(msg)
		if cfg.verbose {
			cmd.PrintErrf(msg)
		}
		time.Sleep(KEEPALIVE_PERIOD)
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

func ExtractFarmGroup(summary *Summary) (string, error) {
	farmGroup := summary.FarmGroup
	jsonMap := farmGroup.(map[string]interface{})
	if val, ok := jsonMap["group"]; ok {
		return val.(string), nil
	}
	return "", fmt.Errorf("couldn't extract infra group from %s", INFRA_GROUP_NAME_CREATED_EVENT)
}

func GetTestnetExpiration(group string) (string, error) {
	url := FARM_BASE_URL + "/group/" + group
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	client := http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode != 200 {
		return "", fmt.Errorf("failed to get group via %s, status_code=%d, body={%s}", url, response.StatusCode, string(body))
	}
	serializedMap := make(map[string]interface{})
	err = json.Unmarshal(body, &serializedMap)
	if err != nil {
		return "", err
	}
	expiration := fmt.Sprintf("%v", serializedMap["expiresAt"])
	return expiration, nil
}

func SetTestnetLifetime(group string, lifetimeSec int) error {
	// Farm uses ttl (time-to-live) in seconds.
	ttl := strconv.Itoa(lifetimeSec)
	url := FARM_BASE_URL + "/group/" + group + "/ttl/" + ttl
	request, err := http.NewRequest("PUT", url, nil)
	if err != nil {
		return err
	}
	client := http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, err := io.ReadAll((response.Body))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("failed to set group lifetime (ttl) via %s, status_code=%d, body={%s}", url, response.StatusCode, string(body))
	}
	return nil
}
