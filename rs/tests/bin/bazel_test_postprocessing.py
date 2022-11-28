#!/usr/bin/env python3
import json
import logging
import os
import urllib.request
from typing import Dict
from typing import List
from typing import Set
from urllib.error import HTTPError
from urllib.error import URLError

CI_JOB_URL = os.getenv("CI_JOB_URL", default="")
CI_PROJECT_URL = os.getenv("CI_PROJECT_URL", default="")
CI_COMMIT_SHA = os.getenv("CI_COMMIT_SHA", default="")
CI_COMMIT_SHORT_SHA = os.getenv("CI_COMMIT_SHORT_SHA", default="")
SLACK_ALERT_CHANNEL = "#test-failure-alerts"
HONEYCOMB_DATASET = "bazel-system-tests-scheduled"

RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
BOLD = "\x1b[1m"
MAGENTA = "\x1b[35m"
NC = "\x1b[0m"


class CustomFormatter(logging.Formatter):
    def __init__(self, fmt):
        super().__init__()
        self.FORMATS = {
            logging.DEBUG: GREEN + fmt + NC,
            logging.INFO: BOLD + BLUE + fmt + NC,
            logging.WARNING: BOLD + YELLOW + fmt + NC,
            logging.ERROR: BOLD + RED + fmt + NC,
        }

    def format(self, record):
        formatter = logging.Formatter(self.FORMATS.get(record.levelno))
        return formatter.format(record)


# Define format for logs
fmt = "%(asctime)s | %(levelname)8s | %(message)s"

# Create custom logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create stdout handler for logging to the console
stdout_handler = logging.StreamHandler()
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(CustomFormatter(fmt))
logger.addHandler(stdout_handler)


def make_request(url, headers=None, data=None):
    request = urllib.request.Request(url, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(request) as response:
            return response.read(), response
    except HTTPError as error:
        return error.status, error.reason
    except URLError as error:
        return "", error.reason
    except TimeoutError:
        return "", "Request timed out"
    except Exception as exception:
        return "", str(exception)


def send_event_to_honeycomb(honeycomb_api_key: str, event_data: List[Dict]):
    json_string = json.dumps(event_data)
    post_data = json_string.encode("utf-8")
    body, response = make_request(
        url=f"https://api.honeycomb.io/1/batch/{HONEYCOMB_DATASET}",
        data=post_data,
        headers={"X-Honeycomb-Team": honeycomb_api_key},
    )
    if hasattr(response, "status"):
        if response.status == 200:
            logger.debug(f"Successfully queued Honeycomb event, status_code={response.status}, message={body}.")
        else:
            logger.error(f"Failed to queue Honeycomb event, status_code={response.status}, error={body}.")
    else:
        logger.error(f"Failed to queue Honeycomb event, error={body}.")


def send_slack_alert(webhook_url: str, channel: str, message: str) -> None:
    post_dict = {"text": message, "channel": channel}
    json_string = json.dumps(post_dict)
    post_data = json_string.encode("utf-8")
    body, response = make_request(
        webhook_url,
        data=post_data,
        headers={"Content-Type": "application/json"},
    )
    if hasattr(response, "status"):
        if response.status == 200:
            logger.debug(f"Successfully sent slack message to channel={channel}.")
        else:
            logger.error(
                f"Failed to send slack message to channel={channel}, " f"status_code={response}, error_message={body}."
            )
    else:
        logger.error(f"Failed to send slack message to channel={channel}, " f"error={body}.")


def send_slack_alerts_from_file(webhook_url: str, filename: str):
    with open(filename) as json_file:
        data = json.load(json_file)
    for channel in data["channels"]:
        send_slack_alert(webhook_url=webhook_url, channel=channel, message=data["message"])


def save_slack_alert(filename: str, test_name: str, slack_channels: List[str]):
    job_log_info = f"<{CI_JOB_URL}|log>" if CI_JOB_URL else " during *manual* run"
    message = (
        f"Bazel test target *{test_name}* failed, {job_log_info}. :x:\n"
        f"Commit: <{CI_PROJECT_URL}/-/commit/{CI_COMMIT_SHA}|{CI_COMMIT_SHORT_SHA}>."
    )
    json_string = {"channels": slack_channels, "message": message}
    with open(filename, "w") as outfile:
        json.dump(json_string, outfile)


class Config:
    def __init__(
        self, output_dir: str, build_event_json_path: str, slack_webhook_url: str, honeycomb_api_token: str
    ) -> None:
        self.build_event_json_path = build_event_json_path
        self.output_dir = output_dir
        self.slack_webhook_url = slack_webhook_url
        self.honeycomb_api_token = honeycomb_api_token


def find_system_test_targets_in_BEP(file_path: str) -> Set[str]:
    system_test_targets = set()
    # This value (keyword) determines, if a given target is a system_test target.
    system_test__needle = "run_system_test rule"
    # We search for all occurrences of this needle in the BEP file.
    with open(file_path) as file:
        for line in file:
            line_dict = json.loads(line)
            if "id" in line_dict and "targetConfigured" in line_dict["id"]:
                target = line_dict["id"]["targetConfigured"]["label"]
                if (
                    "configured" in line_dict
                    and "targetKind" in line_dict["configured"]
                    and line_dict["configured"]["targetKind"] == system_test__needle
                ):
                    system_test_targets.add(target)
    return system_test_targets


def extract_execution_results_for_targets_in_BEP(file_path: str, targets: Set) -> Dict[str, str]:
    results = dict.fromkeys(targets, "FAILED")
    with open(file_path) as file:
        for line in file:
            line_dict = json.loads(line)
            if (
                "id" in line_dict
                and "testSummary" in line_dict["id"]
                and line_dict["id"]["testSummary"]["label"] in targets
            ):
                if "testSummary" in line_dict:
                    results[line_dict["id"]["testSummary"]["label"]] = line_dict["testSummary"]["overallStatus"]
    return results


def process_bazel_results(file_path: str) -> Dict[str, str]:
    # build_event_json_file is not a JSON, but a line-delimited JSON file.
    # To extract test target names and their execution statuses, we parse each file line
    # into a dict and process it.
    test_targets = find_system_test_targets_in_BEP(file_path)
    test_targets_results = extract_execution_results_for_targets_in_BEP(file_path, test_targets)
    return test_targets_results


def main(config: Config) -> None:
    test_targets_results = process_bazel_results(config.build_event_json_path)
    honeycomb_events = []
    slack_alert_files = []
    if len(test_targets_results) == 0:
        logger.warn(f"No targets with `run_system_test rule` detected in {config.build_event_json_path}")
    for test_target_name, execution_status in test_targets_results.items():
        honeycomb_events.append(
            {"data": {"test_target": test_target_name, "execution_result": execution_status, "job_url": CI_JOB_URL}}
        )
        if execution_status == "PASSED":
            logger.info(f"Test target {test_target_name} was executed successfully.")
        else:
            logger.error(f"Test target {test_target_name} has failed.")
            test_name = test_target_name.replace("/", "_").replace(":", "_")
            slack_filename = f"{config.output_dir}/{test_name}_slack_alert.json"
            slack_alert_files.append(slack_filename)
            save_slack_alert(filename=slack_filename, test_name=test_target_name, slack_channels=[SLACK_ALERT_CHANNEL])
    # Send all slack alerts
    if len(slack_alert_files) != 0 and config.slack_webhook_url:
        for file in slack_alert_files:
            send_slack_alerts_from_file(webhook_url=config.slack_webhook_url, filename=file)
    # Send all Honeycomb notifications.
    if len(honeycomb_events) != 0 and config.honeycomb_api_token:
        send_event_to_honeycomb(honeycomb_api_key=config.honeycomb_api_token, event_data=honeycomb_events)


if __name__ == "__main__":
    # Get slack webhook from the env variable.
    slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    # Get Honeycomb token from the env variable.
    honeycomb_api_token = os.environ.get("HONEYCOMB_API_TOKEN", "")
    build_event_json_path = os.environ.get("BUILD_EVENT_JSON_PATH", "")
    logging.debug(f"BUILD_EVENT_JSON_PATH={build_event_json_path}")
    output_dir = os.environ.get("OUTPUT_DIR", "")
    logging.debug(f"OUTPUT_DIR={output_dir}")
    if not build_event_json_path:
        logger.error("BUILD_EVENT_JSON_PATH variable is not defined.")
        exit(1)
    if not output_dir:
        logger.error("OUTPUT_DIR variable is not defined.")
        exit(1)
    if not slack_webhook_url:
        logger.warning("Slack alerts are turned off. Provide SLACK_WEBHOOK_URL env var to send alerts.")
    if not honeycomb_api_token:
        logger.warning(
            "Honeycomb notifications are turned off. Provide HONEYCOMB_API_TOKEN env var to send notifications."
        )
    # Assemble config.
    config = Config(
        output_dir=output_dir,
        build_event_json_path=build_event_json_path,
        slack_webhook_url=slack_webhook_url,
        honeycomb_api_token=honeycomb_api_token,
    )
    main(config)
