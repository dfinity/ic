#!/usr/bin/env python3
import json
import logging
import os
import urllib.request
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from urllib.error import HTTPError
from urllib.error import URLError

CI_JOB_URL = os.getenv("CI_JOB_URL", default="")
CI_PROJECT_URL = os.getenv("CI_PROJECT_URL", default="")
CI_COMMIT_SHA = os.getenv("CI_COMMIT_SHA", default="")
CI_COMMIT_SHORT_SHA = os.getenv("CI_COMMIT_SHORT_SHA", default="")
SLACK_FILE = "slack_alert.json"
SLACK_ALERT_CHANNEL = "#test-failure-alerts"

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
        self, output_dir: str, build_event_json_path: str, slack_webhook_url: str, with_slack_alert: bool
    ) -> None:
        self.build_event_json_path = build_event_json_path
        self.output_dir = output_dir
        self.with_slack_alert = with_slack_alert
        self.slack_webhook_url = slack_webhook_url


def find_first_key_in_dict(d: Dict, search_key: str) -> Optional[str]:
    for key, value in d.items():
        if key == search_key:
            return value
        elif isinstance(value, dict):
            value = find_first_key_in_dict(value, search_key)
            if value is not None:
                return value
    return None


def process_bazel_results(file_path: str) -> Tuple[str, str]:
    status = ""
    test_target = ""
    # build_event_json_file is not a JSON, but a line-delimited JSON file.
    # To extract test execution status and test target name, we parse each line
    # into a dict and search recursively for keys: "overallStatus" and "targetConfigured".
    with open(file_path) as file:
        for line in file:
            line_dict = json.loads(line)
            status_value = find_first_key_in_dict(line_dict, "overallStatus")
            test_target_value = find_first_key_in_dict(line_dict, "targetConfigured")
            if not status and status_value is not None:
                status = status_value
            if not test_target and test_target_value is not None:
                test_target = test_target_value["label"]  # type: ignore
    if not status:
        Exception(f"Bazel test status couldn't be extracted from {file_path}")
    if not test_target:
        Exception(f"Bazel test target couldn't be extracted from {file_path}")
    return (status, test_target)


def main(config: Config) -> None:
    test_exec_status, test_target_name = process_bazel_results(config.build_event_json_path)
    slack_filename = f"{config.output_dir}/{SLACK_FILE}"
    if test_exec_status != "PASSED":
        logger.error(f"Test target {test_target_name} has failed.")
        save_slack_alert(filename=slack_filename, test_name=test_target_name, slack_channels=[SLACK_ALERT_CHANNEL])
        if config.with_slack_alert:
            send_slack_alerts_from_file(webhook_url=config.slack_webhook_url, filename=slack_filename)
    else:
        logger.info(f"Test target {test_target_name} was executed successfully.")


if __name__ == "__main__":
    # Get slack webhook from the env variable.
    slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    build_event_json_path = os.environ.get("BUILD_EVENT_JSON_PATH", "")
    logging.debug(f"BUILD_EVENT_JSON_PATH={build_event_json_path}")
    with_slack_alerts = bool(os.environ.get("WITH_SLACK_ALERTS", "False"))
    output_dir = os.environ.get("OUTPUT_DIR", "")
    logging.debug(f"OUTPUT_DIR={output_dir}")
    if not build_event_json_path:
        logger.error("BUILD_EVENT_JSON_PATH variable is not defined.")
        exit(1)
    if not output_dir:
        logger.error("OUTPUT_DIR variable is not defined.")
        exit(1)
    if not with_slack_alerts:
        logger.warning("Slack alerts are turned off. Use --with_slack_alerts flag to send alerts.")
    # Assemble config.
    config = Config(
        output_dir=output_dir,
        build_event_json_path=build_event_json_path,
        slack_webhook_url=slack_webhook_url,
        with_slack_alert=with_slack_alerts,
    )
    main(config)
