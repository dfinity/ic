#!/usr/bin/env python3
"""
Sends a `message` to a Slack `channel`.

The Slack Webhook URL can be provided in an environment variable SLACK_WEBHOOK_URL.
The Slack channel can be provided in an environment variable SLACK_CHANNEL.
Alternatively, both of these can be provided as command line arguments.
"""
import argparse
import http.client
import json
import logging
import os
import urllib.request


def send_message(
    message: str,
    channel: str = "#precious-bots",
    webhook_url: str = os.environ.get("SLACK_WEBHOOK_URL"),
    dry_run: bool = None,  # If dry_run is not provided, run based on env var CI
) -> http.client:
    """
    Send the `message` to the provided Slack `channel`.

    When not running on the CI, will instead print the message on the console.
    """
    if not webhook_url:
        raise ValueError("SLACK_WEBHOOK_URL env var not found")

    if not channel.startswith("#") and not channel.startswith("@"):
        channel = "#" + channel

    if dry_run is None:
        if os.environ.get("CI"):
            dry_run = False
        else:
            dry_run = True

    if dry_run:
        logging.info("Mock Slack send_message to channel '%s': '%s' ", channel, message)
    else:
        logging.info("Slack send_message to channel '%s': '%s' ", channel, message)
        data = {
            "text": message,
            "channel": channel,
        }
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(data).encode(),
            headers={"content-type": "application/json"},
        )

        try:
            response = urllib.request.urlopen(req, timeout=30)
            return response
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            logging.error("Slack send_message failed with HTTP response body: %s", body)
        except Exception:
            logging.error("Slack send_message could not send the requested message.")


def non_empty_string(value: str) -> str:
    """Ensure that the `value` is not empty."""
    if not value:
        raise argparse.ArgumentTypeError("Cannot proceed with an empty value: '%s'" % value)
    return value


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--webhook-url",
        help="The Slack Webhook URL \
                            (default: environment variable SLACK_WEBHOOK_URL)",
        type=non_empty_string,
        nargs="?",
        const=os.environ.get("SLACK_WEBHOOK_URL", ""),
        default=os.environ.get("SLACK_WEBHOOK_URL", ""),
    )

    parser.add_argument(
        "--channel",
        help="The Slack channel name to which to post the message to \
                            (default: environment variable SLACK_CHANNEL)",
        type=non_empty_string,
        nargs="?",
        const=os.environ.get("SLACK_CHANNEL", "#precious-bots"),
        default=os.environ.get("SLACK_CHANNEL", "#precious-bots"),
    )

    parser.add_argument(
        "--dry-run",
        help="Whether to mock (log) sending Slack messages",
        action="store_true",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    parser.add_argument("message", help="The message to post to Slack")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    send_message(
        message=args.message,
        channel=args.channel,
        webhook_url=args.webhook_url,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
