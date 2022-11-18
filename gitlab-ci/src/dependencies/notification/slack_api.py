import json
import logging
import os
import traceback
import urllib.request
from typing import Dict
from typing import Optional

from model.user import User


class SlackApi:
    channel: str
    log_to_console: bool
    webhook: str
    oauth_token: str
    slack_id_cache: Dict[str, str] = {}

    def __init__(self, channel: str, log_to_console: bool, webhook: str, oauth_token: str):
        self.channel = channel
        self.log_to_console = log_to_console
        self.webhook = webhook
        self.oauth_token = oauth_token

    @staticmethod
    def __send_message(
        message: str,
        channel: str = "#precious-bots",
        webhook_url: str = os.environ.get("SLACK_WEBHOOK_URL"),
        dry_run: bool = None,  # If dry_run is not provided, run based on env var CI
    ):
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
                logging.error(
                    f"Slack send_message failed with HTTP response body: {body}\ntraceback:\n{traceback.format_exc()}"
                )
            except Exception:
                logging.error(f"Slack send_message could not send the requested message.\n{traceback.format_exc()}")

    def send_message(self, message: str):
        SlackApi.__send_message(message, self.channel, self.webhook, self.log_to_console)

    def try_get_slack_id(self, user: User) -> Optional[str]:
        if user.email is None:
            return None
        if user.email in self.slack_id_cache:
            return self.slack_id_cache[user.email]

        req = urllib.request.Request(
            f"https://slack.com/api/users.lookupByEmail?email={user.email}",
            headers={"Authorization": f"Bearer {self.oauth_token}"},
        )

        try:
            http_response = urllib.request.urlopen(req, timeout=30)
            # https://api.slack.com/methods/users.lookupByEmail#examples
            api_response = json.loads(http_response.read())
            if api_response["ok"]:
                self.slack_id_cache[user.email] = api_response["user"]["id"]
                return self.slack_id_cache[user.email]
            else:
                logging.error(
                    f"Slack API users.lookupByEmail for user {user} returned non ok response: {api_response['ok']} with error: {api_response['error'] if 'error' in api_response else 'None'}"
                )
        except Exception:
            logging.error(
                f"There was an exception while calling Slack API users.lookupByEmail:\n{traceback.format_exc()}"
            )
        return None
