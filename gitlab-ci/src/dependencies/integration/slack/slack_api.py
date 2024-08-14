import json
import logging
import traceback
import urllib.request
from typing import Dict, Optional

from integration.slack.slack_channel_config import SlackChannelConfig
from model.user import User


class SlackApi:
    channel_config: SlackChannelConfig
    log_to_console: bool
    oauth_token: str
    slack_id_cache: Dict[str, str] = {}

    def __init__(self, channel_config: SlackChannelConfig, log_to_console: bool, oauth_token: str):
        self.channel_config = channel_config
        self.log_to_console = log_to_console
        self.oauth_token = oauth_token

    def send_message(self, message: str):
        if self.log_to_console:
            logging.info("Mock Slack send_message to channel '%s': '%s' ", self.channel_config, message)
        else:
            logging.info("Slack send_message to channel '%s': '%s' ", self.channel_config, message)
            data = {
                "text": message,
                "channel": self.channel_config.channel_id,
            }
            req = urllib.request.Request(
                "https://slack.com/api/chat.postMessage",
                data=json.dumps(data).encode(),
                headers={"Authorization": f"Bearer {self.oauth_token}", "content-type": "application/json"},
            )

            try:
                urllib.request.urlopen(req, timeout=30)
            except urllib.error.HTTPError as e:
                body = e.read().decode()
                logging.error(
                    "Slack send_message failed."
                )
                logging.debug(
                    f"Slack send_message failed with HTTP response body: {body}\ntraceback:\n{traceback.format_exc()}"
                )
            except Exception:
                logging.error("Slack send_message could not send the requested message.")
                logging.debug(f"Slack send_message could not send the requested message.\ntraceback:\n{traceback.format_exc()}")

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
                    "Slack API users.lookupByEmail for some user returned non ok response."
                )
                logging.debug(
                    f"Slack API users.lookupByEmail for user {user} returned non ok response: {api_response['ok']} with error: {api_response['error'] if 'error' in api_response else 'None'}"
                )
        except Exception:
            logging.error(
                "There was an exception while calling Slack API users.lookupByEmail."
            )
            logging.debug(
                f"There was an exception while calling Slack API users.lookupByEmail:\n{traceback.format_exc()}"
            )
        return None
