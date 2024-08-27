import json
import logging
import traceback
import urllib.request
from time import sleep
from typing import Dict, List, Optional

from integration.slack.slack_channel_config import SlackChannelConfig
from integration.slack.slack_message import SlackMessage
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

    def __api_request(self, url: str, data: Optional[any] = None, retry: int = 0) -> Optional[any]:
        logging.debug(f"Slack API request {url} made with data {data} and retries {retry}")
        req = urllib.request.Request(
            url=url,
            data=json.dumps(data).encode(),
            headers={"Authorization": f"Bearer {self.oauth_token}", "content-type": "application/json; charset=utf-8"},
        )
        while retry >= 0:
            try:
                http_response = urllib.request.urlopen(req, timeout=30)
                return json.loads(http_response.read())
            except urllib.error.HTTPError as e:
                body = e.read().decode()
                logging.error(
                    f"Slack API request {url} failed."
                )
                logging.debug(
                    f"Slack API request {url} failed with HTTP response body: {body}\ntraceback:\n{traceback.format_exc()}"
                )
            except Exception:
                logging.error(f"Slack API request {url} could not send the requested message.")
                logging.debug(f"Slack API request {url} could not send the requested message.\ntraceback:\n{traceback.format_exc()}")
            retry -= 1
            if retry >= 0:
                sleep(1)
        return None

    def send_message(self, message: str, is_block_kit_message: bool = False, thread_id: Optional[str] = None) -> Optional[str]:
        if self.log_to_console:
            logging.info("Mock Slack send_message to channel '%s' and thread '%s': '%s'", self.channel_config, thread_id, message)
            return None

        logging.info("Slack send_message to channel '%s' and thread '%s': '%s'", self.channel_config, thread_id, message)

        data = {
            "channel": self.channel_config.channel_id,
        }
        if is_block_kit_message:
            data["blocks"] = message
        else:
            data["text"] = message
        if thread_id:
            data["thread_ts"] = thread_id

        api_response = self.__api_request("https://slack.com/api/chat.postMessage", data, retry=3)
        if api_response["ok"]:
            return api_response["ts"]
        return None

    def update_message(self, message: str, message_id: str, is_block_kit_message: bool = False):
        if self.log_to_console:
            logging.info("Mock Slack update_message to channel '%s' and message '%s': '%s'", self.channel_config, message_id, message)
            return

        logging.info("Slack update_message to channel '%s' and message '%s': '%s'", self.channel_config, message_id, message)
        data = {
            "channel": self.channel_config.channel_id,
            "ts": message_id,
        }
        if is_block_kit_message:
            data["blocks"] = message
        else:
            data["text"] = message
        self.__api_request("https://slack.com/api/chat.update", data, retry=3)

    def delete_message(self, message_id: str):
        if self.log_to_console:
            logging.info("Mock Slack delete_message from channel '%s' with message id: '%s'", self.channel_config, message_id)
            return

        logging.info("Slack delete_message from channel '%s' with message id: '%s'", self.channel_config, message_id)
        data = {
            "channel": self.channel_config.channel_id,
            "ts": message_id,
        }

        self.__api_request("https://slack.com/api/chat.delete", data, retry=3)

    def add_reaction(self, reaction: str, message_id: str):
        if self.log_to_console:
            logging.info("Mock Slack add_reaction to channel '%s' and message '%s': '%s'", self.channel_config, message_id, reaction)

        logging.info("Slack add_reaction to channel '%s' and message '%s': '%s'", self.channel_config, message_id, reaction)
        data = {
            "name": reaction,
            "channel": self.channel_config.channel_id,
            "timestamp": message_id,
        }

        self.__api_request("https://slack.com/api/reactions.add", data, retry=3)

    def try_get_slack_id(self, user: User) -> Optional[str]:
        if user.email is None:
            return None
        if user.email in self.slack_id_cache:
            return self.slack_id_cache[user.email]

        logging.info("Slack try_get_slack_id for user: '%s'", user)
        # https://api.slack.com/methods/users.lookupByEmail#examples
        api_response = self.__api_request(f"https://slack.com/api/users.lookupByEmail?email={user.email}")
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
        return None

    def get_channel_history(self, oldest: Optional[str] = None, author: Optional[str] = None, prefix: Optional[str] = None, ignore_reaction: Optional[str] = None) -> List[SlackMessage]:
        def include_message(message: any) -> bool:
            if author and ("user" not in message or message["user"] != author):
                return False
            if prefix:
                has_text_prefix = "text" in message and message["text"].startswith(prefix)
                if not has_text_prefix:
                    # text parsing of block messages isn't reliable -> check if the prefix is in the first block
                    has_one_block = "blocks" in message and len(message["blocks"]) > 0
                    if not (has_one_block and prefix in str(message["blocks"][0])):
                        return False
            if ignore_reaction and "reactions" in message:
                for reaction in message["reactions"]:
                    if "name" in reaction and reaction["name"] == ignore_reaction:
                        if author and "users" in reaction:
                            for user in reaction["users"]:
                                if user == author:
                                    return False
                        else:
                            return False
            return True

        logging.info("Slack get_channel_history from channel '%s' with filters: (%s, %s, %s, %s)", self.channel_config, oldest, author, prefix, ignore_reaction)
        cursor = None
        slack_messages = []
        while True:
            url = f"https://slack.com/api/conversations.history?limit=999&channel={self.channel_config.channel_id}"
            if oldest:
                url += f"&oldest={oldest}"
            if cursor:
                url += f"&cursor={cursor}"

            # https://api.slack.com/methods/conversations.history#examples
            api_response = self.__api_request(url, retry=3)

            if api_response["ok"]:
                for message in api_response["messages"]:
                    if include_message(message):
                        blocks = message["blocks"] if "blocks" in message else None
                        slack_messages.append(SlackMessage(id=message["ts"], text=message["text"], blocks=blocks))
                if "response_metadata" in api_response and "next_cursor" in api_response["response_metadata"]:
                    cursor = api_response["response_metadata"]["next_cursor"]
                else:
                    return slack_messages
            else:
                raise RuntimeError(
                    f"Slack API conversations.history returned non ok response for URL {url}: {api_response['ok']} with error: {api_response['error'] if 'error' in api_response else 'None'}")
