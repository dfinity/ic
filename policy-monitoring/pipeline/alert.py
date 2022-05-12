import os
import pprint
import random
from typing import Optional

from slack_sdk.webhook import WebhookClient
from util.print import eprint


class AlertService:
    def __init__(self, secret_service: str, signature: Optional[str] = None):
        self.webhook = WebhookClient("https://hooks.slack.com/services/" + secret_service)
        if signature:
            self.signature = signature
        else:
            self.signature = "".join(
                random.sample(
                    [
                        "a",
                        "b",
                        "c",
                        "d",
                        "e",
                        "f",
                        "g",
                        "h",
                        "i",
                        "j",
                        "k",
                        "l",
                        "m",
                        "n",
                        "o",
                        "p",
                        "q",
                        "r",
                        "s",
                        "t",
                        "u",
                        "v",
                        "w",
                        "x",
                        "y",
                        "z",
                    ],
                    k=13,
                )
            )

    def alert(
        self,
        text: str,
        short_text: Optional[str] = None,
        level="🔴",
        with_url=True,
        with_logging=True,
    ) -> None:

        if short_text:
            fallback = short_text
        else:
            fallback = text
        if with_url:
            if "CI_PIPELINE_URL" in os.environ:
                url = os.environ["CI_PIPELINE_URL"]
            else:
                url = "https://gitlab.com/ic-monitoring/es-log-processor/-/pipelines"
            message = " ".join((level, "%s\nSee <%s>" % (text, url)))
        else:
            message = " ".join((level, text))

        message = self.signature + "\n" + message

        if with_logging:
            eprint(f"{message}", end="\n\n")

        response = self.webhook.send(
            text=fallback, blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": message}}]
        )

        if response.status_code != 200 or response.body != "ok":
            eprint("Slack error with webhook query response:")
            eprint(pprint.pformat(response.__dict__))


# slack = AlertService()
# slack.alert('Testing alert service')
