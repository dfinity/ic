from typing import Optional

from slack_sdk.webhook import WebhookClient
from util.print import eprint


class AlertService:
    def __init__(self, secret_service: str, signature: str):
        self.endpoint = "https://hooks.slack.com/services/" + secret_service
        self.webhook = WebhookClient(self.endpoint)
        self.signature = signature

    def _form_message(
        self,
        text: str,
        level: str,
        url: Optional[str] = None,
    ) -> str:
        if url is not None:
            message = " ".join((level, "%s\nSee <%s>" % (text, url)))
        else:
            message = " ".join((level, text))
        return self.signature + "\n" + message

    def alert(
        self,
        text: str,
        short_text: Optional[str] = None,
        level="🔴",
        url: Optional[str] = None,
        with_logging=True,
    ) -> None:

        if short_text:
            fallback = short_text
        else:
            fallback = text

        message = self._form_message(text, level, url)

        if with_logging:
            eprint(f"{message}", end="\n\n")

        response = self.webhook.send(
            text=fallback, blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": message}}]
        )

        if response.status_code != 200 or response.body != "ok":
            response_file = f"slack_response--{self.signature}.html"
            eprint(
                f"Unexpected Slack WebHook response for endpoint {self.endpoint}: status code {response.status_code}; body saved to {response_file}"
            )
            with open(response_file, "w") as fout:
                fout.write(response.body)


class DummyAlertService(AlertService):
    def __init__(self, signature: str):
        self.signature = signature

    def alert(
        self,
        text: str,
        short_text: Optional[str] = None,
        level="🔴",
        url: Optional[str] = None,
        with_logging=True,
    ) -> None:

        message = self._form_message(text, level, url)

        print(
            f"Warning: alert `{short_text}` cannot be sent via Slack (DummyAlertService has been requested).\nAlert message:"
        )
        print(message, flush=True)

        if with_logging:
            eprint(f"{message}", end="\n\n")
