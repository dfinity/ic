import logging
import os
from typing import Optional

from integration.slack.slack_api import SlackApi
from integration.slack.slack_channel_config import SlackChannelConfig
from model.finding import Finding
from notification.notification_event import (
    AppOwnerNotificationEvent,
    FindingNotificationEvent,
    MRBlockedNotificationEvent,
    NotificationEvent,
    ReleaseBlockedNotificationEvent,
    ScanJobFailedNotificationEvent,
    ScanJobSucceededNotificationEvent,
)
from notification.notification_handler import NotificationHandler

SLACK_CHANNEL_ID = "C04815E0T16"
SLACK_CHANNEL = "#security-vulnerability-management"
SLACK_LOG_TO_CONSOLE = False
APP_OWNERS = "<@U03JGGJBM7V> <@U02EFHJA8D9>"  # Thomas, Venkkatesh

SLACK_OAUTH_TOKEN = os.environ.get("SLACK_PSEC_BOT_OAUTH_TOKEN")
if SLACK_OAUTH_TOKEN is None:
    logging.error("SLACK_OAUTH_TOKEN not set, can't retrieve slack user IDs")

class SlackDefaultNotificationHandler(NotificationHandler):
    slack_api: SlackApi

    def __init__(
            self,
            slack_api: SlackApi = SlackApi(SlackChannelConfig(channel_id=SLACK_CHANNEL_ID, channel=SLACK_CHANNEL), SLACK_LOG_TO_CONSOLE,  SLACK_OAUTH_TOKEN),
    ):
        self.slack_api = slack_api

    def can_handle(self, event: NotificationEvent) -> bool:
        return True

    def handle(self, event: NotificationEvent):
        if isinstance(event, MRBlockedNotificationEvent):
            self.__handle_mr_block(event)
        elif isinstance(event, ReleaseBlockedNotificationEvent):
            self.__handle_release_block(event)
        elif isinstance(event, ScanJobSucceededNotificationEvent):
            self.__handle_scan_job_succeeded(event)
        elif isinstance(event, ScanJobFailedNotificationEvent):
            self.__handle_scan_job_failed_(event)
        elif isinstance(event, FindingNotificationEvent):
            self.__handle_finding_notification(event)
        elif isinstance(event, AppOwnerNotificationEvent):
            self.__handle_app_owner_notification(event)
        else:
            raise RuntimeError(f"{self.__class__.__name__} can not handle event {event}")

    def __handle_mr_block(self, event: MRBlockedNotificationEvent):
        self.slack_api.send_message(
            f"Merge Request blocked {event.merge_request_url} by CI Pipeline {event.ci_job_url}"
        )

    def __handle_release_block(self, event: ReleaseBlockedNotificationEvent):
        self.slack_api.send_message(
            f"Release Build blocked by CI Pipeline {event.ci_job_url} <!channel>"
        )

    def __handle_scan_job_succeeded(self, event: ScanJobSucceededNotificationEvent):
        self.slack_api.send_message(
            f"Scan Job with type {event.job_type.name} and ID {event.scanner_id} succeeded in CI Pipeline {event.ci_job_url}"
        )

    def __handle_scan_job_failed_(self, event: ScanJobFailedNotificationEvent):
        self.slack_api.send_message(
            f'Scan Job with type {event.job_type.name} and ID {event.scanner_id} failed with reason "{event.reason}" in CI Pipeline {event.ci_job_url} {APP_OWNERS}'
        )

    def __get_risk_assessors(self, finding: Finding) -> str:
        if finding.risk_assessor is None or len(finding.risk_assessor) == 0:
            return "no risk assessors set <!channel>"
        res: str = ""
        has_user_with_slack_id: bool = False
        for user in finding.risk_assessor:
            slack_id: Optional[str] = self.slack_api.try_get_slack_id(user)
            if slack_id is None:
                res += "Unknown User" if user.name is None else user.name
            else:
                has_user_with_slack_id = True
                res += f"<@{slack_id}>"
            res += ", "
        res = res[:-2]
        if not has_user_with_slack_id:
            res += " <!channel>"
        return res

    def __handle_finding_notification(self, event: FindingNotificationEvent):
        if event.finding_needs_risk_assessment or event.finding_has_patch_version:
            msg: str = f"Finding {NotificationHandler.get_finding_info(event.finding)} with risk assessors {self.__get_risk_assessors(event.finding)}"
            if event.finding_needs_risk_assessment:
                msg += "\n- needs risk assessment"
            if event.finding_has_patch_version:
                msg += "\n- has patch version available"
            self.slack_api.send_message(msg)
        if event.finding_was_resolved:
            self.slack_api.send_message(f"Finding {NotificationHandler.get_finding_info(event.finding)} was resolved :tada:")

    def __handle_app_owner_notification(self, event: AppOwnerNotificationEvent):
        self.slack_api.send_message(event.message + " " + APP_OWNERS)
