import logging
import os
from typing import Optional

from data_source.finding_data_source_subscriber import FindingDataSourceSubscriber
from model.finding import Finding
from notification.notification_config import NotificationConfig
from notification.slack_api import SlackApi
from scanner.scanner_job_type import ScannerJobType
from scanner.scanner_subscriber import ScannerSubscriber

SLACK_CHANNEL = "#security-vulnerability-management"
SLACK_LOG_TO_CONSOLE = False

SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL_PSEC_VULN_MGT")
if SLACK_WEBHOOK is None:
    logging.error(f"SLACK_WEBHOOK not set, can't post to {SLACK_CHANNEL}")
SLACK_OAUTH_TOKEN = os.environ.get("SLACK_PSEC_BOT_OAUTH_TOKEN")
if SLACK_OAUTH_TOKEN is None:
    logging.error("SLACK_OAUTH_TOKEN not set, can't retrieve slack user IDs")


class SlackNotifier(ScannerSubscriber, FindingDataSourceSubscriber):
    config: NotificationConfig
    slack_api: SlackApi

    def __init__(
        self,
        config: NotificationConfig,
        slack_api: SlackApi = SlackApi(SLACK_CHANNEL, SLACK_LOG_TO_CONSOLE, SLACK_WEBHOOK, SLACK_OAUTH_TOKEN),
    ):
        logging.debug(f"SlackNotifier({config})")
        self.config = config
        self.slack_api = slack_api

    def on_merge_request_blocked(self, job_id: str, merge_request_id: str):
        logging.debug(f"on_merge_request_blocked({job_id},{merge_request_id})")
        if self.config.notify_on_merge_request_blocked:
            self.slack_api.send_message(
                f"Merge Request blocked {self.config.merge_request_base_url}{merge_request_id} by CI Pipeline {self.config.ci_pipeline_base_url}{job_id}"
            )

    def on_release_build_blocked(self, job_id: str):
        logging.debug(f"on_release_build_blocked({job_id})")
        if self.config.notify_on_release_build_blocked:
            self.slack_api.send_message(
                f"Release Build blocked by CI Pipeline {self.config.ci_pipeline_base_url}{job_id} <!channel>"
            )

    def on_scan_job_succeeded(self, job_type: ScannerJobType, job_id: str):
        logging.debug(f"on_scan_job_succeeded({job_type},{job_id})")
        if self.config.notify_on_scan_job_succeeded[job_type]:
            self.slack_api.send_message(
                f"Scan Job with type {job_type.name} succeeded in CI Pipeline {self.config.ci_pipeline_base_url}{job_id}"
            )

    def on_scan_job_failed(self, job_type: ScannerJobType, job_id: str, reason: str):
        logging.debug(f"on_scan_job_failed({job_type},{job_id},{reason})")
        if self.config.notify_on_scan_job_failed[job_type]:
            self.slack_api.send_message(
                f'Scan Job with type {job_type.name} failed with reason "{reason}" in CI Pipeline {self.config.ci_pipeline_base_url}{job_id} <@U03JGGJBM7V> <@U02EFHJA8D9>'
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

    @staticmethod
    def __get_finding_info(finding: Finding) -> str:
        if finding.more_info is None:
            return f"({finding.repository},{finding.scanner},{finding.vulnerable_dependency.id},{finding.vulnerable_dependency.version})"
        return finding.more_info

    def __is_risk_assessment_needed(self, finding: Finding) -> bool:
        return self.config.notify_on_finding_risk_assessment_needed and finding.risk is None

    def __is_patch_version_available(self, finding_before: Optional[Finding], finding: Finding) -> bool:
        return (
            finding.has_patch_version(finding_before)
            if self.config.notify_on_finding_patch_version_available
            else False
        )

    def __notify_if_risk_assessment_needed_or_patch_version_available(
        self, finding_before: Optional[Finding], finding: Finding
    ):
        notify_risk_assessment = self.__is_risk_assessment_needed(finding)
        notify_patch_version = self.__is_patch_version_available(finding_before, finding)
        if notify_risk_assessment or notify_patch_version:
            msg: str = f"Finding {SlackNotifier.__get_finding_info(finding)} with risk assessors {self.__get_risk_assessors(finding)}"
            if notify_risk_assessment:
                msg += "\n- needs risk assessment"
            if notify_patch_version:
                msg += "\n- has patch version available"
            self.slack_api.send_message(msg)

    def on_finding_created(self, finding: Finding):
        logging.debug(f"on_finding_created({finding}")
        self.__notify_if_risk_assessment_needed_or_patch_version_available(None, finding)

    def on_finding_updated(self, finding_before: Finding, finding_after: Finding):
        logging.debug(f"on_finding_updated({finding_before},{finding_after}")
        self.__notify_if_risk_assessment_needed_or_patch_version_available(finding_before, finding_after)
