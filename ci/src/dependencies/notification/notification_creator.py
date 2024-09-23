import logging
from typing import Optional

from data_source.finding_data_source_subscriber import FindingDataSourceSubscriber
from model.finding import Finding
from notification.app_owner_msg_subscriber import AppOwnerMsgSubscriber
from notification.notification_config import NotificationConfig
from notification.notification_event import (
    AppOwnerNotificationEvent,
    FindingNotificationEvent,
    MRBlockedNotificationEvent,
    NotificationEvent,
    ReleaseBlockedNotificationEvent,
    ScanJobFailedNotificationEvent,
    ScanJobSucceededNotificationEvent,
)
from scanner.scanner_job_type import ScannerJobType
from scanner.scanner_subscriber import ScannerSubscriber


class NotificationCreator(ScannerSubscriber, FindingDataSourceSubscriber, AppOwnerMsgSubscriber):
    config: NotificationConfig

    def __init__(
        self,
        config: NotificationConfig,
    ):
        logging.debug(f"NotificationCreator({config})")
        self.config = config

    def __handle(self, event: NotificationEvent):
        for hnd in self.config.notification_handlers:
            if hnd.can_handle(event):
                hnd.handle(event)
                return
        raise RuntimeError(f"There is no handler configured which can handle event {event}")

    def on_merge_request_blocked(self, scanner_id: str, job_id: str, merge_request_id: str):
        logging.debug(f"on_merge_request_blocked({scanner_id},{job_id},{merge_request_id})")
        if self.config.notify_on_merge_request_blocked:
            self.__handle(MRBlockedNotificationEvent(scanner_id, f"{self.config.ci_pipeline_base_url}{job_id}", f"{self.config.merge_request_base_url}{merge_request_id}"))

    def on_release_build_blocked(self, scanner_id: str, job_id: str):
        logging.debug(f"on_release_build_blocked({scanner_id},{job_id})")
        if self.config.notify_on_release_build_blocked:
            self.__handle(ReleaseBlockedNotificationEvent(scanner_id, f"{self.config.ci_pipeline_base_url}{job_id}"))

    def on_scan_job_succeeded(self, scanner_id: str, job_type: ScannerJobType, job_id: str):
        logging.debug(f"on_scan_job_succeeded({scanner_id},{job_type},{job_id})")
        if self.config.notify_on_scan_job_succeeded[job_type]:
            self.__handle(ScanJobSucceededNotificationEvent(scanner_id, job_type, f"{self.config.ci_pipeline_base_url}{job_id}"))

    def on_scan_job_failed(self, scanner_id: str, job_type: ScannerJobType, job_id: str, reason: str):
        logging.debug(f"on_scan_job_failed({scanner_id},{job_type},{job_id},{reason})")
        if self.config.notify_on_scan_job_failed[job_type]:
            self.__handle(ScanJobFailedNotificationEvent(scanner_id, job_type, f"{self.config.ci_pipeline_base_url}{job_id}", reason))

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
            self.__handle(FindingNotificationEvent(finding, notify_risk_assessment, notify_patch_version, False))

    def on_finding_created(self, finding: Finding):
        logging.debug(f"on_finding_created({finding}")
        self.__notify_if_risk_assessment_needed_or_patch_version_available(None, finding)

    def on_finding_refreshed(self, finding_before: Finding, finding_after: Finding):
        logging.debug(f"on_finding_refreshed({finding_before},{finding_after}")
        self.__notify_if_risk_assessment_needed_or_patch_version_available(finding_before, finding_after)

    def on_finding_deleted(self, finding: Finding):
        logging.debug(f"on_finding_deleted({finding}")
        if self.config.notify_on_finding_deleted:
            self.__handle(FindingNotificationEvent(finding, False, False, True))

    def send_notification_to_app_owners(self, message: str):
        logging.debug(f"send_notification_to_owners({message}")
        self.__handle(AppOwnerNotificationEvent(message))
