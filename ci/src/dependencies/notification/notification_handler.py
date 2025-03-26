import abc

from model.finding import Finding
from notification.notification_event import NotificationEvent


class NotificationHandler(abc.ABC):
    """Base class for notification handlers."""

    @abc.abstractmethod
    def can_handle(self, event: NotificationEvent) -> bool:
        """Return true if this handler can handle the provided event"""
        raise NotImplementedError

    @abc.abstractmethod
    def handle(self, event: NotificationEvent):
        """Handle the provided notification event, should be only called if can_handle returns True"""
        raise NotImplementedError

    @staticmethod
    def get_finding_info(finding: Finding) -> str:
        """Returns a string representation of the finding"""
        if finding.more_info is None:
            return f"({finding.repository}, {finding.scanner}, {finding.vulnerable_dependency.id}, {finding.vulnerable_dependency.version})"
        return finding.more_info
