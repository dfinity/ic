from typing import List

from notification.notification_event import NotificationEvent
from notification.notification_handler import NotificationHandler


class BroadcastNotificationHandler(NotificationHandler):
    """Notification handler that passes notifications to ALL nested handlers that can handle it."""

    def __init__(self, nested_handlers: List[NotificationHandler]):
        self.nested_handlers = nested_handlers

    def can_handle(self, event: NotificationEvent) -> bool:
        for hnd in self.nested_handlers:
            if hnd.can_handle(event):
                return True
        return False

    def handle(self, event: NotificationEvent):
        for hnd in self.nested_handlers:
            if hnd.can_handle(event):
                hnd.handle(event)
