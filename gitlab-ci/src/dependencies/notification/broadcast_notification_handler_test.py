from unittest.mock import Mock

from notification.broadcast_notification_handler import BroadcastNotificationHandler
from notification.notification_event import NotificationEvent
from notification.notification_handler import NotificationHandler


def test_can_handle_if_one_nested_can_handle():
    a = MockNotificationHandler(False)
    b = MockNotificationHandler(False)
    c = MockNotificationHandler(True)

    assert BroadcastNotificationHandler(nested_handlers=[a,b,c]).can_handle(Mock())

def test_can_not_handle_if_nested_can_not_handle():
    a = MockNotificationHandler(False)
    b = MockNotificationHandler(False)
    c = MockNotificationHandler(False)

    assert not BroadcastNotificationHandler(nested_handlers=[a,b,c]).can_handle(Mock())

def test_call_all_that_can_handle():
    a = MockNotificationHandler(True)
    b = MockNotificationHandler(False)
    c = MockNotificationHandler(True)
    event = Mock()
    handler = BroadcastNotificationHandler(nested_handlers=[a,b,c])

    assert handler.can_handle(event)

    handler.handle(event)

    assert len(a.events) == 1
    assert len(b.events) == 0
    assert len(c.events) == 1

class MockNotificationHandler(NotificationHandler):

    def __init__(self, can_handle_ret: bool):
        self.can_handle_ret = can_handle_ret
        self.events = []
    def can_handle(self, event: NotificationEvent) -> bool:
        return self.can_handle_ret

    def handle(self, event: NotificationEvent):
        self.events.append(event)
        print(len(self.events))
