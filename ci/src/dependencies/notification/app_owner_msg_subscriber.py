import abc


class AppOwnerMsgSubscriber(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        """Used to detect if given class is subclass of this class"""
        return hasattr(subclass, "send_notification_to_app_owners") and callable(
            subclass.send_notification_to_app_owners
        )

    @abc.abstractmethod
    def send_notification_to_app_owners(self, message: str):
        """Sends a notification to the dependency management owners."""
        raise NotImplementedError
