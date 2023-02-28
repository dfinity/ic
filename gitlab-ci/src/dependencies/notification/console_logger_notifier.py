from notification.notifier import Notifier


class ConsoleLoggerNotifier(Notifier):
    def send_notification_to_app_owners(self, message: str):
        print(f"send_notification_to_app_owners({message})")
