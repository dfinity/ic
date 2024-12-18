from notification.app_owner_msg_subscriber import AppOwnerMsgSubscriber


class ConsoleLoggerAppOwnerMsgSubscriber(AppOwnerMsgSubscriber):
    def send_notification_to_app_owners(self, message: str):
        print(f"send_notification_to_app_owners({message})")
