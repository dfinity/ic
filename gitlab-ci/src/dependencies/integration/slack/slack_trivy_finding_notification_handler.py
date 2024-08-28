import logging
import os
import typing

from integration.github.github_trivy_finding_notification_handler import GithubTrivyFindingNotificationHandler
from integration.slack.slack_api import SlackApi
from integration.slack.slack_channel_config import SlackChannelConfig
from model.team import Team
from notification.notification_event import FindingNotificationEvent, NotificationEvent
from notification.notification_handler import NotificationHandler
from scanner.manager.bazel_trivy_dependency_manager import TRIVY_SCANNER_ID

SUPPORTED_TEAMS = (Team.NODE_TEAM, Team.BOUNDARY_NODE_TEAM)
SLACK_CHANNEL_CONFIG_BY_TEAM = {Team.NODE_TEAM : SlackChannelConfig(channel_id="C05CYLM94KU", channel="#eng-node-psec"),
                                Team.BOUNDARY_NODE_TEAM: SlackChannelConfig(channel_id="C06KQKZ3EBW", channel="#eng-boundary-nodes-psec")}
SLACK_TEAM_GROUP_ID = {Team.NODE_TEAM: "<!subteam^S05FTRNRC5A>", Team.BOUNDARY_NODE_TEAM: "<!subteam^S0313LYB9FZ>"}

SLACK_LOG_TO_CONSOLE = False

SLACK_OAUTH_TOKEN = os.environ.get("SLACK_PSEC_BOT_OAUTH_TOKEN")
if SLACK_OAUTH_TOKEN is None:
    logging.error("SLACK_OAUTH_TOKEN not set, can't retrieve slack user IDs")

class SlackTrivyFindingNotificationHandler(NotificationHandler):
    slack_api_by_team: typing.Dict[Team, SlackApi] = {}
    github_handler: GithubTrivyFindingNotificationHandler

    def __init__(
            self,
            slack_api: SlackApi = None,
            github_handler: GithubTrivyFindingNotificationHandler = GithubTrivyFindingNotificationHandler(),
    ):
        for team in SUPPORTED_TEAMS:
            if slack_api:
                self.slack_api_by_team[team] = slack_api
            else:
                self.slack_api_by_team[team] = SlackApi(SLACK_CHANNEL_CONFIG_BY_TEAM[team], SLACK_LOG_TO_CONSOLE, SLACK_OAUTH_TOKEN)
        self.github_handler = github_handler

    def can_handle(self, event: NotificationEvent) -> bool:
        return isinstance(event, FindingNotificationEvent) and event.finding.scanner == TRIVY_SCANNER_ID

    def handle(self, event: NotificationEvent):
        if isinstance(event, FindingNotificationEvent):
            self.__handle_finding_notification(event)
        else:
            raise RuntimeError(f"{self.__class__.__name__} can not handle event {event}")

    def __handle_finding_notification(self, event: FindingNotificationEvent):
        for team in SUPPORTED_TEAMS:
            if team in event.finding.owning_teams:
                if event.finding_needs_risk_assessment or event.finding_has_patch_version:
                    msg: str = f"Finding {NotificationHandler.get_finding_info(event.finding)} for {SLACK_TEAM_GROUP_ID[team]}"
                    if event.finding_needs_risk_assessment:
                        msg += "\n- needs risk assessment"
                    if event.finding_has_patch_version:
                        msg += "\n- has patch version available"
                        if self.github_handler.can_handle(event):
                            msg += " (base image rebuild was triggered)"
                            self.github_handler.handle(event)
                    self.slack_api_by_team[team].send_message(msg)
                if event.finding_was_resolved:
                    self.slack_api_by_team[team].send_message(f"Finding {NotificationHandler.get_finding_info(event.finding)} was resolved :tada:")
