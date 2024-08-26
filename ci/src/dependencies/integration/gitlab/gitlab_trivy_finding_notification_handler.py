from integration.gitlab.gitlab_api import GitlabApi
from integration.gitlab.gitlab_pipeline_config import GitlabPipeline
from notification.notification_event import FindingNotificationEvent, NotificationEvent
from notification.notification_handler import NotificationHandler
from scanner.manager.bazel_trivy_dependency_manager import TRIVY_SCANNER_ID, OSPackageTrivyResultParser


class GitlabTrivyFindingNotificationHandler(NotificationHandler):
    """Triggers an image build job on gitlab if a new patch version is found for an OS package finding."""

    gitlab_api: GitlabApi
    pipeline_run: bool

    def __init__(self, gitlab_api: GitlabApi = GitlabApi()):
        self.gitlab_api = gitlab_api
        self.pipeline_run = False

    def can_handle(self, event: NotificationEvent) -> bool:
        if isinstance(event, FindingNotificationEvent) and event.finding.scanner == TRIVY_SCANNER_ID and event.finding_has_patch_version:
            parser_id = OSPackageTrivyResultParser().get_parser_id()
            for proj in event.finding.projects:
                if proj.startswith(parser_id):
                    return True
        return False


    def handle(self, event: NotificationEvent):
        if isinstance(event, FindingNotificationEvent):
            self.__handle_finding_notification()
        else:
            raise RuntimeError(f"{self.__class__.__name__} can not handle event {event}")

    def __handle_finding_notification(self):
        if not self.pipeline_run:
            # only run the pipeline once for each job
            self.pipeline_run = self.gitlab_api.run_pipeline(GitlabPipeline.IC_BUILD_PUSH_BASE_CONTAINER_IMAGES)
