from dataclasses import dataclass
from enum import Enum


@dataclass
class GithubWorkflowConfig:
    project: str
    dispatch_event: str

    def __post_init__(self):
        assert self.project is not None and len(self.project) > 0
        assert self.dispatch_event is not None and len(self.dispatch_event) > 0


class GithubWorklow(Enum):
    IC_BUILD_PUSH_BASE_CONTAINER_IMAGES = GithubWorkflowConfig(project="dfinity/ic", dispatch_event="dependency-management-trivy-scan")
