from dataclasses import dataclass
from enum import Enum


@dataclass
class GithubWorkflowConfig:
    project: str
    workflow_name: str

    def __post_init__(self):
        assert self.project is not None and len(self.project) > 0
        assert self.workflow_name is not None and len(self.workflow_name) > 0


class GithubWorklow(Enum):
    IC_BUILD_PUSH_BASE_CONTAINER_IMAGES = GithubWorkflowConfig(project="dfinity/ic", workflow_name="container-base-images.yml")
