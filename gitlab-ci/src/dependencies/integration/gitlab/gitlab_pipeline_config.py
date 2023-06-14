from dataclasses import dataclass
from enum import Enum


@dataclass
class GitlabPipelineConfig:
    project: str
    pipeline_id: int

    def __post_init__(self):
        assert self.project is not None and len(self.project) > 0
        assert self.pipeline_id is not None


class GitlabPipeline(Enum):
    IC_BUILD_PUSH_BASE_CONTAINER_IMAGES = GitlabPipelineConfig(project="dfinity-lab/public/ic", pipeline_id=295024)
