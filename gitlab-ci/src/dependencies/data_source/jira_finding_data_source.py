from typing import List
from typing import Optional

from data_source.commit_type import CommitType
from data_source.finding_data_source import FindingDataSource
from data_source.finding_data_source_subscriber import FindingDataSourceSubscriber
from model.finding import Finding


class JiraFindingDataSource(FindingDataSource):
    subscribers: List[FindingDataSourceSubscriber] = []

    def __init__(self, subscribers: List[FindingDataSourceSubscriber]):
        self.subscribers = subscribers

    def get_open_finding(
        self, repository: str, scanner: str, dependency_id: str, dependency_version: str
    ) -> Optional[Finding]:
        raise NotImplementedError

    def commit_has_block_exception(self, commit_type: CommitType, commit_hash: str) -> bool:
        raise NotImplementedError

    def update_open_finding(self, finding: Finding):
        raise NotImplementedError

    def get_risk_assessor(self) -> str:
        raise NotImplementedError
