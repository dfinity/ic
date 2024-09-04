from typing import Dict, List, Optional, Tuple

from data_source.commit_type import CommitType
from data_source.finding_data_source import FindingDataSource
from model.finding import Finding
from model.user import User


class DummyFindingDataSource(FindingDataSource):
    def get_open_finding(
        self, repository: str, scanner: str, dependency_id: str, dependency_version: str
    ) -> Optional[Finding]:
        return None

    def get_open_findings_for_repo_and_scanner(
        self, repository: str, scanner: str
    ) -> Dict[Tuple[str, str, str, str], Finding]:
        return {}

    def get_deleted_findings(
        self, repository: str, scanner: str, dependency_id: str
    ) -> List[Finding]:
        return []

    def commit_has_block_exception(self, commit_type: CommitType, commit_hash: str) -> bool:
        return True

    def create_or_update_open_finding(self, finding: Finding):
        pass

    def delete_finding(self, finding: Finding):
        pass

    def link_findings(self, finding_a: Finding, finding_b: Finding):
        pass

    def get_risk_assessor(self) -> List[User]:
        return []
