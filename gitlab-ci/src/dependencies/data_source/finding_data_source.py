import abc
from typing import Dict, List, Optional, Tuple

from data_source.commit_type import CommitType
from model.finding import Finding
from model.user import User


class FindingDataSource(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        """Used to detect if given class is subclass of this class"""
        return (
            hasattr(subclass, "get_open_finding")
            and callable(subclass.get_open_finding)
            and hasattr(subclass, "get_open_findings_for_repo_and_scanner")
            and callable(subclass.get_open_findings_for_repo_and_scanner)
            and hasattr(subclass, "get_deleted_findings")
            and callable(subclass.get_deleted_findings)
            and hasattr(subclass, "commit_has_block_exception")
            and callable(subclass.commit_has_block_exception)
            and hasattr(subclass, "create_or_update_open_finding")
            and callable(subclass.create_or_update_open_finding)
            and hasattr(subclass, "delete_finding")
            and callable(subclass.delete_finding)
            and hasattr(subclass, "link_findings")
            and callable(subclass.link_findings)
            and hasattr(subclass, "get_risk_assessor")
            and callable(subclass.get_risk_assessor)
        )

    @abc.abstractmethod
    def get_open_finding(
        self, repository: str, scanner: str, dependency_id: str, dependency_version: str
    ) -> Optional[Finding]:
        """Retrieve open finding with the given properties from data source, returns None if no open finding exists."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_open_findings_for_repo_and_scanner(
        self, repository: str, scanner: str
    ) -> Dict[Tuple[str, str, str, str], Finding]:
        """Get all open findings for the given (repository, scanner) combination, returned in a dict by finding id."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_deleted_findings(
        self, repository: str, scanner: str, dependency_id: str
    ) -> List[Finding]:
        """Retrieve deleted findings with the given properties from data source, returns an empty list if no deleted findings exist or the data source doesn't support retrieval of deleted findings."""
        raise NotImplementedError

    @abc.abstractmethod
    def commit_has_block_exception(self, commit_type: CommitType, commit_hash: str) -> bool:
        """Returns true if the data source contains a block exception for the commit of the given type and hash."""
        raise NotImplementedError

    @abc.abstractmethod
    def create_or_update_open_finding(self, finding: Finding):
        """Updates the given finding or creates a new one if none exists yet."""
        raise NotImplementedError

    @abc.abstractmethod
    def delete_finding(self, finding: Finding):
        """Deletes the given finding from the data source. The data source may choose to perform a soft-delete, so that deleted findings are still retrievable via get_deleted_findings()."""
        raise NotImplementedError

    @abc.abstractmethod
    def link_findings(self, finding_a: Finding, finding_b: Finding):
        """Creates a link between the two findings if supported by the datasource. Both findings must exist in the datasource."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_risk_assessor(self) -> List[User]:
        """Get the IDs of the current on duty risk assessors."""
        raise NotImplementedError
