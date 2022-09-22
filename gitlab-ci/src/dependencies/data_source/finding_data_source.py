import abc
from typing import Optional

from data_source.commit_type import CommitType
from model.finding import Finding


class FindingDataSource(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        """Used to detect if given class is subclass of this class"""
        return (
            hasattr(subclass, "get_open_finding")
            and callable(subclass.get_open_finding)
            and hasattr(subclass, "commit_has_block_exception")
            and callable(subclass.commit_has_block_exception)
            and hasattr(subclass, "update_open_finding")
            and callable(subclass.update_open_finding)
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
    def commit_has_block_exception(self, commit_type: CommitType, commit_hash: str) -> bool:
        """Returns true if the data source contains a block exception for the commit of the given type and hash."""
        raise NotImplementedError

    @abc.abstractmethod
    def update_open_finding(self, finding: Finding):
        """Updates the given finding or creates a new one if none exists yet."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_risk_assessor(self) -> str:
        """Get the ID of the current on duty risk assessor."""
        raise NotImplementedError
