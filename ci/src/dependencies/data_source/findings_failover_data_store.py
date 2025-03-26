import abc
from typing import List

from model.finding import Finding


class FindingsFailoverDataStore(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        """Used to detect if given class is subclass of this class"""
        return (
            hasattr(subclass, "can_handle")
            and callable(subclass.can_handle)
            and hasattr(subclass, "store_findings")
            and callable(subclass.store_findings)
        )

    @abc.abstractmethod
    def can_handle(self, finding: Finding) -> bool:
        """Returns true if the failover store can handle this finding, false otherwise."""
        raise NotImplementedError

    @abc.abstractmethod
    def store_findings(self, repository: str, scanner: str, findings: List[Finding]):
        """Tries to store the provided findings in the failover store."""
        raise NotImplementedError
