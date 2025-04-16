import abc

from model.finding import Finding


class FindingDataSourceSubscriber(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        """Used to detect if given class is subclass of this class"""
        return (
            hasattr(subclass, "on_finding_created")
            and callable(subclass.on_finding_created)
            and hasattr(subclass, "on_finding_refreshed")
            and callable(subclass.on_finding_refreshed)
            and hasattr(subclass, "on_finding_deleted")
            and callable(subclass.on_finding_deleted)
        )

    @abc.abstractmethod
    def on_finding_created(self, finding: Finding):
        """The provided finding was created successfully in the data source."""
        raise NotImplementedError

    @abc.abstractmethod
    def on_finding_refreshed(self, finding_before: Finding, finding_after: Finding):
        """A finding was successfully refreshed in the data source. Provided is the finding before and after the update. Note that both findings might be the same if a finding existed before and hasn't changed in the current scan."""
        raise NotImplementedError

    @abc.abstractmethod
    def on_finding_deleted(self, finding: Finding):
        """The provided finding was deleted successfully from the data source."""
        raise NotImplementedError
