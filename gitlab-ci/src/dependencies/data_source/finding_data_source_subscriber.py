import abc

from model.finding import Finding


class FindingDataSourceSubscriber(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        """Used to detect if given class is subclass of this class"""
        return (
            hasattr(subclass, "on_finding_created")
            and callable(subclass.on_finding_created)
            and hasattr(subclass, "on_finding_updated")
            and callable(subclass.on_finding_updated)
        )

    @abc.abstractmethod
    def on_finding_created(self, finding: Finding):
        """The provided finding was created successfully in the data source."""
        raise NotImplementedError

    @abc.abstractmethod
    def on_finding_updated(self, finding_before: Finding, finding_after: Finding):
        """A finding was successfully updated in the data source. Provided is the finding before and after the update."""
        raise NotImplementedError
