import abc

from scanner.scanner_job_type import ScannerJobType


class ScannerSubscriber(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        """Used to detect if given class is subclass of this class"""
        return (
            hasattr(subclass, "on_merge_request_blocked")
            and callable(subclass.on_merge_request_blocked)
            and hasattr(subclass, "on_release_build_blocked")
            and callable(subclass.on_release_build_blocked)
            and hasattr(subclass, "on_scan_job_succeeded")
            and callable(subclass.on_scan_job_succeeded)
            and hasattr(subclass, "on_scan_job_failed")
            and callable(subclass.on_scan_job_failed)
        )

    @abc.abstractmethod
    def on_merge_request_blocked(self, scanner_id: str, job_id: str, merge_request_id: str):
        """A merge request with the given IDs was blocked."""
        raise NotImplementedError

    @abc.abstractmethod
    def on_release_build_blocked(self, scanner_id: str, job_id: str):
        """A release build with the given ID was blocked."""
        raise NotImplementedError

    @abc.abstractmethod
    def on_scan_job_succeeded(self, scanner_id: str, job_type: ScannerJobType, job_id: str):
        """The scan job of the given type and ID was successfully completed."""
        raise NotImplementedError

    @abc.abstractmethod
    def on_scan_job_failed(self, scanner_id: str, job_type: ScannerJobType, job_id: str, reason: str):
        """The scan job of the given type and ID failed because of the given reason."""
        raise NotImplementedError
