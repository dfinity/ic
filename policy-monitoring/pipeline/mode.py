from enum import Enum
from typing import Set


class Mode(Enum):
    raw = "raw"  # Simply pretty-print all log entries
    save_event_stream = "save_event_stream"

    universal_policy = "universal_policy"

    check_pipeline_liveness = "check_pipeline_liveness"

    def __str__(self):
        """Returns this mode's name"""
        return self.value


def is_raw_stream_reusable(modes: Set[Mode]) -> bool:
    return len(modes) > 1


def multiple_preprocessing_needed(modes: Set[Mode]) -> bool:
    """
    Indicates whether the event stream must be reusable.

    Use case:
        Inference of GlobalInfra via pre-scan.

    Implementation:
        Are there more than one modes enabled (except for Mode.raw)?
    """
    return len(modes.difference(set([Mode.raw]))) > 1


def consume(modes: Set[Mode], mode: Mode) -> bool:
    if mode in modes:
        modes.remove(mode)
        return True
    else:
        return False
