from enum import Enum


class Mode(Enum):
    raw = "raw"  # Simply pretty-print all log entries
    save_event_stream = "save_event_stream"

    universal_policy = "universal_policy"

    pre_processor_test = "pre_processor_test"

    check_pipeline_liveness = "check_pipeline_liveness"

    def __str__(self):
        """Returns this mode's name"""
        return self.value
