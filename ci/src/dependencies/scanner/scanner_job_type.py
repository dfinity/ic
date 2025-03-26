from enum import Enum


class ScannerJobType(Enum):
    MERGE_SCAN = 1
    RELEASE_SCAN = 2
    PERIODIC_SCAN = 3
