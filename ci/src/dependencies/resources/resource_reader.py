import os
from enum import Enum
from typing import Set


class IgnoreList(str, Enum):
    BOUNDARY_GUEST_OS = "container_scanner_finding_failover_ignore_list_boundary_guestos.txt"
    GUEST_OS = "container_scanner_finding_failover_ignore_list_guestos.txt"


def read_ignore_list(ignore_list: IgnoreList) -> Set[str]:
    res = set()
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ignore_list)) as file:
        for line in file:
            if not line.startswith("//"):
                res.add(line.strip())
    return res
