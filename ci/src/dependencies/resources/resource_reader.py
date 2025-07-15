import os
from enum import Enum
from typing import Set


class IgnoreList(str, Enum):
    GUEST_OS = "container_scanner_finding_failover_ignore_list_guestos.txt"


def read_ignore_list(ignore_list: IgnoreList) -> Set[str]:
    res = set()
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ignore_list)) as file:
        for line in file:
            stripped_line = line.strip()
            if not (stripped_line.startswith("//") or len(stripped_line) == 0):
                res.add(stripped_line)
    return res
