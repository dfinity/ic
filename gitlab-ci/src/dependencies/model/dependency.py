from dataclasses import dataclass
from typing import Dict
from typing import List


@dataclass
class Dependency:
    """unique identifier for the dependency (e.g., https://crates.io/crates/chrono)"""

    id: str
    """short name for the dependency (e.g., chrono)"""
    name: str
    """version of the dependency"""
    version: str
    """maps vulnerability id to list of fix versions"""
    fix_version_for_vulnerability: Dict[str, List[str]]
