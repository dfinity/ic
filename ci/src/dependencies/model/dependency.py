from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Dependency:
    """unique identifier for the dependency (e.g., https://crates.io/crates/chrono)"""

    id: str
    """short name for the dependency (e.g., chrono)"""
    name: str
    """version of the dependency"""
    version: str
    """maps vulnerability id to list of fix versions, list of fix versions should be non-empty"""
    fix_version_for_vulnerability: Dict[str, List[str]] = field(default_factory=lambda: {})

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.id is not None and len(self.id) > 0
        assert self.name is not None and len(self.name) > 0
        assert self.version is not None and len(self.version) > 0
        assert self.fix_version_for_vulnerability is not None
        for patch_versions in self.fix_version_for_vulnerability.values():
            assert len(patch_versions) > 0
