from dataclasses import dataclass
from typing import Optional


@dataclass
class User:
    """unique identifier for the user"""

    id: str
    """short name for the user"""
    name: Optional[str] = None
    """email of the user"""
    email: Optional[str] = None

    def __post_init__(self):
        """Validate field values after initialization"""
        assert self.id is not None and len(self.id) > 0
        assert self.name is None or len(self.name) > 0
        assert self.email is None or len(self.email) > 0
