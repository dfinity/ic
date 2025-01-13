from dataclasses import dataclass
from typing import Any, Optional, Set


@dataclass
class SlackMessage:
    id: str
    text: str
    blocks: Optional[Any]
    reactions: Set[str]

    def __post_init__(self):
        assert self.id is not None and len(self.id) > 0
        assert self.text is not None and len(self.text) > 0
