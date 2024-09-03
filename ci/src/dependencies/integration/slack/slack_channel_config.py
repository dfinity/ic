from dataclasses import dataclass
from typing import Optional


@dataclass
class SlackChannelConfig:
    channel_id: Optional[str] # might be None during testing
    channel: str

    def __post_init__(self):
        assert self.channel is not None and len(self.channel) > 0
