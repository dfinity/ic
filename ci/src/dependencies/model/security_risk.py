from enum import Enum
from typing import Optional


class SecurityRisk(Enum):
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @staticmethod
    def of(word: Optional[str]) -> Optional['SecurityRisk']:
        if word is None:
            return None
        word = word.strip().upper()
        if len(word) == 0:
            return None

        for risk in SecurityRisk:
            if risk.name.startswith(word):
                return risk
        return None

    @staticmethod
    def new_risk_from(risk_a: Optional['SecurityRisk'], risk_b: Optional['SecurityRisk']):
        if risk_a is None or risk_b is None:
            # if one of the risks is undetermined, new risk should be undetermined
            return None
        return risk_a if risk_a.value >= risk_b.value else risk_b
