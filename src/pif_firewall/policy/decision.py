"""3-tier content decision: Allow / Quarantine / Block.

Quarantine strips only the suspicious span and lets the rest of the content
through, which keeps the false-positive rate down versus an all-or-nothing
block.
"""
import re
from dataclasses import dataclass
from enum import Enum

from pif_firewall.detection.ensemble import RiskAssessment

BLOCK_THRESHOLD = 0.75
QUARANTINE_THRESHOLD = 0.35


class Decision(str, Enum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    BLOCK = "block"


@dataclass
class PolicyResult:
    decision: Decision
    sanitized_text: str
    reason: str


def decide(text: str, assessment: RiskAssessment) -> PolicyResult:
    if assessment.risk_score >= BLOCK_THRESHOLD:
        return PolicyResult(
            decision=Decision.BLOCK,
            sanitized_text="",
            reason=f"risk {assessment.risk_score:.2f} >= block threshold; "
                   f"attacks={sorted(a.value for a in assessment.attack_types)}",
        )
    if assessment.risk_score >= QUARANTINE_THRESHOLD:
        sanitized = text
        for span in assessment.evidence:
            clean_span = re.sub(r"^\[decoded:[^\]]*\]\s*", "", span)
            sanitized = sanitized.replace(clean_span, "[REDACTED]")
        return PolicyResult(
            decision=Decision.QUARANTINE,
            sanitized_text=sanitized,
            reason=f"risk {assessment.risk_score:.2f} in quarantine band; "
                   f"spans redacted={len(assessment.evidence)}",
        )
    return PolicyResult(decision=Decision.ALLOW, sanitized_text=text, reason="risk below threshold")
