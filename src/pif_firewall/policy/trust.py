"""Trust-aware weighting: the same risk score matters more from a retrieved
document than from the direct user, since imperative instructions embedded
in retrieved content are inherently suspicious (indirect injection)."""
from pif_firewall.ingest.document import TrustLevel

TRUST_MULTIPLIER = {
    TrustLevel.USER: 1.0,
    TrustLevel.RETRIEVED: 1.35,
    TrustLevel.TOOL_OUTPUT: 1.2,
}


def weighted_risk(raw_score: float, trust_level: TrustLevel) -> float:
    return min(1.0, raw_score * TRUST_MULTIPLIER.get(trust_level, 1.0))
