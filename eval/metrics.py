"""Evaluation metrics: per-attack-type recall, benign false-positive rates
(flagged vs hard-blocked), overall detection rate and scan latency.

'Flagged' = decision != ALLOW (quarantine or block). 'Blocked' = hard BLOCK only.
A quarantined benign email still reaches the agent with a span redacted, so the
blocked rate is the number that measures real disruption; report both."""
import time
from dataclasses import dataclass

from pif_firewall.firewall import Firewall
from pif_firewall.ingest.document import SourceType
from pif_firewall.policy.decision import Decision


@dataclass
class EvalCase:
    text: str
    attack_type: str | None  # None means benign
    source_type: SourceType = SourceType.EMAIL


def _scan(case: EvalCase, firewall: Firewall):
    # fresh session per case so taint never leaks between cases
    return firewall.scan(case.text, case.source_type, session_id=f"eval-{id(case)}")


def detection_recall(cases: list[EvalCase], firewall: Firewall) -> dict[str, float]:
    per_type_total: dict[str, int] = {}
    per_type_caught: dict[str, int] = {}
    for case in cases:
        if case.attack_type is None:
            continue
        per_type_total[case.attack_type] = per_type_total.get(case.attack_type, 0) + 1
        if _scan(case, firewall).policy.decision != Decision.ALLOW:
            per_type_caught[case.attack_type] = per_type_caught.get(case.attack_type, 0) + 1
    return {t: per_type_caught.get(t, 0) / total for t, total in per_type_total.items()}


def overall_detection_rate(cases: list[EvalCase], firewall: Firewall) -> float:
    attacks = [c for c in cases if c.attack_type is not None]
    if not attacks:
        return 0.0
    caught = sum(1 for c in attacks if _scan(c, firewall).policy.decision != Decision.ALLOW)
    return caught / len(attacks)


def overall_block_rate(cases: list[EvalCase], firewall: Firewall) -> float:
    """Share of attacks hard-BLOCKED (not just quarantined). Trust weighting shows up here."""
    attacks = [c for c in cases if c.attack_type is not None]
    if not attacks:
        return 0.0
    return sum(1 for c in attacks if _scan(c, firewall).policy.decision == Decision.BLOCK) / len(attacks)


def benign_rates(cases: list[EvalCase], firewall: Firewall) -> dict[str, float]:
    benign = [c for c in cases if c.attack_type is None]
    if not benign:
        return {"flagged": 0.0, "blocked": 0.0}
    flagged = blocked = 0
    for case in benign:
        decision = _scan(case, firewall).policy.decision
        flagged += decision != Decision.ALLOW
        blocked += decision == Decision.BLOCK
    return {"flagged": flagged / len(benign), "blocked": blocked / len(benign)}


def benign_false_positive_rate(cases: list[EvalCase], firewall: Firewall) -> float:
    return benign_rates(cases, firewall)["flagged"]


def mean_scan_latency_ms(cases: list[EvalCase], firewall: Firewall) -> float:
    if not cases:
        return 0.0
    start = time.perf_counter()
    for case in cases:
        _scan(case, firewall)
    return (time.perf_counter() - start) / len(cases) * 1000
