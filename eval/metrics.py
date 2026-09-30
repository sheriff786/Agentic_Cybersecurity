"""Evaluation metrics: per-attack-type recall, benign false-positive rate,
and end-to-end attack success rate (with vs without the tool gate)."""
from dataclasses import dataclass

from pif_firewall.firewall import Firewall
from pif_firewall.ingest.document import SourceType
from pif_firewall.policy.decision import Decision


@dataclass
class EvalCase:
    text: str
    attack_type: str | None  # None means benign
    source_type: SourceType = SourceType.EMAIL


def detection_recall(cases: list[EvalCase], firewall: Firewall) -> dict[str, float]:
    per_type_total: dict[str, int] = {}
    per_type_caught: dict[str, int] = {}
    for case in cases:
        if case.attack_type is None:
            continue
        per_type_total[case.attack_type] = per_type_total.get(case.attack_type, 0) + 1
        result = firewall.scan(case.text, case.source_type, session_id=f"eval-{id(case)}")
        if result.policy.decision != Decision.ALLOW:
            per_type_caught[case.attack_type] = per_type_caught.get(case.attack_type, 0) + 1
    return {
        attack_type: per_type_caught.get(attack_type, 0) / total
        for attack_type, total in per_type_total.items()
    }


def benign_false_positive_rate(cases: list[EvalCase], firewall: Firewall) -> float:
    benign_cases = [c for c in cases if c.attack_type is None]
    if not benign_cases:
        return 0.0
    flagged = 0
    for case in benign_cases:
        result = firewall.scan(case.text, case.source_type, session_id=f"eval-{id(case)}")
        if result.policy.decision != Decision.ALLOW:
            flagged += 1
    return flagged / len(benign_cases)
