"""Combine rule, embedding-classifier, decoded-span and (uncertain-only) judge
signals into a single risk score and set of matched attack types."""
from dataclasses import dataclass, field

from pif_firewall.attack_types import AttackType
from pif_firewall.detection import embedding_classifier, llm_judge, rules

UNCERTAIN_LOW = 0.25
UNCERTAIN_HIGH = 0.65


@dataclass
class RiskAssessment:
    risk_score: float
    attack_types: set[AttackType] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)
    judge_invoked: bool = False


def assess(text: str, decoded_spans: list[str] | None = None,
           judge_backend=None) -> RiskAssessment:
    rule_hits = rules.scan(text)
    for span in decoded_spans or []:
        hidden_hits = rules.scan(span)
        for hit in hidden_hits:
            hit.evidence = f"[decoded:{span[:40]}] {hit.evidence}"
        rule_hits.extend(hidden_hits)
        if hidden_hits:
            rule_hits.append(rules.RuleMatch(AttackType.ENCODED_INSTRUCTIONS, span[:60], 0.5))

    classifier_result = embedding_classifier.classify(text)

    attack_types = {hit.attack_type for hit in rule_hits}
    evidence = [hit.evidence for hit in rule_hits]
    rule_score = min(1.0, sum(hit.weight for hit in rule_hits))
    combined = max(rule_score, classifier_result.score)

    judge_invoked = False
    if UNCERTAIN_LOW <= combined <= UNCERTAIN_HIGH:
        verdict = llm_judge.judge(text, backend=judge_backend)
        judge_invoked = True
        if verdict and verdict.attack_type:
            attack_types.add(verdict.attack_type)
            evidence.append(verdict.evidence_span)
            combined = max(combined, verdict.confidence)

    return RiskAssessment(
        risk_score=combined,
        attack_types=attack_types,
        evidence=evidence,
        judge_invoked=judge_invoked,
    )
