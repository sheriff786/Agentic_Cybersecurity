"""Combine rule, embedding-classifier, decoded-span and (uncertain-only) judge
signals into a single risk score and set of matched attack types."""
from dataclasses import dataclass, field

from pif_firewall.attack_types import AttackType
from pif_firewall.detection import action_signals, embedding_classifier, llm_judge, rules
from pif_firewall.detection.embedding_classifier import ClassifierScore

UNCERTAIN_LOW = 0.25
UNCERTAIN_HIGH = 0.65


@dataclass
class RiskAssessment:
    risk_score: float
    attack_types: set[AttackType] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)
    judge_invoked: bool = False
    judge_reason: str = ""


def assess(text: str, decoded_spans: list[str] | None = None,
           judge_backend=None, use_classifier: bool = True,
           judge_on_action: bool = False) -> RiskAssessment:
    """judge_on_action: also route action-bearing text whose score is below the
    uncertain band to the judge (set for untrusted/retrieved content only)."""
    rule_hits = rules.scan(text)
    for span in decoded_spans or []:
        hidden_hits = rules.scan(span)
        for hit in hidden_hits:
            hit.evidence = f"[decoded:{span[:40]}] {hit.evidence}"
        rule_hits.extend(hidden_hits)
        if hidden_hits:
            rule_hits.append(rules.RuleMatch(AttackType.ENCODED_INSTRUCTIONS, span[:60], 0.5))

    classifier_result = (embedding_classifier.classify(text) if use_classifier
                         else ClassifierScore(score=0.0, matched_terms=[]))

    attack_types = {hit.attack_type for hit in rule_hits}
    evidence = [hit.evidence for hit in rule_hits]
    rule_score = min(1.0, sum(hit.weight for hit in rule_hits))
    combined = max(rule_score, classifier_result.score)

    judge_invoked = False
    judge_reason = ""
    if UNCERTAIN_LOW <= combined <= UNCERTAIN_HIGH:
        judge_reason = "uncertain_band"
    elif judge_on_action and combined < UNCERTAIN_LOW and action_signals.is_action_bearing(text):
        judge_reason = "action_bearing"
    print(f"DEBUG: judge_on_action={judge_on_action}, combined={combined}, action_bearing={action_signals.is_action_bearing(text)}, judge_reason='{judge_reason}'", flush=True)
    if judge_reason and judge_backend is not None:
        print(f"DEBUG: Invoking judge with text={text[:50]}", flush=True)
        verdict = llm_judge.judge(text, backend=judge_backend)
        print(f"DEBUG: Judge verdict: {verdict}", flush=True)
        judge_invoked = True
        if verdict and verdict.attack_type:
            attack_types.add(verdict.attack_type)
            evidence.append(verdict.evidence_span)
            combined = max(combined, verdict.confidence)
            print(f"DEBUG: Updated combined to {combined}", flush=True)

    return RiskAssessment(
        risk_score=combined,
        attack_types=attack_types,
        evidence=evidence,
        judge_invoked=judge_invoked,
        judge_reason=judge_reason if judge_invoked else "",
    )
