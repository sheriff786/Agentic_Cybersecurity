"""Fast, cheap pattern-based detectors. First line of the detection ensemble."""
import re
from dataclasses import dataclass

from pif_firewall.attack_types import AttackType


@dataclass
class RuleMatch:
    attack_type: AttackType
    evidence: str
    weight: float


# --- instruction-override family -------------------------------------------------
# Generalises "ignore (all|any|the) (previous|prior|above) instructions" to the
# real-world variants: a DISCARD verb + optional scope words + an instruction-like
# noun ("ignore previous directions", "forget all prior tasks", "disregard the
# above prompt"). The look-behinds skip negations ("don't ignore the rules").
_NEG = r"(?<!n't )(?<!\bnot )(?<!\bnever )"
_DISCARD = r"(?:ignore|disregard|forget|discard|override|overlook|neglect|abandon)"
_SCOPE = (r"(?:all|any|every|everything|anything|the|your|these|those|my|previous|prior|preceding|"
          r"above|earlier|former|foregoing|initial|original|system)")
_OBJECT = (r"(?:instructions?|directions?|directives?|prompts?|rules?|orders?|tasks?|commands?|"
           r"guidelines?|constraints?|restrictions?|programming|context|messages?|requests?|text)")
_TIME = r"(?:before|above|earlier|so far|beforehand|until now)"

# --- exfiltration co-signal ---------------------------------------------------------
# "send ALL emails to a@b.com": a bulk/sensitive object followed by an external-looking
# address. Weak on its own (0.3, below the quarantine threshold: the content scan cannot
# know which domains are internal; the tool gate does), but it tips a message that
# already carries an override signal over the block threshold.
_EXFIL = (r"\b(?:send|forward|email|mail|share|upload|post|leak|export)\b[^.\n]{0,40}?"
          r"\b(?:all|every|everything|entire|whole|complete|full|confidential|secret|private|"
          r"passwords?|credentials?|customers?|records?|database)\b[^.\n]{0,40}?"
          r"\b(?:to|at)\s+[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

_PATTERNS: dict[AttackType, list] = {
    AttackType.INSTRUCTION_OVERRIDE: [
        re.compile(r"ignore (all|any|the) (previous|prior|above) instructions", re.I),
        re.compile(r"disregard (your|the) (system prompt|instructions|guidelines)", re.I),
        re.compile(r"forget (everything|what) (you were told|above)", re.I),
        re.compile(r"new instructions?:", re.I),
        re.compile(_NEG + r"\b" + _DISCARD + r"\s+(?:" + _SCOPE + r"\s+){1,4}" + _OBJECT + r"\b", re.I),
        re.compile(_NEG + r"\b" + _DISCARD + r"\s+(?:everything|all|anything)\b(?:\s+\w+){0,3}?\s+" + _TIME + r"\b", re.I),
        re.compile(_NEG + r"\b" + _DISCARD + r"\s+(?:the\s+)?above\b", re.I),
    ],
    AttackType.ROLE_CHANGE: [
        re.compile(r"you are now [a-z0-9_\- ]{2,40}", re.I),
        re.compile(r"act as (an? )?(unrestricted|jailbroken|dan|developer mode)", re.I),
        re.compile(r"pretend (you are|to be) .*(no rules|unfiltered|without restrictions)", re.I),
        re.compile(r"\bDAN\b|do anything now", re.I),
    ],
    AttackType.SECRET_EXTRACTION: [
        re.compile(r"(reveal|print|show|output) (your|the) (system prompt|hidden instructions)", re.I),
        re.compile(r"what (are|is) your (instructions|system prompt|rules)", re.I),
        re.compile(r"repeat (everything|the text) above", re.I),
    ],
    AttackType.TOOL_ABUSE: [
        re.compile(r"(send|forward|email) .*(to|at) [\w.+-]+@[\w-]+\.[\w.-]+.*(without|silently|don't (tell|notify))", re.I),
        re.compile(r"use the (.*)tool to (delete|exfiltrate|transfer|wire)", re.I),
        re.compile(r"call (the )?[a-z_]+\(.*\) (immediately|without confirmation)", re.I),
        (re.compile(_EXFIL, re.I), 0.3),   # (pattern, weight) overrides the per-type weight
    ],
    AttackType.CREDENTIAL_THEFT: [
        re.compile(r"(api[_ ]?key|password|secret[_ ]?key|access[_ ]?token|private[_ ]?key)\s*[:=]", re.I),
        re.compile(r"enter your (password|credentials|otp|one-time code)", re.I),
        re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    ],
    AttackType.CONTEXT_POISONING: [
        re.compile(r"for (all|any) future (messages|turns|requests|conversations)", re.I),
        re.compile(r"remember this (for|as) (the rest of|every future)", re.I),
        re.compile(r"from now on,? (always|never)", re.I),
    ],
    AttackType.MULTI_STEP_JAILBREAK: [
        re.compile(r"step 1[:.].*step 2", re.I | re.S),
        re.compile(r"first,? .*then,? ignore", re.I | re.S),
        re.compile(r"let's play a game where", re.I),
    ],
    AttackType.INDIRECT_INJECTION: [
        re.compile(r"<!--\s*(ignore|system|assistant)[:\s]", re.I),
        re.compile(r"\[hidden instructions?\]", re.I),
        re.compile(r"note to (ai|assistant|model|llm)\s*:", re.I),
    ],
}


# Calibrated per attack type. A single generic phrase ("ignore previous
# instructions") must NOT reach the block threshold on its own once the
# retrieved-content trust multiplier is applied (0.5 x 1.35 = 0.675 -> quarantine),
# while highly specific patterns (hidden-instruction markers, "send ... silently")
# are strong enough to block alone. Two independent hits always block.
_WEIGHTS: dict[AttackType, float] = {
    AttackType.INSTRUCTION_OVERRIDE: 0.5,
    AttackType.ROLE_CHANGE: 0.5,
    AttackType.SECRET_EXTRACTION: 0.5,
    AttackType.TOOL_ABUSE: 0.8,
    AttackType.CREDENTIAL_THEFT: 0.5,
    AttackType.CONTEXT_POISONING: 0.5,
    AttackType.MULTI_STEP_JAILBREAK: 0.4,
    AttackType.INDIRECT_INJECTION: 0.7,
}


def scan(text: str) -> list[RuleMatch]:
    """Run every compiled pattern against the text; cheap, deterministic, explainable.

    Overlapping matches of the SAME attack type are merged into one hit (highest
    weight wins), so several phrasings of one idea never count as independent
    evidence. Hits of different types, or non-overlapping hits, do add up."""
    raw: list[tuple[AttackType, int, int, float]] = []
    for attack_type, patterns in _PATTERNS.items():
        for entry in patterns:
            pattern, weight = entry if isinstance(entry, tuple) else (entry, _WEIGHTS.get(attack_type, 0.5))
            found = pattern.search(text)
            if found:
                raw.append((attack_type, found.start(), found.end(), weight))

    merged: list[list] = []
    for attack_type, start_pos, end_pos, weight in sorted(raw, key=lambda r: (r[0].value, r[1])):
        last = merged[-1] if merged else None
        if last and last[0] == attack_type and start_pos < last[2]:
            last[2] = max(last[2], end_pos)
            last[3] = max(last[3], weight)
        else:
            merged.append([attack_type, start_pos, end_pos, weight])
    return [RuleMatch(attack_type=a, evidence=text[b:c], weight=w) for a, b, c, w in merged]
