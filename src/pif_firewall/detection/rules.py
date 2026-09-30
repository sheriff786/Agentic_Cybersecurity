"""Fast, cheap pattern-based detectors. First line of the detection ensemble."""
import re
from dataclasses import dataclass

from pif_firewall.attack_types import AttackType


@dataclass
class RuleMatch:
    attack_type: AttackType
    evidence: str
    weight: float


_PATTERNS: dict[AttackType, list[re.Pattern]] = {
    AttackType.INSTRUCTION_OVERRIDE: [
        re.compile(r"ignore (all|any|the) (previous|prior|above) instructions", re.I),
        re.compile(r"disregard (your|the) (system prompt|instructions|guidelines)", re.I),
        re.compile(r"forget (everything|what) (you were told|above)", re.I),
        re.compile(r"new instructions?:", re.I),
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


def scan(text: str) -> list[RuleMatch]:
    """Run every compiled pattern against the text; cheap, deterministic, explainable."""
    matches: list[RuleMatch] = []
    for attack_type, patterns in _PATTERNS.items():
        for pattern in patterns:
            found = pattern.search(text)
            if found:
                matches.append(RuleMatch(attack_type=attack_type, evidence=found.group(0), weight=0.6))
    return matches
