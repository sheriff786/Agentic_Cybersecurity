"""Canonical attack taxonomy for the Prompt Injection Firewall.

Grouped into A/B/C categories for architecture + presentation:
  A: Content-level manipulation (caught by the detection ensemble)
  B: Exfiltration / abuse (caught by the tool gate + output scan)
  C: Stateful / cross-turn attacks (caught by the session taint tracker)
"""
from enum import Enum


class AttackCategory(str, Enum):
    CONTENT_MANIPULATION = "A"
    EXFILTRATION_ABUSE = "B"
    STATEFUL = "C"


class AttackType(str, Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_CHANGE = "role_change"
    SECRET_EXTRACTION = "secret_extraction"
    TOOL_ABUSE = "tool_abuse"
    CREDENTIAL_THEFT = "credential_theft"
    CONTEXT_POISONING = "context_poisoning"
    MULTI_STEP_JAILBREAK = "multi_step_jailbreak"
    ENCODED_INSTRUCTIONS = "encoded_instructions"
    INDIRECT_INJECTION = "indirect_injection"


ATTACK_CATEGORY = {
    AttackType.INSTRUCTION_OVERRIDE: AttackCategory.CONTENT_MANIPULATION,
    AttackType.ROLE_CHANGE: AttackCategory.CONTENT_MANIPULATION,
    AttackType.ENCODED_INSTRUCTIONS: AttackCategory.CONTENT_MANIPULATION,
    AttackType.INDIRECT_INJECTION: AttackCategory.CONTENT_MANIPULATION,
    AttackType.SECRET_EXTRACTION: AttackCategory.EXFILTRATION_ABUSE,
    AttackType.CREDENTIAL_THEFT: AttackCategory.EXFILTRATION_ABUSE,
    AttackType.TOOL_ABUSE: AttackCategory.EXFILTRATION_ABUSE,
    AttackType.CONTEXT_POISONING: AttackCategory.STATEFUL,
    AttackType.MULTI_STEP_JAILBREAK: AttackCategory.STATEFUL,
}
