"""Tool-call gate: the containment layer. Even when detection misses an
attack in the content, dangerous actions (send email to an external address
with sensitive data, delete files, wire transfers, etc.) still get checked
here before execution.
"""
from dataclasses import dataclass
from enum import Enum

from pif_firewall.gate.dlp import label_sensitive
from pif_firewall.policy.taint import SessionTaint

INTERNAL_DOMAIN_SUFFIXES: tuple[str, ...] = ("@company.com",)

SENSITIVE_TOOLS = {"send_email", "transfer_funds", "delete_file", "share_link"}


class GateDecision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


@dataclass
class ToolCall:
    name: str
    arguments: dict


@dataclass
class GateResult:
    decision: GateDecision
    reason: str


def _is_external_recipient(recipient: str) -> bool:
    return not recipient.lower().endswith(INTERNAL_DOMAIN_SUFFIXES)


def gate(call: ToolCall, payload_text: str, taint: SessionTaint) -> GateResult:
    """Known limitation: this only catches sensitive-data-to-external-destination
    patterns backed by DLP labels/policy rules; an attack that stays fully
    inside an allowed action (e.g. a misleading but 'legitimate' internal
    email) will not be caught here. See docs/failure_cases.md."""
    findings = label_sensitive(payload_text)

    if call.name == "send_email":
        recipient = call.arguments.get("to", "")
        if findings and _is_external_recipient(recipient):
            return GateResult(
                decision=GateDecision.BLOCK,
                reason=f"sensitive data ({list(findings)}) -> external recipient {recipient}",
            )
        if taint.tainted and _is_external_recipient(recipient):
            return GateResult(
                decision=GateDecision.REVIEW,
                reason="session tainted by earlier untrusted content; external send needs review",
            )

    if call.name in SENSITIVE_TOOLS and taint.tainted:
        return GateResult(decision=GateDecision.REVIEW, reason="sensitive tool call during tainted session")

    return GateResult(decision=GateDecision.ALLOW, reason="no policy violation detected")
