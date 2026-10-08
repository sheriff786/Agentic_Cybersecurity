"""Tool-call gate: the containment layer. Even when detection misses an
attack in the content, dangerous actions (reading a secret, sending sensitive
data to an external address, deleting files, wire transfers) are checked here
before execution.

`untrusted_origin=True` means the action was derived from retrieved/external
content (email, PDF, web page) rather than typed by the user. That is the
provenance signal the gate uses. It is session/turn-level, not exact lineage.
"""
import os
from dataclasses import dataclass
from enum import Enum

from pif_firewall.gate.dlp import SecretRegistry, is_sensitive_path, label_sensitive
from pif_firewall.policy.taint import SessionTaint


def _internal_suffixes() -> tuple[str, ...]:
    """Configurable via PIF_INTERNAL_DOMAINS, e.g. "@company.com,@corp.example"."""
    raw = os.environ.get("PIF_INTERNAL_DOMAINS", "@company.com")
    suffixes = []
    for item in raw.split(","):
        item = item.strip().lower()
        if item:
            suffixes.append(item if item.startswith("@") else "@" + item)
    return tuple(suffixes)


INTERNAL_DOMAIN_SUFFIXES: tuple[str, ...] = _internal_suffixes()

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
    return not recipient.lower().endswith(_internal_suffixes())


def gate(call: ToolCall, payload_text: str, taint: SessionTaint,
         registry: SecretRegistry | None = None, untrusted_origin: bool = False) -> GateResult:
    """Known limitations (see docs/failure_cases.md): sensitivity comes from DLP
    patterns, the secret registry and path naming rules; an attack that stays
    fully inside an allowed action (e.g. a misleading but 'legitimate' internal
    email) is not caught here."""
    findings = label_sensitive(payload_text, registry)

    if call.name == "read_file":
        path = str(call.arguments.get("path", ""))
        if is_sensitive_path(path):
            if untrusted_origin:
                return GateResult(GateDecision.BLOCK,
                                  f"sensitive path {path} requested by untrusted content")
            if taint.tainted:
                return GateResult(GateDecision.REVIEW,
                                  f"sensitive path {path} read during tainted session")
        return GateResult(GateDecision.ALLOW, "no policy violation detected")

    if call.name == "send_email":
        recipient = call.arguments.get("to", "")
        external = _is_external_recipient(recipient)
        if findings and external:
            return GateResult(
                GateDecision.BLOCK,
                f"sensitive data ({list(findings)}) -> external recipient {recipient}",
            )
        if external and untrusted_origin:
            return GateResult(
                GateDecision.REVIEW,
                f"external send to {recipient} was triggered by untrusted content",
            )
        if external and taint.tainted:
            return GateResult(
                GateDecision.REVIEW,
                "session tainted by earlier untrusted content; external send needs review",
            )

    if call.name in SENSITIVE_TOOLS and taint.tainted:
        return GateResult(GateDecision.REVIEW, "sensitive tool call during tainted session")

    return GateResult(GateDecision.ALLOW, "no policy violation detected")
