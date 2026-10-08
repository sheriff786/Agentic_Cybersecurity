"""Minimal agent loop: retrieves content, (optionally) scans it through the
firewall, and naively acts on embedded instructions - this naivety is the
point, it's what makes indirect injection dangerous without the firewall.

use_scan / use_gate let the eval harness switch the two defence layers on and
off independently (detection-only vs containment-only vs both).
Every action here is derived from retrieved email text, so tool calls are
gated with untrusted_origin=True.
"""
import re
from typing import Callable, Optional

from pif_firewall.firewall import Firewall
from pif_firewall.gate.tool_gate import GateDecision
from pif_firewall.ingest.document import SourceType
from pif_firewall.policy.decision import Decision

from demo_agent.tools import read_file, search_inbox, send_email

_SEND_RE = re.compile(r"send\b.{0,60}?\bto ([\w.+-]+@[\w-]+(?:\.[\w-]+)+)", re.I)
_READ_RE = re.compile(r"read ([\w./\\-]+\.[a-z0-9]+)", re.I)


class EmailAssistantAgent:
    def __init__(self, firewall: Firewall | None = None, session_id: str = "demo",
                 use_scan: bool = True, use_gate: bool = True,
                 approver: Optional[Callable[[str], bool]] = None) -> None:
        self.firewall = firewall
        self.session_id = session_id
        self.use_scan = use_scan
        self.use_gate = use_gate
        # human-in-the-loop for gate REVIEW outcomes; None means deny by default
        self.approver = approver

    def _maybe_scan(self, text: str, origin: str) -> tuple[str, bool, str]:
        """Returns (text_to_use, is_blocked, log_line)."""
        if self.firewall is None or not self.use_scan:
            return text, False, ""
        result = self.firewall.scan(text, SourceType.EMAIL, session_id=self.session_id, origin=origin)
        line = f"[firewall] content scan -> {result.policy.decision.value} (risk {result.risk_score:.2f})"
        if result.policy.decision == Decision.BLOCK:
            return "", True, line
        return result.policy.sanitized_text, False, line

    def _maybe_gate(self, tool_name: str, arguments: dict, payload_text: str) -> tuple[bool, str]:
        """Returns (allowed, reason)."""
        if self.firewall is None or not self.use_gate:
            return True, ""
        result = self.firewall.gate(tool_name, arguments, payload_text,
                                    session_id=self.session_id, untrusted_origin=True)
        if result.decision == GateDecision.ALLOW:
            return True, result.reason
        if result.decision == GateDecision.REVIEW and self.approver is not None:
            approved = bool(self.approver(f"{tool_name} {arguments}: {result.reason}"))
            return approved, f"{result.reason} (human {'approved' if approved else 'denied'})"
        return False, result.reason

    def handle_inbox_query(self, query: str) -> list[str]:
        log: list[str] = []
        raw_email = search_inbox(query)
        text, blocked, scan_line = self._maybe_scan(raw_email, origin=f"inbox:{query}")
        if scan_line:
            log.append(scan_line)
        if blocked:
            log.append("[firewall] content BLOCKED - agent will not act on this email")
            return log

        read_match = _READ_RE.search(text)
        send_match = _SEND_RE.search(text)

        if read_match:
            path = read_match.group(1)
            allowed, reason = self._maybe_gate("read_file", {"path": path}, "")
            if not allowed:
                log.append(f"[firewall] tool gate BLOCKED read_file {path}: {reason}")
                return log
            file_contents = read_file(path)
            log.append(f"[agent] read {path} -> {file_contents}")
            if self.firewall is not None and self.use_gate:
                self.firewall.record_tool_output("read_file", {"path": path}, file_contents)
            if send_match:
                recipient = send_match.group(1)
                allowed, reason = self._maybe_gate("send_email", {"to": recipient}, file_contents)
                if allowed:
                    send_email(recipient, "Re: your request", file_contents)
                    log.append(f"[agent] sent contents to {recipient} (LEAK if attacker-controlled)")
                else:
                    log.append(f"[firewall] tool gate BLOCKED send_email to {recipient}: {reason}")
        elif send_match:
            recipient = send_match.group(1)
            allowed, reason = self._maybe_gate("send_email", {"to": recipient}, text)
            if allowed:
                send_email(recipient, "Re: your request", "Q3 report attached.")
                log.append(f"[agent] sent report to {recipient}")
            else:
                log.append(f"[firewall] tool gate BLOCKED send_email to {recipient}: {reason}")
        else:
            log.append("[agent] no actionable instruction found in email")
        return log
