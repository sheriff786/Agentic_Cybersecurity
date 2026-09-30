"""Minimal agent loop: retrieves content, (optionally) scans it through the
firewall, and naively acts on embedded instructions - this naivety is the
point, it's what makes indirect injection dangerous without the firewall.
"""
import re

from pif_firewall.firewall import Firewall
from pif_firewall.ingest.document import SourceType
from pif_firewall.policy.decision import Decision

from demo_agent.tools import read_file, search_inbox, send_email

_SEND_RE = re.compile(r"send\b.{0,60}?\bto ([\w.+-]+@[\w-]+\.[\w.-]+)", re.I)
_READ_RE = re.compile(r"read ([\w./\\-]+\.[a-z0-9]+)", re.I)


class EmailAssistantAgent:
    def __init__(self, firewall: Firewall | None = None, session_id: str = "demo") -> None:
        self.firewall = firewall
        self.session_id = session_id

    def _maybe_scan(self, text: str, origin: str) -> tuple[str, bool]:
        """Returns (text_to_use, is_blocked)."""
        if self.firewall is None:
            return text, False
        result = self.firewall.scan(text, SourceType.EMAIL, session_id=self.session_id, origin=origin)
        if result.policy.decision == Decision.BLOCK:
            return "", True
        return result.policy.sanitized_text, False

    def _maybe_gate(self, tool_name: str, arguments: dict, payload_text: str) -> bool:
        """Returns True if the tool call is allowed to execute."""
        if self.firewall is None:
            return True
        result = self.firewall.gate(tool_name, arguments, payload_text, session_id=self.session_id)
        return result.decision.value == "allow"

    def handle_inbox_query(self, query: str) -> list[str]:
        log: list[str] = []
        raw_email = search_inbox(query)
        text, blocked = self._maybe_scan(raw_email, origin=f"inbox:{query}")
        if blocked:
            log.append("[firewall] content BLOCKED - agent will not act on this email")
            return log

        read_match = _READ_RE.search(text)
        send_match = _SEND_RE.search(text)

        if read_match:
            file_contents = read_file(read_match.group(1))
            log.append(f"[agent] read {read_match.group(1)} -> {file_contents}")
            if send_match:
                recipient = send_match.group(1)
                if self._maybe_gate("send_email", {"to": recipient}, file_contents):
                    send_email(recipient, "Re: your request", file_contents)
                    log.append(f"[agent] sent contents to {recipient} (LEAK if attacker-controlled)")
                else:
                    log.append(f"[firewall] tool gate BLOCKED send_email to {recipient}")
        elif send_match:
            recipient = send_match.group(1)
            if self._maybe_gate("send_email", {"to": recipient}, text):
                send_email(recipient, "Re: your request", "Q3 report attached.")
                log.append(f"[agent] sent report to {recipient}")
            else:
                log.append(f"[firewall] tool gate BLOCKED send_email to {recipient}")
        else:
            log.append("[agent] no actionable instruction found in email")
        return log
