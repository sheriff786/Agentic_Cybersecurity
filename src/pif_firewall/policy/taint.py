"""Approximate, session-level taint tracking for Context Poisoning and
Multi-Step Jailbreaks: attacks that don't look malicious in a single turn.

This is intentionally coarse (turn-level taint, not exact data-lineage
tracing, which isn't reliably possible inside an LLM pipeline): once
untrusted content enters a session above a threshold, every tool call in
that turn is marked tainted and the gate applies a stricter policy.
"""
from dataclasses import dataclass, field


@dataclass
class SessionTaint:
    session_id: str
    accumulated_risk: float = 0.0
    tainted: bool = False
    history: list[float] = field(default_factory=list)

    def observe(self, risk_score: float, decay: float = 0.85, threshold: float = 0.5) -> None:
        self.accumulated_risk = self.accumulated_risk * decay + risk_score
        self.history.append(risk_score)
        self.tainted = self.accumulated_risk >= threshold


class TaintStore:
    """In-memory per-session taint state. Swap for Redis/DB in production."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionTaint] = {}

    def get(self, session_id: str) -> SessionTaint:
        return self._sessions.setdefault(session_id, SessionTaint(session_id=session_id))

    def record(self, session_id: str, risk_score: float) -> SessionTaint:
        taint = self.get(session_id)
        taint.observe(risk_score)
        return taint
