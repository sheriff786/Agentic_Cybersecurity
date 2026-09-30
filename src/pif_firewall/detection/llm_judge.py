"""Isolated LLM judge, only invoked by the ensemble for uncertain cases.

Security property: the judge only ever *reads* content and returns a
structured verdict. It never receives tool access and its output is never
treated as instructions to execute - only as a classification signal.
"""
from dataclasses import dataclass
from typing import Callable, Optional

from pif_firewall.attack_types import AttackType


@dataclass
class JudgeVerdict:
    attack_type: Optional[AttackType]
    confidence: float
    evidence_span: str
    rationale: str


JudgeBackend = Callable[[str], JudgeVerdict]


def judge(text: str, backend: Optional[JudgeBackend] = None) -> Optional[JudgeVerdict]:
    """Call the configured LLM backend. Returns None when no backend is wired up
    (keeps the pipeline runnable/testable without an LLM API key)."""
    if backend is None:
        return None
    return backend(text)
