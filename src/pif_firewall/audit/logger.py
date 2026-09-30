"""Structured, append-only audit log. Every firewall decision is explainable:
attack_type, confidence, evidence_span and the reason it was allowed/blocked.
"""
import json
import time
from dataclasses import asdict, dataclass, field


@dataclass
class AuditRecord:
    timestamp: float
    stage: str  # "content_policy" | "tool_gate"
    decision: str
    reason: str
    attack_types: list[str] = field(default_factory=list)
    session_id: str | None = None


class AuditLogger:
    def __init__(self, path: str | None = None) -> None:
        self.path = path
        self._records: list[AuditRecord] = []

    def log(self, record: AuditRecord) -> None:
        self._records.append(record)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(record)) + "\n")

    def records(self) -> list[AuditRecord]:
        return list(self._records)


def new_record(stage: str, decision: str, reason: str,
               attack_types: list[str] | None = None, session_id: str | None = None) -> AuditRecord:
    return AuditRecord(
        timestamp=time.time(),
        stage=stage,
        decision=decision,
        reason=reason,
        attack_types=attack_types or [],
        session_id=session_id,
    )
