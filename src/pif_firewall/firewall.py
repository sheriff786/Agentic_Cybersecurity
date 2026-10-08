"""Main orchestrator: the single entry point demo agents and the FastAPI
service call into. Implements the locked flow:
normalize -> fast detectors -> (uncertain) LLM judge -> trust/taint policy ->
Allow/Quarantine/Block, plus a separate gate() for tool calls.

The use_* flags exist for the ablation study in eval/ (turn one layer off and
measure what drops). Leave them all True in production.
"""
from dataclasses import dataclass

from pif_firewall.audit.logger import AuditLogger, new_record
from pif_firewall.detection.ensemble import assess
from pif_firewall.gate.dlp import SecretRegistry, is_sensitive_path
from pif_firewall.gate.tool_gate import GateResult, ToolCall, gate as gate_tool_call
from pif_firewall.ingest.document import SourceType, TrustLevel
from pif_firewall.ingest.normalizers import normalize
from pif_firewall.policy.decision import PolicyResult, decide
from pif_firewall.policy.taint import TaintStore
from pif_firewall.policy.trust import weighted_risk


@dataclass
class ScanResult:
    policy: PolicyResult
    risk_score: float
    attack_types: list[str]


class Firewall:
    def __init__(self, judge_backend=None, audit_path: str | None = None,
                 use_normalization: bool = True, use_trust_weighting: bool = True,
                 use_classifier: bool = True, judge_on_action: bool = True) -> None:
        self.judge_backend = judge_backend
        self.audit = AuditLogger(path=audit_path)
        self.taint_store = TaintStore()
        self.secrets = SecretRegistry()
        self.use_normalization = use_normalization
        self.use_trust_weighting = use_trust_weighting
        self.use_classifier = use_classifier
        self.judge_on_action = judge_on_action

    # ---- content scanning -------------------------------------------------
    def scan(self, raw_text: str, source_type: SourceType, session_id: str = "default",
             origin: str = "unknown", trust_level: TrustLevel | None = None) -> ScanResult:
        doc = normalize(raw_text, source_type, origin=origin, trust_level=trust_level,
                        decode=self.use_normalization)
        assessment = assess(doc.text, decoded_spans=doc.decoded_spans,
                            judge_backend=self.judge_backend, use_classifier=self.use_classifier,
                            judge_on_action=self.judge_on_action and doc.trust_level != TrustLevel.USER)
        if self.use_trust_weighting:
            assessment.risk_score = weighted_risk(assessment.risk_score, doc.trust_level)

        policy_result = decide(doc.text, assessment)
        self.taint_store.record(session_id, assessment.risk_score)

        self.audit.log(new_record(
            stage="content_policy",
            decision=policy_result.decision.value,
            reason=policy_result.reason,
            attack_types=[a.value for a in assessment.attack_types],
            session_id=session_id,
        ))

        return ScanResult(
            policy=policy_result,
            risk_score=assessment.risk_score,
            attack_types=[a.value for a in assessment.attack_types],
        )

    # ---- containment ------------------------------------------------------
    def register_secret(self, value: str) -> None:
        """Operator registers known secret values (vault contents, canary tokens)."""
        self.secrets.add(value)

    def record_tool_output(self, tool_name: str, arguments: dict, output: str) -> None:
        """Call after a tool returns. Output of a sensitive-path read becomes a
        registered secret, so a later send_email carrying it is caught by DLP
        even if the value has no recognisable format."""
        if tool_name == "read_file" and is_sensitive_path(str(arguments.get("path", ""))):
            self.secrets.add(output)

    def gate(self, tool_name: str, arguments: dict, payload_text: str = "",
             session_id: str = "default", untrusted_origin: bool = False) -> GateResult:
        taint = self.taint_store.get(session_id)
        result = gate_tool_call(ToolCall(name=tool_name, arguments=arguments), payload_text,
                                taint, registry=self.secrets, untrusted_origin=untrusted_origin)
        self.audit.log(new_record(
            stage="tool_gate",
            decision=result.decision.value,
            reason=result.reason,
            session_id=session_id,
        ))
        return result
