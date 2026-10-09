"""Thin FastAPI wrapper around the pif_firewall core library - drop-in HTTP
API for any agent framework, per the 'Agent Security Gateway' positioning."""
from fastapi import FastAPI

from pif_firewall.firewall import Firewall
from pif_firewall.ingest.document import SourceType

from service.schemas import (
    GateRequest,
    GateResponse,
    RegisterSecretRequest,
    ScanRequest,
    ScanResponse,
)

app = FastAPI(title="Prompt Injection Firewall - Agent Security Gateway")
firewall = Firewall()


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    source_type = SourceType(req.source_type)
    result = firewall.scan(req.text, source_type, session_id=req.session_id, origin=req.origin)
    return ScanResponse(
        decision=result.policy.decision.value,
        sanitized_text=result.policy.sanitized_text,
        reason=result.policy.reason,
        risk_score=result.risk_score,
        attack_types=result.attack_types,
    )


@app.post("/gate", response_model=GateResponse)
def gate(req: GateRequest) -> GateResponse:
    result = firewall.gate(req.tool_name, req.arguments, req.payload_text,
                           session_id=req.session_id, untrusted_origin=req.untrusted_origin)
    return GateResponse(decision=result.decision.value, reason=result.reason)


@app.post("/register-secret")
def register_secret(req: RegisterSecretRequest) -> dict:
    """Operator registers a known secret value (never logged or echoed back)."""
    firewall.register_secret(req.value)
    return {"status": "registered"}


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
