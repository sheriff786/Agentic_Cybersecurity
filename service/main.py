"""Thin FastAPI wrapper around the pif_firewall core library - drop-in HTTP
API for any agent framework, per the 'Agent Security Gateway' positioning."""
import os
from fastapi import FastAPI
from dotenv import load_dotenv

from pif_firewall.firewall import Firewall
from pif_firewall.ingest.document import SourceType
from pif_firewall.detection.judge_backends import make_openai_judge

from service.schemas import GateRequest, GateResponse, ScanRequest, ScanResponse

# Load environment variables from .env file
load_dotenv()

# Optionally enable LLM judge if OpenAI API key is present
_openai_key = os.getenv("OPENAI_API_KEY")
_judge_backend = make_openai_judge() if _openai_key else None

app = FastAPI(title="Prompt Injection Firewall - Agent Security Gateway")
firewall = Firewall(judge_backend=_judge_backend, judge_on_action=True)
print(f'FIREWALL MAIN: judge_backend={_judge_backend is not None}, judge_on_action={firewall.judge_on_action}', flush=True)


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
    result = firewall.gate(req.tool_name, req.arguments, req.payload_text, session_id=req.session_id)
    return GateResponse(decision=result.decision.value, reason=result.reason)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}

