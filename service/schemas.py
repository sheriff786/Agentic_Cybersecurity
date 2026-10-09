"""Pydantic request/response models for the FastAPI wrapper."""
from pydantic import BaseModel


class ScanRequest(BaseModel):
    text: str
    source_type: str = "user_message"
    session_id: str = "default"
    origin: str = "unknown"


class ScanResponse(BaseModel):
    decision: str
    sanitized_text: str
    reason: str
    risk_score: float
    attack_types: list[str]


class GateRequest(BaseModel):
    tool_name: str
    arguments: dict
    payload_text: str = ""
    session_id: str = "default"
    untrusted_origin: bool = False  # True when the action was derived from retrieved/external content


class GateResponse(BaseModel):
    decision: str
    reason: str


class RegisterSecretRequest(BaseModel):
    value: str
