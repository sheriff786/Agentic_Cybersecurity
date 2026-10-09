"""Thin FastAPI wrapper around the pif_firewall core library - drop-in HTTP
API for any agent framework, per the 'Agent Security Gateway' positioning."""
from fastapi import FastAPI, UploadFile, Form, File

from pif_firewall.firewall import Firewall
from pif_firewall.ingest.document import SourceType
from pif_firewall.detection.judge_backends import make_openai_judge

from service.schemas import (
    GateRequest,
    GateResponse,
    RegisterSecretRequest,
    ScanRequest,
    ScanResponse,
)

app = FastAPI(title="Prompt Injection Firewall - Agent Security Gateway")
firewall = Firewall(judge_backend=make_openai_judge())


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


def _get_source_type(filename: str, content_type: str) -> SourceType:
    """Guess SourceType from file extension or content-type."""
    if not filename:
        # fallback to content-type
        if content_type == "application/pdf":
            return SourceType.PDF
        if content_type in ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/msword"):
            return SourceType.WORD_DOC
        if content_type.startswith("image/"):
            return SourceType.IMAGE
        if content_type == "application/json":
            return SourceType.API_RESPONSE
        if content_type == "message/rfc822":
            return SourceType.EMAIL
        if content_type == "text/plain":
            return SourceType.USER_MESSAGE
        # default to USER_MESSAGE
        return SourceType.USER_MESSAGE
    # Use filename extension
    import os
    ext = os.path.splitext(filename.lower())[1]
    if ext == ".pdf":
        return SourceType.PDF
    if ext in (".docx", ".doc"):
        return SourceType.WORD_DOC
    if ext == ".txt" or ext == ".ocr.txt":
        return SourceType.USER_MESSAGE
    if ext in (".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".gif"):
        return SourceType.IMAGE
    if ext in (".html", ".htm"):
        return SourceType.HTML
    if ext == ".md":
        return SourceType.MARKDOWN
    if ext == ".eml":
        return SourceType.EMAIL
    if ext == ".json":
        return SourceType.API_RESPONSE
    if ext in (".py", ".js", ".ts", ".java", ".c", ".cpp", ".cs", ".go", ".rs", ".rb", ".php", ".sh", ".bash", ".zsh", ".fish", ".pl", ".pm", ".lua", ".dart", ".scala", ".kotlin", ".swift", ".m", ".mm", ".asm", ".s", ".sql", ".r", ".matlab", ".vb", ".vbs", ".asm", ".s", ".bat", ".cmd", ".ps1", ".psm1", ".tsx", ".jsx", ".vue", ".svelte", ".htm", ".xhtml"):
        return SourceType.SOURCE_CODE
    # fallback to content-type
    if content_type == "application/pdf":
        return SourceType.PDF
    if content_type in ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/msword"):
        return SourceType.WORD_DOC
    if content_type.startswith("image/"):
        return SourceType.IMAGE
    if content_type == "application/json":
        return SourceType.API_RESPONSE
    if content_type == "message/rfc822":
        return SourceType.EMAIL
    if content_type == "text/plain":
        return SourceType.USER_MESSAGE
    return SourceType.USER_MESSAGE


@app.post("/scan-file", response_model=ScanResponse)
async def scan_file(
    file: UploadFile = File(...),
    session_id: str = Form("default"),
    origin: str = Form("unknown"),
):
    # Determine source type based on file extension or content-type
    filename = file.filename or ""
    content_type = file.content_type or ""
    source_type = _get_source_type(filename, content_type)
    # Read file content
    content = await file.read()
    # Extract text content using appropriate extracter
    from pif_firewall.ingest.extractors import extract_content, ExtractionError
    try:
        extracted_text = extract_content(filename, content)
    except ExtractionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # Call firewall scan directly with extracted text
    result = firewall.scan(extracted_text, source_type, session_id=session_id, origin=origin)
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
