"""Common document representation produced by the ingest layer."""
from dataclasses import dataclass, field
from enum import Enum


class SourceType(str, Enum):
    USER_MESSAGE = "user_message"
    WEB_PAGE = "web_page"
    PDF = "pdf"
    EMAIL = "email"
    MARKDOWN = "markdown"
    HTML = "html"
    WORD_DOC = "word_doc"
    API_RESPONSE = "api_response"
    OCR_TEXT = "ocr_text"
    SOURCE_CODE = "source_code"
    IMAGE = "image"


class TrustLevel(str, Enum):
    """Retrieved/external content starts lower-trust than direct user input."""
    USER = "user"
    RETRIEVED = "retrieved"
    TOOL_OUTPUT = "tool_output"


@dataclass
class NormalizedDocument:
    text: str
    source_type: SourceType
    trust_level: TrustLevel
    origin: str = "unknown"
    decoded_spans: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
