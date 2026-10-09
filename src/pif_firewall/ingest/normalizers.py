"""Source-specific normalization into plain text with provenance tagging.

Keeps external dependencies optional: falls back to regex-based stripping
when a parsing library (bs4, python-docx) is not installed.
"""
import re
from typing import Union

from pif_firewall.ingest.decoders import normalize_and_decode
from pif_firewall.ingest.document import NormalizedDocument, SourceType, TrustLevel

_TAG_RE = re.compile(r"<[^>]+>")
_HIDDEN_STYLE_RE = re.compile(
    r"<[^>]+style=\"[^\"]*(display:\s*none|visibility:\s*hidden|font-size:\s*0)[^\"]*\"[^>]*>.*?</[^>]+>",
    re.IGNORECASE | re.DOTALL,
)

_DEFAULT_TRUST = {
    SourceType.USER_MESSAGE: TrustLevel.USER,
    SourceType.WEB_PAGE: TrustLevel.RETRIEVED,
    SourceType.PDF: TrustLevel.RETRIEVED,
    SourceType.EMAIL: TrustLevel.RETRIEVED,
    SourceType.MARKDOWN: TrustLevel.RETRIEVED,
    SourceType.HTML: TrustLevel.RETRIEVED,
    SourceType.WORD_DOC: TrustLevel.RETRIEVED,
    SourceType.API_RESPONSE: TrustLevel.TOOL_OUTPUT,
    SourceType.OCR_TEXT: TrustLevel.RETRIEVED,
    SourceType.SOURCE_CODE: TrustLevel.RETRIEVED,
    SourceType.IMAGE: TrustLevel.RETRIEVED,
}


def _strip_html(raw: str) -> str:
    # remove content hidden via CSS before stripping tags, a common smuggling trick
    no_hidden = _HIDDEN_STYLE_RE.sub(" ", raw)
    return _TAG_RE.sub(" ", no_hidden)


def _extract_text(raw: Union[str, bytes], source_type: SourceType) -> str:
    if source_type in (SourceType.HTML, SourceType.WEB_PAGE):
        if isinstance(raw, bytes):
            raw = raw.decode(errors="ignore")
        try:
            from bs4 import BeautifulSoup  # optional dependency

            soup = BeautifulSoup(raw, "html.parser")
            for hidden in soup.select('[style*="display:none"], [style*="visibility:hidden"]'):
                hidden.decompose()
            return soup.get_text(separator=" ")
        except ImportError:
            return _strip_html(raw)
    if source_type == SourceType.WORD_DOC:
        try:
            import io

            import docx  # python-docx, optional dependency

            if isinstance(raw, str):
                raw = raw.encode()
            document = docx.Document(io.BytesIO(raw))
            return "\n".join(p.text for p in document.paragraphs)
        except ImportError:
            if isinstance(raw, bytes):
                return raw.decode(errors="ignore")
            return raw
    if source_type == SourceType.PDF:
        try:
            import io
            import PyPDF2

            if isinstance(raw, str):
                raw = raw.encode(errors="ignore")
            pdf_reader = PyPDF2.PdfReader(io.BytesIO(raw))
            text = []
            for page in pdf_reader.pages:
                text.append(page.extract_text() or "")
            return "\n".join(text)
        except Exception:
            # fallback: treat as raw text (will likely be garbage)
            if isinstance(raw, bytes):
                return raw.decode(errors="ignore")
            return raw
    if source_type == SourceType.IMAGE:
        try:
            from PIL import Image
            import pytesseract
            import io

            if isinstance(raw, str):
                # assume it's a base64 or path? we'll just return raw
                return raw
            image = Image.open(io.BytesIO(raw))
            # Perform OCR
            text = pytesseract.image_to_string(image)
            return text
        except Exception:
            # OCR dependencies not installed or other error
            if isinstance(raw, bytes):
                # Could not extract text; return empty or raise?
                return ""
            return raw
    # For any other source type, just return raw as string
    if isinstance(raw, bytes):
        return raw.decode(errors="ignore")
    return raw


def normalize(raw: Union[str, bytes], source_type: SourceType, origin: str = "unknown",
              trust_level: TrustLevel | None = None, decode: bool = True) -> NormalizedDocument:
    """Turn arbitrary source content into a common, decoded text representation."""
    extracted = _extract_text(raw, source_type)
    cleaned, decoded_spans = normalize_and_decode(extracted) if decode else (extracted, [])
    return NormalizedDocument(
        text=cleaned,
        source_type=source_type,
        trust_level=trust_level or _DEFAULT_TRUST.get(source_type, TrustLevel.RETRIEVED),
        origin=origin,
        decoded_spans=decoded_spans,
    )
