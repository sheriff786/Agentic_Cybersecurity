"""Source-specific normalization into plain text with provenance tagging.

Keeps external dependencies optional: falls back to regex-based stripping
when a parsing library (bs4, python-docx) is not installed.
"""
import re

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


def _extract_text(raw: str, source_type: SourceType) -> str:
    if source_type in (SourceType.HTML, SourceType.WEB_PAGE):
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

            document = docx.Document(io.BytesIO(raw.encode() if isinstance(raw, str) else raw))
            return "\n".join(p.text for p in document.paragraphs)
        except ImportError:
            return raw
    return raw


def normalize(raw: str, source_type: SourceType, origin: str = "unknown",
              trust_level: TrustLevel | None = None) -> NormalizedDocument:
    """Turn arbitrary source content into a common, decoded text representation."""
    extracted = _extract_text(raw, source_type)
    cleaned, decoded_spans = normalize_and_decode(extracted)
    return NormalizedDocument(
        text=cleaned,
        source_type=source_type,
        trust_level=trust_level or _DEFAULT_TRUST.get(source_type, TrustLevel.RETRIEVED),
        origin=origin,
        decoded_spans=decoded_spans,
    )
