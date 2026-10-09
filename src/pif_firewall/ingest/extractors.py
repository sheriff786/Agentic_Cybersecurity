"""Extract text from heterogeneous inputs before sending them to the Prompt Injection Firewall.

Supported:
- PDF
- Word (.docx)
- Images via Tesseract OCR
- HTML
- Markdown
- Email (.eml)
- JSON API responses
- Source code
- Plain text and OCR text
"""
from __future__ import annotations

import json
from email import policy
from email.parser import BytesParser
from html import unescape
from io import BytesIO
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup
from docx import Document
from PIL import Image, UnidentifiedImageError
from PyPDF2 import PdfReader
import pytesseract

from pif_firewall.ingest.document import SourceType

# Configure this if Tesseract is not available through PATH.
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)
class ExtractionError(RuntimeError):
    """Raised when text extraction fails."""


def extract_content(filename: str, content: bytes) -> str:
    """Dispatch to the right extractor based on file extension.
    
    Args:
        filename: Original filename (may be empty)
        content: File content as bytes
        
    Returns:
        Extracted text as string
        
    Raises:
        ExtractionError: If extraction fails
    """
    if not filename:
        # No filename, treat as plain text
        return content.decode(errors="ignore")
    
    ext = Path(filename.lower()).suffix
    
    try:
        if ext == ".pdf":
            return _extract_pdf(content)
        if ext in (".docx", ".doc"):
            return _extract_word(content)
        if ext in (".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".gif"):
            return _extract_image_ocr(content)
        if ext in (".html", ".htm"):
            return _extract_html(content)
        if ext == ".md":
            return _extract_markdown(content)
        if ext == ".eml":
            return _extract_email(content)
        if ext == ".json":
            return _extract_json(content)
        if ext in (".py", ".js", ".ts", ".java", ".c", ".cpp", ".cs", ".go", ".rs", ".rb", ".php", ".sh", ".bash", ".zsh", ".fish", ".pl", ".pm", ".lua", ".dart", ".scala", ".kotlin", ".swift", ".m", ".mm", ".asm", ".s", ".sql", ".r", ".matlab", ".vb", ".vbs", ".asm", ".s", ".bat", ".cmd", ".ps1", ".psm1", ".tsx", ".jsx", ".vue", ".svelte", ".htm", ".xhtml"):
            return _extract_source_code(content)
        if ext == ".txt" or ext == ".ocr.txt":
            return _extract_plain_text(content)
        # Fallback: treat as plain text
        return content.decode(errors="ignore")
    except Exception as exc:
        raise ExtractionError(f"Failed to extract text from {filename}: {exc}") from exc


def _extract_pdf(content: bytes) -> str:
    """Extract text from PDF using PyPDF2."""
    try:
        pdf_reader = PdfReader(BytesIO(content))
        text = []
        for page in pdf_reader.pages:
            text.append(page.extract_text() or "")
        return "\n".join(text)
    except Exception as exc:
        raise ExtractionError(f"PDF extraction failed: {exc}") from exc


def _extract_word(content: bytes) -> str:
    """Extract text from Word document using python-docx."""
    try:
        document = Document(BytesIO(content))
        return "\n".join(paragraph.text for paragraph in document.paragraphs)
    except Exception as exc:
        raise ExtractionError(f"Word extraction failed: {exc}") from exc


def _extract_image_ocr(content: bytes) -> str:
    """Extract text from image using Tesseract OCR."""
    try:
        image = Image.open(BytesIO(content))
        # Perform OCR
        text = pytesseract.image_to_string(image)
        return text
    except UnidentifiedImageError as exc:
        raise ExtractionError(f"Invalid or unsupported image format: {exc}") from exc
    except Exception as exc:
        raise ExtractionError(f"OCR extraction failed: {exc}") from exc


def _extract_html(content: bytes) -> str:
    """Extract visible text from HTML using BeautifulSoup."""
    try:
        if isinstance(content, bytes):
            raw = content.decode(errors="ignore")
        else:
            raw = content
        
        soup = BeautifulSoup(raw, "html.parser")
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
            
        # Get text
        text = soup.get_text()
        
        # Break into lines and remove leading/trailing space
        lines = (line.strip() for line in text.splitlines())
        # Break multi-headlines into a line each
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        # Drop blank lines
        text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return text
    except Exception as exc:
        raise ExtractionError(f"HTML extraction failed: {exc}") from exc


def _extract_markdown(content: bytes) -> str:
    """Extract text from Markdown (just return as-is for now)."""
    try:
        if isinstance(content, bytes):
            return content.decode(errors="ignore")
        return content
    except Exception as exc:
        raise ExtractionError(f"Markdown extraction failed: {exc}") from exc


def _extract_email(content: bytes) -> str:
    """Extract text from email (.eml) file."""
    try:
        # Parse the email
        msg = BytesParser(policy=policy.default).parsebytes(content)
        
        # Extract headers
        headers = []
        for key in msg.keys():
            value = msg[key]
            if value:
                headers.append(f"{key}: {value}")
        
        headers_text = "\n".join(headers)
        
        # Extract body
        if msg.is_multipart():
            body_parts = []
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    body = part.get_payload(decode=True)
                    if body:
                        body_parts.append(body.decode(errors="ignore"))
                elif content_type == "text/html":
                    # Extract text from HTML part
                    try:
                        html_body = part.get_payload(decode=True)
                        if html_body:
                            html_text = _extract_html(html_body)
                            body_parts.append(html_text)
                    except Exception:
                        # If HTML extraction fails, treat as plain text
                        body = part.get_payload(decode=True)
                        if body:
                            body_parts.append(body.decode(errors="ignore"))
            body_text = "\n\n".join(body_parts)
        else:
            # Not multipart
            body = msg.get_payload(decode=True)
            if body:
                content_type = msg.get_content_type()
                if content_type == "text/html":
                    try:
                        body_text = _extract_html(body)
                    except Exception:
                        body_text = body.decode(errors="ignore")
                else:
                    body_text = body.decode(errors="ignore")
            else:
                body_text = ""
        
        # Combine headers and body
        if headers_text and body_text:
            return f"{headers_text}\n\n{body_text}"
        elif headers_text:
            return headers_text
        else:
            return body_text
    except Exception as exc:
        raise ExtractionError(f"Email extraction failed: {exc}") from exc


def _extract_json(content: bytes) -> str:
    """Extract text from JSON API response."""
    try:
        if isinstance(content, bytes):
            raw = content.decode(errors="ignore")
        else:
            raw = content
        
        # Parse JSON to validate and pretty-print
        parsed = json.loads(raw)
        # Pretty-print with indentation
        return json.dumps(parsed, indent=2, ensure_ascii=False)
    except json.JSONDecodeError as exc:
        raise ExtractionError(f"Invalid JSON: {exc}") from exc
    except Exception as exc:
        raise ExtractionError(f"JSON extraction failed: {exc}") from exc


def _extract_source_code(content: bytes) -> str:
    """Extract text from source code file (just return as-is)."""
    try:
        if isinstance(content, bytes):
            return content.decode(errors="ignore")
        return content
    except Exception as exc:
        raise ExtractionError(f"Source code extraction failed: {exc}") from exc


def _extract_plain_text(content: bytes) -> str:
    """Extract text from plain text file."""
    try:
        if isinstance(content, bytes):
            return content.decode(errors="ignore")
        return content
    except Exception as exc:
        raise ExtractionError(f"Plain text extraction failed: {exc}") from exc