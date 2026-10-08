"""Decode obfuscation techniques used to hide instructions (Encoded Instructions attack)."""
import base64
import codecs
import re

ZERO_WIDTH_CHARS = "\u200b\u200c\u200d\u2060\ufeff"
_ZW_RE = re.compile("[" + ZERO_WIDTH_CHARS + "]")

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{20,}")

# common Cyrillic look-alikes used to dodge keyword-based detectors
HOMOGLYPH_MAP = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0455": "s", "\u0456": "i",
}


def strip_zero_width(text: str) -> str:
    return _ZW_RE.sub("", text)


def normalize_homoglyphs(text: str) -> str:
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def try_decode_base64(candidate: str) -> str | None:
    try:
        decoded = base64.b64decode(candidate, validate=True)
        text = decoded.decode("utf-8")
        return text if text.isprintable() else None
    except Exception:
        return None


def try_decode_hex(candidate: str) -> str | None:
    cleaned = candidate[2:] if candidate.lower().startswith("0x") else candidate
    try:
        decoded = bytes.fromhex(cleaned).decode("utf-8")
        return decoded if decoded.isprintable() else None
    except Exception:
        return None


def try_decode_rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")


def find_encoded_spans(text: str) -> list[tuple[str, str]]:
    """Return (encoding, decoded_text) pairs found inside `text`."""
    findings = []
    for match in _BASE64_RE.finditer(text):
        decoded = try_decode_base64(match.group(1))
        if decoded:
            findings.append(("base64", decoded))
    for match in _HEX_RE.finditer(text):
        decoded = try_decode_hex(match.group(0))
        if decoded:
            findings.append(("hex", decoded))
    # ROT13 hides text by rotating letters, so the whole text is rotated back and
    # handed to the rules as an extra span. Gibberish simply never matches a rule.
    rotated = try_decode_rot13(text)
    if rotated != text:
        findings.append(("rot13", rotated))
    return findings


def normalize_and_decode(text: str) -> tuple[str, list[str]]:
    """Strip obfuscation and surface any decoded hidden instructions as extra spans."""
    cleaned = strip_zero_width(text)
    cleaned = normalize_homoglyphs(cleaned)
    decoded_spans = [decoded for _, decoded in find_encoded_spans(cleaned)]
    return cleaned, decoded_spans
