"""Lightweight DLP: label spans that look like secrets/credentials/PII so the
tool gate can judge 'sensitive data + external destination' actions.
"""
import re

_PATTERNS = {
    "api_key": re.compile(r"\b(sk|pk|api)[-_][A-Za-z0-9]{16,}\b"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}


def label_sensitive(text: str) -> dict[str, list[str]]:
    findings: dict[str, list[str]] = {}
    for label, pattern in _PATTERNS.items():
        hits = pattern.findall(text)
        if hits:
            findings[label] = hits
    return findings
