"""Lightweight DLP: label spans that look like secrets/credentials/PII so the
tool gate can judge 'sensitive data + external destination' actions.

Three sources of "sensitive":
  1. regex patterns for well-known secret formats (keys, cards, emails)
  2. a SecretRegistry of exact known secret values (vault contents, canaries) -
     this catches secrets that have NO recognisable format, e.g. a plain password
  3. path rules (is_sensitive_path) so reading /secrets/* can be gated up-front
"""
import re

_PATTERNS = {
    "api_key": re.compile(r"\b(sk|pk|api)[-_][A-Za-z0-9]{16,}\b"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}

# Naming-based sensitivity. Known limitation: a sensitive file with an innocent
# name/location will not match (see docs/failure_cases.md).
SENSITIVE_PATH_PATTERNS = (
    re.compile(r"(^|/)secrets?(/|$)", re.I),
    re.compile(r"(^|/)\.env(\.|$)", re.I),
    re.compile(r"(^|/)id_(rsa|ed25519|ecdsa)(\.pub)?$", re.I),
    re.compile(r"(credentials?|passwords?|api[_-]?keys?)[^/]*$", re.I),
    re.compile(r"\.(pem|key|pfx|p12)$", re.I),
)


def is_sensitive_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return any(pattern.search(normalized) for pattern in SENSITIVE_PATH_PATTERNS)


class SecretRegistry:
    """Exact-match registry of known secret values (never logged or echoed)."""

    MIN_LEN = 6  # shorter values would cause constant false matches

    def __init__(self) -> None:
        self._secrets: set[str] = set()

    def add(self, value: str) -> None:
        value = (value or "").strip()
        if len(value) >= self.MIN_LEN:
            self._secrets.add(value)

    def find_in(self, text: str) -> int:
        return sum(1 for secret in self._secrets if secret in text)

    def __len__(self) -> int:
        return len(self._secrets)


def label_sensitive(text: str, registry: SecretRegistry | None = None) -> dict[str, list[str]]:
    findings: dict[str, list[str]] = {}
    for label, pattern in _PATTERNS.items():
        hits = pattern.findall(text)
        if hits:
            findings[label] = hits
    if registry is not None:
        count = registry.find_in(text)
        if count:
            findings["known_secret"] = [f"<{count} registered secret(s)>"]
    return findings
