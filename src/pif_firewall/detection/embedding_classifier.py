"""Embedding-based classifier stage of the detection ensemble.

This module defines the interface expected by the ensemble. Ship a real
sentence-embedding + classifier (e.g. a small logistic-regression head over
sentence-transformers) here; for now it exposes a lightweight lexical
fallback so the pipeline runs end-to-end without extra model downloads.
"""
from dataclasses import dataclass

_SUSPICIOUS_TERMS = (
    "ignore", "disregard", "override", "jailbreak", "bypass", "unrestricted",
    "system prompt", "exfiltrate", "wire transfer", "do anything now",
)


@dataclass
class ClassifierScore:
    score: float  # 0..1 probability of malicious intent
    matched_terms: list[str]


def classify(text: str) -> ClassifierScore:
    lowered = text.lower()
    matched = [term for term in _SUSPICIOUS_TERMS if term in lowered]
    score = min(1.0, 0.15 * len(matched))
    return ClassifierScore(score=score, matched_terms=matched)
