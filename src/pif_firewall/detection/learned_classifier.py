"""Learned prompt-injection classifier (TF-IDF n-grams + logistic regression).

Training happens offline with scikit-learn (eval/train_classifier.py), which
exports a plain JSON model. INFERENCE HAS NO ML DEPENDENCY and loads no pickle:
the vectoriser maths is reimplemented here (sublinear tf x idf, L2 norm, dot
product with the coefficients) and is checked against scikit-learn by a parity
test and at training time. JSON also means a poisoned model file cannot execute code.

Behaviour contract:
  - no model file            -> score() returns None, the firewall behaves as before
  - text with no known terms -> score() returns None (unknown is NOT 'maybe an attack')
  - otherwise a probability in [0, 1]; the model carries TWO thresholds chosen from
    cross-validated out-of-fold predictions: a flag (quarantine) threshold and a much
    stricter block threshold, so an ML-only signal alone rarely hard-blocks
Model location: $PIF_CLASSIFIER_PATH, else <repo>/models/injection_clf.json, else ./models/...
"""
import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

_TOKEN = re.compile(r"[a-z0-9']+")

# Function words ignored when measuring how much of a text the model actually knows.
_STOP = frozenset("""a an the and or but if of to in on at by for with from as is are was were be been it its
this that these those i you he she we they me my your our their him her them us not no so do does did
have has had will would can could should there here what which who whom how when where why than then
too very just also about into over under up down out off""".split())


def content_tokens(text: str) -> list[str]:
    """Lower-cased word tokens without function words; used for the coverage guard."""
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 1]


def analyze(text: str) -> list[str]:
    """Unigrams + bigrams over lower-cased word tokens (shared by training and inference)."""
    tokens = _TOKEN.findall(text.lower())
    return tokens + [f"{a} {b}" for a, b in zip(tokens, tokens[1:])]


@dataclass
class LearnedModel:
    vocab: dict[str, int]
    idf: list[float]
    coef: list[float]
    intercept: float
    threshold: float = 0.5          # flag (quarantine) at or above this probability
    block_threshold: float = 0.9    # hard-block at or above this probability
    min_coverage: float = 0.0       # share of content words the model must know before it speaks
    meta: dict = field(default_factory=dict)

    def _weights(self, text: str) -> dict[str, float]:
        counts = Counter(t for t in analyze(text) if t in self.vocab)
        if not counts:
            return {}
        raw = {t: (1.0 + math.log(c)) * self.idf[self.vocab[t]] for t, c in counts.items()}
        norm = math.sqrt(sum(w * w for w in raw.values()))
        return {t: w / norm for t, w in raw.items()} if norm else {}

    def coverage(self, text: str) -> float:
        """Share of the text's content words that are in the model's vocabulary."""
        tokens = content_tokens(text)
        return sum(t in self.vocab for t in tokens) / len(tokens) if tokens else 0.0

    def signal(self, text: str) -> float | None:
        """What the firewall uses: score(), but silent when the text is mostly outside what
        the model was trained on. With few known terms, L2 normalisation lets two or three
        words dominate the vector and the probability is meaningless."""
        if self.coverage(text) < self.min_coverage:
            return None
        return self.score(text)

    def score(self, text: str) -> float | None:
        weights = self._weights(text)
        if not weights:
            return None
        z = self.intercept + sum(self.coef[self.vocab[t]] * w for t, w in weights.items())
        return 1.0 / (1.0 + math.exp(-z))

    def explain(self, text: str, k: int = 3) -> list[str]:
        """Spans of the ORIGINAL text for the n-grams pushing the score up most
        (explainability + something concrete for quarantine to redact)."""
        weights = self._weights(text)
        contributions = sorted(((self.coef[self.vocab[t]] * w, t) for t, w in weights.items()), reverse=True)
        spans: list[str] = []
        for value, term in contributions:
            if value <= 0 or len(spans) >= k:
                break
            pattern = r"\W+".join(re.escape(part) for part in term.split())
            found = re.search(pattern, text, re.I)
            if found and found.group(0) not in spans:
                spans.append(found.group(0))
        return spans

    @classmethod
    def from_dict(cls, data: dict) -> "LearnedModel":
        return cls(vocab=data["vocab"], idf=data["idf"], coef=data["coef"], intercept=data["intercept"],
                   threshold=data.get("threshold", 0.5),
                   block_threshold=data.get("block_threshold", 0.9),
                   min_coverage=data.get("min_coverage", 0.0), meta=data.get("meta", {}))

    def to_dict(self) -> dict:
        return {"vocab": self.vocab, "idf": self.idf, "coef": self.coef, "intercept": self.intercept,
                "threshold": self.threshold, "block_threshold": self.block_threshold,
                "min_coverage": self.min_coverage, "meta": self.meta}


_model: LearnedModel | None = None
_loaded = False


def _candidate_paths() -> list[Path]:
    paths = []
    if os.environ.get("PIF_CLASSIFIER_PATH"):
        paths.append(Path(os.environ["PIF_CLASSIFIER_PATH"]))
    paths.append(Path(__file__).resolve().parents[3] / "models" / "injection_clf.json")
    paths.append(Path.cwd() / "models" / "injection_clf.json")
    return paths


def get_model() -> LearnedModel | None:
    global _model, _loaded
    if not _loaded:
        _loaded = True
        for path in _candidate_paths():
            if path.is_file():
                _model = LearnedModel.from_dict(json.loads(path.read_text(encoding="utf-8")))
                break
    return _model


def set_model(model: LearnedModel | None) -> None:
    """Install (or clear) a model explicitly. Used by tests and by training scripts."""
    global _model, _loaded
    _model, _loaded = model, True


def score(text: str) -> float | None:
    model = get_model()
    return model.score(text) if model else None


def status() -> str:
    model = get_model()
    if not model:
        return "not loaded (no models/injection_clf.json); rules + lexical score only"
    return (f"loaded: {len(model.vocab)} terms, quarantine>={model.threshold:.2f}, block>={model.block_threshold:.2f}, "
            f"min content-word coverage {model.min_coverage:.0%}, "
            f"trained on {model.meta.get('n_train', '?')} cases")
