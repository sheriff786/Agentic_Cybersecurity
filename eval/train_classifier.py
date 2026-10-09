"""Train the learned classifier on the DEV split and export a dependency-free JSON model.

    pip install -e .[ml]
    python -m eval.train_classifier --split dev --out models/injection_clf.json

What it does, in order:
  1. loads dev cases (attack = 1, benign = 0); 'test' is refused on purpose
  2. runs stratified k-fold CROSS-VALIDATION with the vectoriser inside every fold
     (no leakage) and prints the honest estimates: ROC AUC, recall at 1% / 5% benign
     false-positive rate, precision/recall at 0.5
  3. picks the decision threshold from the out-of-fold predictions: the smallest
     threshold with benign FPR <= --max-fpr (default 2%), clamped to [0.5, 0.9]
  4. fits on all dev cases, exports JSON, checks pure-Python inference == scikit-learn,
     and prints the strongest features (explainability)

The numbers to trust are the CV ones. After training, `run_eval --split dev` is measured
on data the model has seen, so it is optimistic. The final report is `--split test`, once.
"""
import argparse
import json
import math
from pathlib import Path

from pif_firewall.detection.learned_classifier import LearnedModel, analyze, content_tokens

from eval.run_eval import load_cases


def _sk():
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("Training needs scikit-learn: pip install -e .[ml]") from exc
    return TfidfVectorizer, LogisticRegression


def make_vectorizer():
    TfidfVectorizer, _ = _sk()
    return TfidfVectorizer(analyzer=analyze, min_df=2, sublinear_tf=True)


def make_classifier(C: float):
    _, LogisticRegression = _sk()
    return LogisticRegression(C=C, class_weight="balanced", max_iter=2000)


def fit(texts: list[str], labels: list[int], C: float = 1.0):
    vectorizer = make_vectorizer()
    X = vectorizer.fit_transform(texts)
    return vectorizer, make_classifier(C).fit(X, labels)


def to_model(vectorizer, classifier, threshold: float, meta: dict, block_threshold: float = 0.9,
             min_coverage: float = 0.0) -> LearnedModel:
    vocab = {term: int(idx) for term, idx in vectorizer.vocabulary_.items()}
    return LearnedModel(vocab=vocab, idf=[float(x) for x in vectorizer.idf_],
                        coef=[float(x) for x in classifier.coef_[0]],
                        intercept=float(classifier.intercept_[0]), threshold=threshold,
                        block_threshold=block_threshold, min_coverage=min_coverage, meta=meta)


def out_of_fold_detailed(texts: list[str], labels: list[int], C: float, folds: int,
                         seed: int = 0) -> tuple[list[float], list[float]]:
    """Out-of-fold probabilities AND content-word coverage. The vectoriser (and so the
    vocabulary) is refit inside every fold, so coverage reflects genuinely unseen text.
    Cases with no known terms get probability 0.0: at deployment they produce no signal."""
    from sklearn.model_selection import StratifiedKFold

    folds = max(2, min(folds, sum(labels), len(labels) - sum(labels)))
    probs = [0.0] * len(texts)
    covs = [0.0] * len(texts)
    for train_idx, test_idx in StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed).split(texts, labels):
        vectorizer = make_vectorizer()
        X_train = vectorizer.fit_transform([texts[i] for i in train_idx])
        classifier = make_classifier(C).fit(X_train, [labels[i] for i in train_idx])
        X_test = vectorizer.transform([texts[i] for i in test_idx])
        predicted = classifier.predict_proba(X_test)[:, 1]
        known_rows = X_test.getnnz(axis=1)
        vocab = vectorizer.vocabulary_
        for position, i in enumerate(test_idx):
            probs[i] = float(predicted[position]) if known_rows[position] else 0.0
            tokens = content_tokens(texts[i])
            covs[i] = sum(t in vocab for t in tokens) / len(tokens) if tokens else 0.0
    return probs, covs


def out_of_fold(texts: list[str], labels: list[int], C: float, folds: int, seed: int = 0) -> list[float]:
    return out_of_fold_detailed(texts, labels, C, folds, seed)[0]


def choose_threshold(labels: list[int], probs: list[float], max_fpr: float) -> float:
    benign = [p for p, y in zip(probs, labels) if y == 0]
    for candidate in sorted({round(p, 4) for p in probs} | {0.5, 0.9}):
        fpr = sum(p >= candidate for p in benign) / len(benign) if benign else 0.0
        if fpr <= max_fpr:
            return min(0.9, max(0.5, candidate))
    return 0.9


def choose_block_threshold(labels: list[int], probs: list[float], flag_threshold: float) -> float:
    """Block threshold: above every out-of-fold benign case, with a safety margin (see below).
    Capped at 0.95."""
    benign = [p for p, y in zip(probs, labels) if y == 0]
    highest_benign = max(benign) if benign else 0.0
    # With only ~100 benign cases "no benign above it" is a thin guarantee, so keep a margin:
    # at least 0.05 above the highest out-of-fold benign and at least 0.10 above the flag line.
    return min(0.95, max(flag_threshold + 0.10, round(highest_benign + 0.05, 4)))


def rates_at(labels: list[int], probs: list[float], threshold: float) -> tuple[float, float]:
    attacks = [p for p, y in zip(probs, labels) if y == 1]
    benign = [p for p, y in zip(probs, labels) if y == 0]
    return (sum(p >= threshold for p in attacks) / len(attacks), sum(p >= threshold for p in benign) / len(benign))


def report(labels: list[int], probs: list[float]) -> None:
    from sklearn.metrics import precision_score, recall_score, roc_auc_score, roc_curve

    fpr, tpr, _ = roc_curve(labels, probs)

    def recall_at(max_fpr: float) -> float:
        return max((t for f, t in zip(fpr, tpr) if f <= max_fpr), default=0.0)

    preds = [int(p >= 0.5) for p in probs]
    benign = [p for p, y in zip(probs, labels) if y == 0]
    print(f"  ROC AUC                    {roc_auc_score(labels, probs):.3f}")
    print(f"  recall @ benign FPR <= 1%  {recall_at(0.01):.0%}")
    print(f"  recall @ benign FPR <= 5%  {recall_at(0.05):.0%}")
    print(f"  at threshold 0.5: precision {precision_score(labels, preds):.0%} | "
          f"recall {recall_score(labels, preds):.0%} | benign FPR {sum(p >= 0.5 for p in benign) / len(benign):.0%}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["dev", "seed"], default="dev",
                        help="'test' is intentionally not allowed")
    parser.add_argument("--include-seed", action="store_true", help="also train on the hand-written seed cases")
    parser.add_argument("--out", default="models/injection_clf.json")
    parser.add_argument("--C", type=float, default=1.0, help="inverse regularisation strength")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--max-fpr", type=float, default=0.02)
    parser.add_argument("--min-coverage", type=float, default=0.5,
                        help="share of content words the model must know before it gives a signal")
    args = parser.parse_args()

    cases = load_cases(args.split)
    if args.include_seed and args.split != "seed":
        cases += load_cases("seed")
    texts = [c.text for c in cases]
    labels = [int(c.attack_type is not None) for c in cases]
    n_attack = sum(labels)
    if n_attack < 10 or len(labels) - n_attack < 10:
        raise SystemExit(f"Need at least 10 attack and 10 benign cases (have {n_attack}/{len(labels) - n_attack}).")
    print(f"Training data: {n_attack} attack, {len(labels) - n_attack} benign\n")

    print(f"Cross-validated estimate ({args.folds}-fold, vectoriser refit in every fold):")
    probs, covs = out_of_fold_detailed(texts, labels, args.C, args.folds)
    report(labels, probs)

    n_att, n_ben = n_attack, len(labels) - n_attack
    print("\nCoverage guard sweep (what deployment would see; dropped cases give NO ML signal):")
    print(f"  {'min coverage':>12}  {'cases kept':>10}  {'attack recall':>13}  {'benign flagged':>14}")
    for cov in (0.0, 0.3, 0.4, 0.5, 0.6, 0.7):
        masked = [p if c >= cov else 0.0 for p, c in zip(probs, covs)]
        t = choose_threshold(labels, masked, args.max_fpr)
        recall, fpr = rates_at(labels, masked, t)
        kept = sum(c >= cov for c in covs) / len(covs)
        marker = "  <- chosen" if abs(cov - args.min_coverage) < 1e-9 else ""
        print(f"  {cov:>12.0%}  {kept:>10.0%}  {recall:>13.0%}  {fpr:>14.0%}{marker}")

    probs = [p if c >= args.min_coverage else 0.0 for p, c in zip(probs, covs)]
    threshold = choose_threshold(labels, probs, args.max_fpr)
    block_threshold = choose_block_threshold(labels, probs, threshold)
    flag_recall, flag_fpr = rates_at(labels, probs, threshold)
    block_recall, block_fpr = rates_at(labels, probs, block_threshold)
    print(f"\nChosen thresholds (out-of-fold, min coverage {args.min_coverage:.0%}):")
    print(f"  quarantine >= {threshold:.2f}  (benign FPR <= {args.max_fpr:.0%})  -> recall {flag_recall:.0%}, benign flagged {flag_fpr:.0%}")
    print(f"  block      >= {block_threshold:.2f}  (margin above benign)      -> recall {block_recall:.0%}, benign blocked {block_fpr:.0%}")

    vectorizer, classifier = fit(texts, labels, args.C)
    model = to_model(vectorizer, classifier, threshold,
                     meta={"n_train": len(labels), "n_attack": n_attack, "C": args.C, "source_split": args.split},
                     block_threshold=block_threshold, min_coverage=args.min_coverage)

    # parity: pure-Python inference must equal scikit-learn
    sk_probs = classifier.predict_proba(vectorizer.transform(texts))[:, 1]
    diffs = [abs(model.score(t) - p) for t, p in zip(texts, sk_probs) if model.score(t) is not None]
    worst = max(diffs) if diffs else 0.0
    print(f"Parity check vs scikit-learn: max abs diff {worst:.2e}")
    if worst > 1e-9:
        raise SystemExit("Parity check FAILED - refusing to write the model.")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(model.to_dict()), encoding="utf-8")
    print(f"Wrote {out} ({len(model.vocab)} terms)\n")

    inverse = {idx: term for term, idx in model.vocab.items()}
    ranked = sorted(range(len(model.coef)), key=lambda i: model.coef[i], reverse=True)
    print("Strongest ATTACK features:", ", ".join(f"{inverse[i]} ({model.coef[i]:.2f})" for i in ranked[:12]))
    print("Strongest BENIGN features:", ", ".join(f"{inverse[i]} ({model.coef[i]:.2f})" for i in ranked[-8:]))
    print("\nReminder: trust the CV numbers above; `run_eval --split dev` is now optimistic (seen data).")


if __name__ == "__main__":
    main()
