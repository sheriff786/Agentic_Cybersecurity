"""Evaluation harness entry point: `python -m eval.run_eval`

Loads attack/benign cases from data/attacks and data/benign (plain .txt
files, one case per file, attack type read from the filename prefix before
'__'), and reports the metrics called out in the review verdict: per-attack
recall and benign FPR. Extend with latency/ablation/attack-success-rate as
the eval set grows.
"""
import time
from pathlib import Path

from pif_firewall.firewall import Firewall

from eval.metrics import EvalCase, benign_false_positive_rate, detection_recall

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load_cases() -> list[EvalCase]:
    cases: list[EvalCase] = []
    attacks_dir = DATA_DIR / "attacks"
    benign_dir = DATA_DIR / "benign"
    for path in sorted(attacks_dir.glob("*.txt")):
        text = path.read_text(encoding="utf-8")
        attack_type = path.stem.split("__")[0]
        cases.append(EvalCase(text=text, attack_type=attack_type))
    for path in sorted(benign_dir.glob("*.txt")):
        cases.append(EvalCase(text=path.read_text(encoding="utf-8"), attack_type=None))
    return cases


def main() -> None:
    cases = _load_cases()
    if not cases:
        print("No eval cases found yet - add .txt files under data/attacks and data/benign.")
        return

    firewall = Firewall()
    start = time.perf_counter()
    recall = detection_recall(cases, firewall)
    fpr = benign_false_positive_rate(cases, firewall)
    elapsed = time.perf_counter() - start

    print("Per-attack-type recall:")
    for attack_type, value in recall.items():
        print(f"  {attack_type}: {value:.2%}")
    print(f"Benign false-positive rate: {fpr:.2%}")
    print(f"Total eval time: {elapsed:.3f}s over {len(cases)} cases")


if __name__ == "__main__":
    main()
