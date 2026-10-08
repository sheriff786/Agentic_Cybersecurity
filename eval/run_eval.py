"""Evaluation harness: `python -m eval.run_eval [--split seed|dev|test] [--judge none|openai]`

Splits (so you cannot accidentally tune on your final numbers):
  seed  hand-written cases directly in data/attacks and data/benign (harness check only)
  dev   data/*/public_dev  - tune rules/weights against THIS
  test  data/*/public_test - run once at the end; these are the numbers to quote

File names: attack type = known attack-type prefix of the file name
('secret_extraction__003.txt' and 'secret_extraction_malicious_03.txt' both work);
public imports are named public_injection__<tag>_NNNNN.txt.

Reports: per-type recall, benign flagged/blocked, latency, ablation
(including judge rows when --judge openai) and end-to-end attack success rate.
"""
import argparse
import os
import time
from pathlib import Path

from pif_firewall.attack_types import AttackType
from pif_firewall.firewall import Firewall

from eval.attack_success import attack_success_matrix
from eval.metrics import (
    EvalCase,
    benign_rates,
    detection_recall,
    mean_scan_latency_ms,
    overall_block_rate,
    overall_detection_rate,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_TYPE_VALUES = sorted((t.value for t in AttackType), key=len, reverse=True)

ABLATIONS = {
    "full (no judge)":     {},
    "no_normalization":    {"use_normalization": False},
    "no_trust_weighting":  {"use_trust_weighting": False},
    "no_classifier":       {"use_classifier": False},
    "rules_only":          {"use_normalization": False, "use_trust_weighting": False,
                            "use_classifier": False},
}


def _attack_type_from_name(stem: str) -> str:
    for value in _TYPE_VALUES:
        if stem.startswith(value):
            return value
    return stem.split("__")[0]


def _files(folder: Path, recursive: bool) -> list[Path]:
    if not folder.exists():
        return []
    return sorted(folder.rglob("*.txt") if recursive else folder.glob("*.txt"))


def load_cases(split: str) -> list[EvalCase]:
    if split == "seed":
        attack_dirs, benign_dirs, recursive = [DATA_DIR / "attacks"], [DATA_DIR / "benign"], False
    else:
        attack_dirs = [DATA_DIR / "attacks" / f"public_{split}"]
        benign_dirs = [DATA_DIR / "benign" / f"public_{split}"]
        recursive = True
    cases: list[EvalCase] = []
    for folder in attack_dirs:
        for path in _files(folder, recursive):
            cases.append(EvalCase(path.read_text(encoding="utf-8"), _attack_type_from_name(path.stem)))
    for folder in benign_dirs:
        for path in _files(folder, recursive):
            cases.append(EvalCase(path.read_text(encoding="utf-8"), None))
    return cases


class TimedJudge:
    """Wraps a judge backend to count calls and measure latency separately."""

    def __init__(self, inner):
        self.inner, self.calls, self.total = inner, 0, 0.0

    def __call__(self, text):
        start = time.perf_counter()
        try:
            return self.inner(text)
        finally:
            self.calls += 1
            self.total += time.perf_counter() - start

    def summary(self) -> str:
        mean = self.total / self.calls * 1000 if self.calls else 0.0
        return f"judge calls {self.calls}, mean {mean:.0f} ms/call"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["seed", "dev", "test"], default="seed")
    parser.add_argument("--judge", choices=["none", "openai"], default="none")
    args = parser.parse_args()

    if args.judge == "openai" and not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("--judge openai needs OPENAI_API_KEY (and: pip install -e .[judge]). "
                         "Without it the judge would silently return neutral verdicts.")

    cases = load_cases(args.split)
    if not cases:
        hint = ("add .txt files under data/attacks and data/benign" if args.split == "seed"
                else "run eval.import_public_dataset first")
        print(f"No '{args.split}' cases found - {hint}.")
        return
    n_attack = sum(c.attack_type is not None for c in cases)
    print(f"Split: {args.split} | cases: {n_attack} attack, {len(cases) - n_attack} benign")
    if args.split == "test":
        print("FINAL REPORT SPLIT: do not tune rules/weights on these cases.")
    if args.split == "seed":
        print("(seed split is hand-written: a harness check, not a benchmark)")
    print()

    judge_rows: dict[str, tuple[Firewall, TimedJudge]] = {}
    if args.judge == "openai":
        from pif_firewall.detection.judge_backends import make_openai_judge

        for label, routing in (("+judge, uncertain band only", False), ("+judge, with action routing", True)):
            timed = TimedJudge(make_openai_judge())
            judge_rows[label] = (Firewall(judge_backend=timed, judge_on_action=routing), timed)

    main_fw = judge_rows["+judge, with action routing"][0] if judge_rows else Firewall()

    print("1) Per-attack-type recall (flagged = quarantine or block):")
    for attack_type, value in sorted(detection_recall(cases, main_fw).items()):
        print(f"   {attack_type:<24} {value:.0%}")

    rates = benign_rates(cases, main_fw)
    print(f"\n2) Benign false positives: flagged {rates['flagged']:.0%} | hard-blocked {rates['blocked']:.0%}")
    print(f"3) Mean scan latency (rules path, no judge): {mean_scan_latency_ms(cases, Firewall()):.3f} ms/case")

    print("\n4) Ablation  (attack flagged | attack blocked | benign flagged | benign blocked):")
    for name, kwargs in ABLATIONS.items():
        det = overall_detection_rate(cases, Firewall(**kwargs))
        blk = overall_block_rate(cases, Firewall(**kwargs))
        br = benign_rates(cases, Firewall(**kwargs))
        print(f"   {name:<30} {det:>5.0%} | {blk:>5.0%} | {br['flagged']:>5.0%} | {br['blocked']:>5.0%}")
    for name, (fw, timed) in judge_rows.items():
        det = overall_detection_rate(cases, fw)
        blk = overall_block_rate(cases, fw)
        br = benign_rates(cases, fw)
        print(f"   {name:<30} {det:>5.0%} | {blk:>5.0%} | {br['flagged']:>5.0%} | {br['blocked']:>5.0%}"
              f"   [{timed.summary()}]")

    print("\n5) End-to-end attack success rate (lower is better):")
    print(f"   {'config':<15} {'all':>6} {'rule_matching':>14} {'evasive':>9}")
    for name, row in attack_success_matrix().items():
        print(f"   {name:<15} {row['all']:>6.0%} {row['rule_matching']:>14.0%} {row['evasive']:>9.0%}")


if __name__ == "__main__":
    main()
