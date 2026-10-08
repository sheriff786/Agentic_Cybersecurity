"""Turn a public prompt-injection dataset (JSONL, CSV or Parquet) into eval cases,
split deterministically into a DEV half and a frozen TEST half.

    python -m eval.import_public_dataset --input deepset_train.jsonl --tag deepset --english-only
    python -m eval.import_public_dataset --input data.parquet --text-field prompt --label-field label

Output (plain .txt files, one case per file):
    data/attacks/public_dev/   data/attacks/public_test/
    data/benign/public_dev/    data/benign/public_test/

Discipline that keeps your numbers honest:
  * tune rules / weights / thresholds ONLY against --split dev
  * run --split test once, at the end, and quote only those numbers
  * the split is by hash of the text, so duplicates can never land in both halves
Label handling: 1 / true / injection / jailbreak / malicious / attack -> attack,
everything else -> benign. For 3-class datasets (e.g. 2 = harmful request) rows
labelled 2 are SKIPPED, because they are not injections.
Check each dataset's licence before redistributing files (data/*/public_* is in .gitignore).
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_ATTACK_LABELS = {"1", "true", "injection", "malicious", "attack", "jailbreak", "injected"}
_SKIP_LABELS = {"2"}  # e.g. "direct request for harmful behaviour" in 3-class datasets
_EN_STOPWORDS = {"the", "and", "to", "of", "a", "in", "is", "you", "that", "it", "for", "on",
                 "with", "as", "are", "this", "be", "or", "your", "i", "not", "all", "please"}


def read_rows(path: Path):
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)
    elif suffix == ".parquet":
        try:
            import pandas as pd
        except ImportError as exc:  # pragma: no cover
            raise SystemExit("Parquet needs: pip install pandas pyarrow") from exc
        yield from pd.read_parquet(path).to_dict(orient="records")
    else:
        with path.open(encoding="utf-8", newline="") as fh:
            yield from csv.DictReader(fh)


def looks_english(text: str) -> bool:
    words = [w.strip(".,!?;:'\"()").lower() for w in text.split()]
    if len(words) < 4:
        return True  # too short to judge; keep
    return sum(w in _EN_STOPWORDS for w in words) / len(words) >= 0.12


def bucket_of(text: str) -> str:
    return "dev" if int(hashlib.sha1(text.encode("utf-8")).hexdigest(), 16) % 2 == 0 else "test"


def import_rows(rows, text_field: str, label_field: str, tag: str, data_dir: Path = DATA_DIR,
                english_only: bool = False, limit: int = 0) -> dict[str, int]:
    counts = {"attack_dev": 0, "attack_test": 0, "benign_dev": 0, "benign_test": 0,
              "skipped_duplicate": 0, "skipped_non_english": 0, "skipped_other_label": 0}
    seen: set[str] = set()
    for i, row in enumerate(rows):
        if limit and i >= limit:
            break
        text, label = str(row[text_field]).strip(), str(row[label_field]).strip().lower()
        if not text:
            continue
        if label in _SKIP_LABELS:
            counts["skipped_other_label"] += 1
            continue
        if english_only and not looks_english(text):
            counts["skipped_non_english"] += 1
            continue
        digest = hashlib.sha1(text.encode("utf-8")).hexdigest()
        if digest in seen:
            counts["skipped_duplicate"] += 1
            continue
        seen.add(digest)

        side = bucket_of(text)
        kind = "attack" if label in _ATTACK_LABELS else "benign"
        folder = data_dir / ("attacks" if kind == "attack" else "benign") / f"public_{side}"
        folder.mkdir(parents=True, exist_ok=True)
        counts[f"{kind}_{side}"] += 1
        n = counts[f"{kind}_{side}"]
        name = f"public_injection__{tag}_{n:05d}.txt" if kind == "attack" else f"benign__{tag}_{n:05d}.txt"
        (folder / name).write_text(text, encoding="utf-8")
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--label-field", default="label")
    parser.add_argument("--tag", default="", help="short dataset name used in file names")
    parser.add_argument("--english-only", action="store_true",
                        help="drop non-English rows (the rules are English-only)")
    parser.add_argument("--limit", type=int, default=0, help="max rows (0 = all)")
    args = parser.parse_args()

    path = Path(args.input)
    counts = import_rows(read_rows(path), args.text_field, args.label_field,
                         tag=args.tag or path.stem, english_only=args.english_only, limit=args.limit)
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
