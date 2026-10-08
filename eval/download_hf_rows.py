"""Download one split of a Hugging Face dataset to JSONL using the public
datasets-server API (the same endpoint as the 'API' button on the dataset page).
Standard library only - no pandas/pyarrow/datasets needed.

    python -m eval.download_hf_rows --dataset deepset/prompt-injections --split train --out data_raw/deepset_train.jsonl
    python -m eval.download_hf_rows --dataset deepset/prompt-injections --split test  --out data_raw/deepset_test.jsonl

Then feed the JSONL to eval.import_public_dataset. The API returns at most 100
rows per request, so this pages through the split.
"""
import argparse
import json
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://datasets-server.huggingface.co/rows"
PAGE = 100


def fetch_page(dataset: str, config: str, split: str, offset: int, length: int = PAGE) -> dict:
    query = urllib.parse.urlencode({"dataset": dataset, "config": config, "split": split,
                                    "offset": offset, "length": length})
    request = urllib.request.Request(f"{API}?{query}", headers={"User-Agent": "pif-firewall-eval"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def download(dataset: str, split: str, config: str = "default", fetch=fetch_page) -> list[dict]:
    rows: list[dict] = []
    offset = 0
    while True:
        page = fetch(dataset, config, split, offset)
        batch = [item["row"] for item in page.get("rows", [])]
        rows.extend(batch)
        offset += len(batch)
        if not batch or offset >= page.get("num_rows_total", offset):
            return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", required=True, help="e.g. deepset/prompt-injections")
    parser.add_argument("--split", default="train")
    parser.add_argument("--config", default="default")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    rows = download(args.dataset, args.split, args.config)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")
    print(f"Wrote {len(rows)} rows to {out}")
    if rows:
        print("Columns:", ", ".join(rows[0].keys()))


if __name__ == "__main__":
    main()
