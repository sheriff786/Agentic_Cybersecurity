"""Error analysis: which attacks does the firewall miss, and what words
distinguish them from benign text?

    python -m eval.inspect_misses --split dev --limit 25

Use it BEFORE changing any rule. Look for patterns that generalise (a phrase
family, a structure) instead of copying single sentences into regexes - copied
sentences overfit to the dev set and will not transfer to the test split.
Also prints false positives (benign text that was flagged).
"""
import argparse
import re
from collections import Counter

from pif_firewall.firewall import Firewall
from pif_firewall.policy.decision import Decision

from eval.run_eval import load_cases

_STOP = {"the", "a", "an", "and", "or", "to", "of", "in", "is", "are", "it", "that", "this", "for",
         "on", "with", "as", "be", "was", "were", "i", "you", "me", "my", "your", "we", "at", "by",
         "from", "what", "how", "do", "does", "can", "will", "not", "no", "so", "if", "but", "have",
         "has", "had", "about", "there", "their", "they", "he", "she", "his", "her", "its"}


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z']{3,}", text.lower()) if w not in _STOP}


def _short(text: str, n: int = 170) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[:n] + "..."


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["seed", "dev"], default="dev",
                        help="'test' is intentionally not allowed here")
    parser.add_argument("--limit", type=int, default=25)
    args = parser.parse_args()

    cases = load_cases(args.split)
    fw = Firewall()
    missed, caught, false_pos, benign_all = [], 0, [], []
    for i, case in enumerate(cases):
        decision = fw.scan(case.text, case.source_type, session_id=f"inspect-{i}").policy.decision
        if case.attack_type is not None:
            if decision == Decision.ALLOW:
                missed.append(case.text)
            else:
                caught += 1
        else:
            benign_all.append(case.text)
            if decision != Decision.ALLOW:
                false_pos.append(case.text)

    total = len(missed) + caught
    print(f"Attacks: {total} | caught {caught} | missed {len(missed)}")
    print(f"Benign: {len(benign_all)} | falsely flagged {len(false_pos)}\n")

    print(f"--- First {args.limit} MISSED attacks ---")
    for text in missed[: args.limit]:
        print(f"* {_short(text)}")

    if false_pos:
        print(f"\n--- Falsely flagged benign (up to {args.limit}) ---")
        for text in false_pos[: args.limit]:
            print(f"* {_short(text)}")

    if missed and benign_all:
        miss_df = Counter(w for t in missed for w in _words(t))
        ben_df = Counter(w for t in benign_all for w in _words(t))
        scored = [(w, c, ben_df.get(w, 0), (c / len(missed)) / ((ben_df.get(w, 0) + 1) / len(benign_all)))
                  for w, c in miss_df.items() if c >= 3]
        scored.sort(key=lambda x: -x[3])
        print("\n--- Words over-represented in MISSED attacks vs benign (doc counts) ---")
        print(f"{'word':<16}{'in missed':>10}{'in benign':>11}{'ratio':>8}")
        for word, in_missed, in_benign, ratio in scored[:20]:
            print(f"{word:<16}{in_missed:>10}{in_benign:>11}{ratio:>8.1f}")


if __name__ == "__main__":
    main()
