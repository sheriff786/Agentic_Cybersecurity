# Prompt Injection Firewall — Agent Security Gateway

ET AI Hackathon (Agentic Edition) — Problem 2.

**Thesis:** detection of prompt injection will never be perfect, so dangerous
agent actions must be independently authorized (contained) regardless of
whether detection catches the attack in the content itself.

Target grid position: **F3 (7+ attack types) + D2 (high-reliability, structured/textual input)**.

## Architecture

Normalize → fast rule/embedding detectors → (uncertain cases only) isolated
LLM judge → trust + session-taint policy → **Allow / Quarantine / Block** →
agent → **tool-call gate** (Allow / Block / Review) → audit log.

See [docs/architecture.md](docs/architecture.md) for the full flow diagram and
[docs/failure_cases.md](docs/failure_cases.md) for known limitations (reported
honestly, on purpose).

## Layout

- `src/pif_firewall/` — core library (ingest, detection, policy, gate, audit)
- `service/` — thin FastAPI wrapper (`/scan`, `/gate`) for drop-in use by any agent
- `demo_agent/` — mock enterprise email assistant with 3 demo scenes
- `eval/` — recall / false-positive-rate / attack-success-rate harness
- `data/` — attack + benign sample sets for evaluation
- `tests/` — unit tests per layer

## Quick start

```powershell
pip install -e .[service,parsers,dev]
python -m demo_agent.run_demo
python -m eval.run_eval
pytest
uvicorn service.main:app --reload
```

## Implementation status (read this before claiming anything)

| Component | Status |
|---|---|
| Normalize: zero-width, homoglyph, base64, hex, ROT13, hidden HTML | implemented |
| Rule detectors (9 attack types, per-type calibrated weights) | implemented |
| "Embedding classifier" | **placeholder**: a lexical keyword score behind the same interface, not an embedding model |
| LLM judge | **interface + OpenAI backend** (`detection/judge_backends.py`); runs only if you pass `judge_backend=`. Routed to when the score is uncertain OR when untrusted content is action-bearing (verb + email/URL/path), so plain-language attacks reach it. Verified with mocked clients, not a live API |
| Trust weighting, 3-tier Allow/Quarantine/Block, session taint | implemented |
| Tool gate: sensitive-path reads, DLP + secret registry, external-send review | implemented; sensitivity comes from naming/patterns/registry (see failure cases) |
| Human review of REVIEW outcomes | `approver` callback in the demo agent (default deny) |
| Eval harness (recall, FPR flagged/blocked, latency, ablation, attack success rate) | implemented; ships with a small **hand-written seed set**, so numbers are a harness check, not a benchmark |

Evaluation discipline: `python -m eval.import_public_dataset` splits any public dataset into a
DEV half (tune against it) and a TEST half (run once, quote only those numbers):
```
python -m eval.run_eval --split seed   # hand-written harness check
python -m eval.run_eval --split dev    # tune here
python -m eval.run_eval --split test   # final report only
python -m eval.run_eval --split dev --judge openai   # needs OPENAI_API_KEY
```

## Attack coverage (target: 7 of 9 for F3)

| Category | Attack types | Caught by |
|---|---|---|
| A. Content manipulation | Instruction Override, Role Change, Encoded Instructions, Indirect Injection | Detection ensemble + normalize layer |
| B. Exfiltration / abuse | Secret Extraction, Credential Theft, Tool Abuse | Tool gate + output scan |
| C. Stateful | Context Poisoning, Multi-Step Jailbreaks | Session taint tracker |
