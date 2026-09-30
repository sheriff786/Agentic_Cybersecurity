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
pytest
uvicorn service.main:app --reload
```

## Attack coverage (target: 7 of 9 for F3)

| Category | Attack types | Caught by |
|---|---|---|
| A. Content manipulation | Instruction Override, Role Change, Encoded Instructions, Indirect Injection | Detection ensemble + normalize layer |
| B. Exfiltration / abuse | Secret Extraction, Credential Theft, Tool Abuse | Tool gate + output scan |
| C. Stateful | Context Poisoning, Multi-Step Jailbreaks | Session taint tracker |
