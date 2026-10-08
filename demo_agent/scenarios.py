"""Demo scenes. Scenes 1-3 are the original plan; 2b and 2c prove the thesis:
detection is imperfect (2b/2c use an attack no rule matches), so containment
at the tool gate is what actually stops the leak."""
from pif_firewall.firewall import Firewall

from demo_agent.agent import EmailAssistantAgent
from demo_agent.tools import SECRET_VAULT, SENT_EMAILS


def _make_firewall() -> Firewall:
    firewall = Firewall()
    for secret in SECRET_VAULT.values():  # operator registers known secrets
        firewall.register_secret(secret)
    return firewall


def _run(title: str, agent: EmailAssistantAgent, query: str) -> list[str]:
    SENT_EMAILS.clear()
    log = [title]
    log += agent.handle_inbox_query(query)
    log.append(f"sent emails: {SENT_EMAILS}")
    return log


def scene_without_firewall() -> list[str]:
    return _run("=== Scene 1: indirect injection, NO firewall ===",
                EmailAssistantAgent(firewall=None), "poisoned")


def scene_with_firewall() -> list[str]:
    return _run("=== Scene 2: same attack, WITH firewall (detection catches it) ===",
                EmailAssistantAgent(firewall=_make_firewall(), session_id="scene2"), "poisoned")


def scene_evasive_contained() -> list[str]:
    return _run("=== Scene 2b: EVASIVE attack, detection MISSES, tool gate contains it ===",
                EmailAssistantAgent(firewall=_make_firewall(), session_id="scene2b"), "evasive")


def scene_evasive_detection_only() -> list[str]:
    return _run("=== Scene 2c: same evasive attack, detection ONLY (gate off) -> leak ===",
                EmailAssistantAgent(firewall=_make_firewall(), session_id="scene2c", use_gate=False),
                "evasive")


def scene_benign_passthrough() -> list[str]:
    return _run("=== Scene 3: benign request, WITH firewall ===",
                EmailAssistantAgent(firewall=_make_firewall(), session_id="scene3"), "benign")
