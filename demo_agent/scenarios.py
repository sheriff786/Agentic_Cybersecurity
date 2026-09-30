"""Three demo scenes matching the locked plan: attack without firewall,
attack with firewall (contained even if detection is imperfect), and a
benign pass-through with minimal disruption."""
from pif_firewall.firewall import Firewall

from demo_agent.agent import EmailAssistantAgent
from demo_agent.tools import SENT_EMAILS


def scene_without_firewall() -> list[str]:
    SENT_EMAILS.clear()
    agent = EmailAssistantAgent(firewall=None)
    log = ["=== Scene 1: indirect injection, NO firewall ==="]
    log += agent.handle_inbox_query("poisoned")
    log.append(f"sent emails: {SENT_EMAILS}")
    return log


def scene_with_firewall() -> list[str]:
    SENT_EMAILS.clear()
    firewall = Firewall()
    agent = EmailAssistantAgent(firewall=firewall, session_id="scene2")
    log = ["=== Scene 2: same attack, WITH firewall ==="]
    log += agent.handle_inbox_query("poisoned")
    log.append(f"sent emails: {SENT_EMAILS}")
    return log


def scene_benign_passthrough() -> list[str]:
    SENT_EMAILS.clear()
    firewall = Firewall()
    agent = EmailAssistantAgent(firewall=firewall, session_id="scene3")
    log = ["=== Scene 3: benign request, WITH firewall ==="]
    log += agent.handle_inbox_query("benign")
    log.append(f"sent emails: {SENT_EMAILS}")
    return log
