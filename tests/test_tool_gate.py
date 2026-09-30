from pif_firewall.gate.tool_gate import GateDecision, ToolCall, gate
from pif_firewall.policy.taint import SessionTaint


def test_gate_blocks_sensitive_data_to_external_recipient():
    call = ToolCall(name="send_email", arguments={"to": "attacker@external-mail.com"})
    result = gate(call, "api_key: sk-abcdef1234567890", SessionTaint(session_id="s1"))
    assert result.decision == GateDecision.BLOCK


def test_gate_allows_clean_internal_email():
    call = ToolCall(name="send_email", arguments={"to": "colleague@company.com"})
    result = gate(call, "Here is the Q3 report as requested.", SessionTaint(session_id="s2"))
    assert result.decision == GateDecision.ALLOW
