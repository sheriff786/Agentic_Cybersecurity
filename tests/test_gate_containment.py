from pif_firewall.firewall import Firewall
from pif_firewall.gate.tool_gate import GateDecision, ToolCall, gate
from pif_firewall.policy.taint import SessionTaint


def _taint(tainted=False):
    t = SessionTaint(session_id="t")
    t.tainted = tainted
    return t


def test_read_sensitive_path_from_untrusted_content_is_blocked():
    result = gate(ToolCall("read_file", {"path": "/secrets/db_password.txt"}), "", _taint(),
                  untrusted_origin=True)
    assert result.decision == GateDecision.BLOCK


def test_read_sensitive_path_requested_by_user_is_allowed():
    result = gate(ToolCall("read_file", {"path": "/secrets/db_password.txt"}), "", _taint(),
                  untrusted_origin=False)
    assert result.decision == GateDecision.ALLOW


def test_read_normal_file_from_untrusted_content_is_allowed():
    result = gate(ToolCall("read_file", {"path": "/docs/handbook.txt"}), "", _taint(),
                  untrusted_origin=True)
    assert result.decision == GateDecision.ALLOW


def test_formatless_secret_is_caught_via_registry():
    firewall = Firewall()
    firewall.register_secret("S3cr3t-Pa55word!")
    result = firewall.gate("send_email", {"to": "x@external.org"}, "here: S3cr3t-Pa55word!")
    assert result.decision == GateDecision.BLOCK


def test_read_output_of_sensitive_path_becomes_registered_secret():
    firewall = Firewall()
    firewall.record_tool_output("read_file", {"path": "/secrets/token.txt"}, "plain-text-value-123")
    result = firewall.gate("send_email", {"to": "x@external.org"}, "plain-text-value-123")
    assert result.decision == GateDecision.BLOCK


def test_external_send_triggered_by_untrusted_content_needs_review():
    result = gate(ToolCall("send_email", {"to": "x@external.org"}), "hello", _taint(),
                  untrusted_origin=True)
    assert result.decision == GateDecision.REVIEW


def test_internal_domain_is_configurable(monkeypatch):
    monkeypatch.setenv("PIF_INTERNAL_DOMAINS", "corp.example")
    result = gate(ToolCall("send_email", {"to": "a@corp.example"}), "hello", _taint(),
                  untrusted_origin=True)
    assert result.decision == GateDecision.ALLOW
