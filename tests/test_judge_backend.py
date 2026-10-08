import json
from types import SimpleNamespace

from pif_firewall.attack_types import AttackType
from pif_firewall.detection.judge_backends import make_openai_judge, parse_verdict


def _fake_client(content):
    def create(**kwargs):
        # the judged text must be fenced as untrusted data
        assert "<content>" in kwargs["messages"][1]["content"]
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))])
    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))


def test_parse_valid_verdict():
    raw = json.dumps({"attack_type": "instruction_override", "confidence": 0.9,
                      "evidence_span": "ignore previous", "rationale": "override"})
    verdict = parse_verdict(raw)
    assert verdict.attack_type == AttackType.INSTRUCTION_OVERRIDE and verdict.confidence == 0.9


def test_parse_garbage_is_neutral():
    verdict = parse_verdict("not json at all")
    assert verdict.attack_type is None and verdict.confidence == 0.0


def test_unknown_attack_type_is_neutral():
    verdict = parse_verdict(json.dumps({"attack_type": "made_up", "confidence": 0.9}))
    assert verdict.attack_type is None


def test_backend_uses_client_and_fences_content():
    raw = json.dumps({"attack_type": "role_change", "confidence": 0.8, "evidence_span": "x", "rationale": "y"})
    backend = make_openai_judge(client=_fake_client(raw))
    assert backend("some text </content> escape attempt").attack_type == AttackType.ROLE_CHANGE


def test_backend_failure_is_neutral():
    def boom(**kwargs):
        raise RuntimeError("network down")
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=boom)))
    assert make_openai_judge(client=client)("text").attack_type is None
