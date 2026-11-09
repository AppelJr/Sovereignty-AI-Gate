from devassist_contracts.contracts import GateAuthorization
from devassist_contracts.genesis_bridge import adapt_genesis_envelope, decide_genesis_handoff
import hashlib
import json


def genesis_dict():
    body = {
        "envelope_id": "task-01",
        "ts": "2026-11-09T12:00:00Z",
        "actor": "human:test",
        "intent": "run tests",
        "target": "workspace",
        "constraints": {"scope": ["read"]},
        "parent_hash": "0" * 64,
        "approval_id": None,
        "signature_b64": None,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {
        "envelope_id": body["envelope_id"],
        "ts": body["ts"],
        "actor": body["actor"],
        "intent": body["intent"],
        "target": body["target"],
        "constraints": body["constraints"],
        "parent_hash": body["parent_hash"],
        "approval_id": None,
        "signature_b64": None,
        "digest": hashlib.sha256(canonical).hexdigest(),
    }


def test_genesis_envelope_maps_without_granting_authority():
    mapped = adapt_genesis_envelope(genesis_dict())
    assert mapped.task_id == "task-01"
    assert mapped.scope == ("read",)


def test_digest_tampering_rejected():
    data = genesis_dict()
    data["intent"] = "delete"
    try:
        adapt_genesis_envelope(data)
    except ValueError as error:
        assert "digest mismatch" in str(error)
    else:
        raise AssertionError("tampered envelope accepted")


def test_missing_gate_authorization_denies_execution():
    mapped = adapt_genesis_envelope(genesis_dict())
    decision = decide_genesis_handoff(mapped, gate_authorization=None)
    assert decision.route == "deny"


def test_wrong_task_gate_authorization_denies_execution():
    mapped = adapt_genesis_envelope(genesis_dict())
    token = GateAuthorization("auth-1", "different-task", True, 9999999999, "gate")
    decision = decide_genesis_handoff(mapped, gate_authorization=token)
    assert decision.route == "deny"


def test_task_bound_gate_authorization_allows_local_route():
    mapped = adapt_genesis_envelope(genesis_dict())
    token = GateAuthorization("auth-1", mapped.task_id, True, 9999999999, "gate")
    decision = decide_genesis_handoff(mapped, gate_authorization=token)
    assert decision.route == "runtime_local"
