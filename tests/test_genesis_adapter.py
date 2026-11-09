import hashlib
import json

import pytest

from devassist_contracts import ContractError, GateAuthorization
from devassist_contracts.genesis_adapter import adapt_genesis_envelope


def make_envelope(**overrides):
    value = {
        "envelope_id": "gen-1",
        "ts": "2026-11-06T12:00:00Z",
        "actor": "human:owner",
        "intent": "run tests",
        "target": "feature-branch",
        "constraints": {
            "approval_id": "gate-auth-1",
            "actor_id": "human:owner",
            "policy_epoch": 3,
            "expires_at": "2026-11-06T13:00:00Z",
            "scope": ["workspace/project"],
        },
        "parent_hash": "a" * 64,
        "approval_id": "gate-auth-1",
        "signature_b64": None,
    }
    value.update(overrides)
    body = {k: value.get(k) for k in (
        "envelope_id", "ts", "actor", "intent", "target", "constraints",
        "parent_hash", "approval_id", "signature_b64"
    )}
    value["digest"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    return value


def make_auth(**overrides):
    values = dict(
        auth_id="gate-auth-1",
        task_id="gen-1",
        allowed=True,
        expires_at=1793970000.0,
        issued_by="sovereignty-ai-gate",
    )
    values.update(overrides)
    return GateAuthorization(**values)


def test_genesis_envelope_maps_only_with_gate_authorization():
    task, decision = adapt_genesis_envelope(
        make_envelope(), mode="GHOST", gate_authorization=make_auth(),
        requested_route="devassist_local", now=1793966400.0,
    )
    assert task.task_id == "gen-1"
    assert task.requester == "human:owner"
    assert task.scope == ("workspace/project",)
    assert decision.route == "devassist_local"
    assert decision.gate_auth_id == "gate-auth-1"


def test_genesis_digest_mismatch_rejected():
    value = make_envelope()
    value["intent"] = "delete everything"
    with pytest.raises(ContractError, match="digest mismatch"):
        adapt_genesis_envelope(value, mode="GHOST", gate_authorization=make_auth(),
                               requested_route="devassist_local", now=1793966400.0)


def test_genesis_actor_mismatch_rejected():
    value = make_envelope()
    value["constraints"]["actor_id"] = "human:other"
    value.pop("digest")
    with pytest.raises(ContractError, match="actor_id"):
        adapt_genesis_envelope(value, mode="GHOST", gate_authorization=make_auth(),
                               requested_route="devassist_local", now=1793966400.0)


def test_genesis_approval_cannot_replace_gate_authorization():
    with pytest.raises(ContractError, match="approval_id"):
        adapt_genesis_envelope(make_envelope(), mode="GHOST",
                               gate_authorization=make_auth(auth_id="other"),
                               requested_route="devassist_local", now=1793966400.0)


def test_expired_genesis_approval_denies():
    value = make_envelope()
    value["constraints"]["expires_at"] = "2026-11-06T11:00:00Z"
    value.pop("digest")
    auth = make_auth(expires_at=1793960000.0)
    _, decision = adapt_genesis_envelope(
        value, mode="GHOST", gate_authorization=auth,
        requested_route="devassist_local", now=1793966400.0,
    )
    assert decision.route == "deny"


def test_ghost_mode_cannot_use_external_route():
    _, decision = adapt_genesis_envelope(
        make_envelope(), mode="GHOST", gate_authorization=make_auth(),
        requested_route="runtime_external",
        external_allowlist=frozenset({"api.example"}),
        external_target="api.example", now=1793966400.0,
    )
    assert decision.route == "deny"


def test_bool_policy_epoch_rejected():
    value = make_envelope()
    value["constraints"]["policy_epoch"] = True
    value.pop("digest")
    with pytest.raises(ContractError, match="policy_epoch"):
        adapt_genesis_envelope(value, mode="GHOST", gate_authorization=make_auth(),
                               requested_route="devassist_local", now=1793966400.0)
