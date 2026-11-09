"""Strict adapter for Genesis envelopes entering the Gate contract.

This module translates data only. It does not verify provider signatures, mint
GateAuthorization, or grant authority. The caller must supply a Gate-issued
authorization. Any malformed input raises ContractError; expired input returns
a deny decision.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Mapping, Optional

from .common import ContractError, digest
from .contracts import GateAuthorization, RouteDecision, TaskEnvelope, decide_route

_REQUIRED = frozenset({
    "envelope_id", "ts", "actor", "intent", "target", "constraints", "parent_hash"
})
_ALLOWED_CONSTRAINTS = frozenset({
    "approval_id", "actor_id", "policy_epoch", "expires_at", "scope", "notes"
})
_REQUIRED_CONSTRAINTS = frozenset({
    "approval_id", "actor_id", "policy_epoch", "expires_at", "scope"
})


def _genesis_digest(envelope: Mapping[str, Any]) -> str:
    body = {
        "envelope_id": envelope["envelope_id"],
        "ts": envelope["ts"],
        "actor": envelope["actor"],
        "intent": envelope["intent"],
        "target": envelope["target"],
        "constraints": envelope["constraints"],
        "parent_hash": envelope["parent_hash"],
        "approval_id": envelope.get("approval_id"),
        "signature_b64": envelope.get("signature_b64"),
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def adapt_genesis_envelope(
    envelope: Mapping[str, Any],
    *,
    mode: str,
    gate_authorization: GateAuthorization,
    requested_route: str,
    external_allowlist: frozenset[str] = frozenset(),
    owner_approval_id: Optional[str] = None,
    external_target: Optional[str] = None,
    decision_id: str = "",
    now: Optional[float] = None,
) -> tuple[TaskEnvelope, RouteDecision]:
    """Validate and translate a Genesis envelope, then defer to Gate routing.

    mode is explicit because Genesis' current envelope schema has no mode.
    gate_authorization must be minted by the Gate; Genesis approval fields
    are checked for binding but are never treated as authorization themselves.
    """
    if not isinstance(envelope, Mapping):
        raise ContractError("Genesis envelope must be a mapping")
    missing = _REQUIRED - set(envelope)
    if missing:
        raise ContractError(f"Genesis envelope missing fields: {sorted(missing)}")
    for field in ("envelope_id", "ts", "actor", "intent", "target", "parent_hash"):
        value = envelope[field]
        if not isinstance(value, str) or not value.strip():
            raise ContractError(f"{field} must be a non-empty string")

    parent_hash = envelope["parent_hash"]
    if len(parent_hash) != 64 or any(c not in "0123456789abcdef" for c in parent_hash.lower()):
        raise ContractError("parent_hash must be a 64-character SHA-256 hex digest")

    constraints = envelope["constraints"]
    if not isinstance(constraints, dict):
        raise ContractError("constraints must be a mapping")
    unknown = set(constraints) - _ALLOWED_CONSTRAINTS
    missing_constraints = _REQUIRED_CONSTRAINTS - set(constraints)
    if unknown:
        raise ContractError(f"unknown Genesis constraints: {sorted(unknown)}")
    if missing_constraints:
        raise ContractError(f"missing Genesis constraints: {sorted(missing_constraints)}")

    approval_id = constraints["approval_id"]
    actor_id = constraints["actor_id"]
    epoch = constraints["policy_epoch"]
    expires_at = constraints["expires_at"]
    scope = constraints["scope"]
    if not isinstance(approval_id, str) or not approval_id.strip():
        raise ContractError("approval_id must be non-empty")
    if not isinstance(actor_id, str) or actor_id != envelope["actor"]:
        raise ContractError("actor_id must match Genesis actor")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise ContractError("policy_epoch must be a non-negative integer")
    if not isinstance(scope, list) or not scope or any(not isinstance(x, str) or not x.strip() for x in scope):
        raise ContractError("scope must be a non-empty list of strings")
    if not isinstance(expires_at, str) or not expires_at.strip():
        raise ContractError("expires_at must be a non-empty ISO-8601 timestamp")

    try:
        parsed_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if parsed_expiry.tzinfo is None:
            raise ValueError("timezone required")
        genesis_expiry = parsed_expiry.timestamp()
    except (ValueError, OverflowError) as exc:
        raise ContractError("expires_at must be timezone-aware ISO-8601") from exc

    if not isinstance(gate_authorization, GateAuthorization):
        raise ContractError("a Gate-issued GateAuthorization is required")
    if gate_authorization.task_id != envelope["envelope_id"]:
        raise ContractError("Gate authorization task_id does not match Genesis envelope_id")
    if gate_authorization.auth_id != approval_id:
        raise ContractError("Genesis approval_id does not match Gate authorization")
    if gate_authorization.expires_at > genesis_expiry:
        raise ContractError("Gate authorization must not outlive Genesis approval expiry")

    supplied_digest = envelope.get("digest")
    if supplied_digest is not None:
        if not isinstance(supplied_digest, str) or supplied_digest != _genesis_digest(envelope):
            raise ContractError("Genesis envelope digest mismatch")

    payload_hash = digest(dict(envelope))
    task = TaskEnvelope(
        task_id=envelope["envelope_id"],
        requester=envelope["actor"],
        intent=envelope["intent"],
        scope=tuple(scope),
        mode=mode,
        created_at=envelope["ts"],
        payload_hash=payload_hash,
    )

    current = datetime.now().timestamp() if now is None else now
    if current >= genesis_expiry:
        decision = RouteDecision(
            decision_id or f"rd-{task.task_id}",
            task.task_id,
            "deny",
            task.mode,
            "Genesis approval expired",
        )
    else:
        decision = decide_route(
            task,
            gate_authorization,
            requested_route,
            external_allowlist,
            owner_approval_id,
            external_target,
            decision_id,
            current,
        )
    return task, decision
