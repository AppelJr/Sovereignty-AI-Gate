"""Strict bridge from Genesis envelopes into Sovereignty-AI-Gate contracts.

The bridge maps provenance and intent. It cannot mint GateAuthorization.
Callers must supply a Gate-issued authorization to obtain an executing route.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .contracts import GateAuthorization, RouteDecision, TaskEnvelope, decide_route


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def adapt_genesis_envelope(
    source: Mapping[str, Any],
    *,
    mode: str = "GHOST",
) -> TaskEnvelope:
    required = {
        "envelope_id", "ts", "actor", "intent", "target",
        "constraints", "parent_hash", "digest",
    }
    if not isinstance(source, Mapping) or required - set(source):
        raise ValueError("incomplete Genesis envelope")
    constraints = source["constraints"]
    if not isinstance(constraints, dict):
        raise ValueError("Genesis constraints must be an object")
    scope = constraints.get("scope")
    if not isinstance(scope, list) or not scope or not all(isinstance(x, str) and x for x in scope):
        raise ValueError("Genesis scope must be a non-empty string list")

    body = {key: source[key] for key in (
        "envelope_id", "ts", "actor", "intent", "target", "constraints", "parent_hash"
    )}
    body["approval_id"] = source.get("approval_id")
    body["signature_b64"] = source.get("signature_b64")
    expected = hashlib.sha256(_canonical(body)).hexdigest()
    if not isinstance(source["digest"], str) or source["digest"] != expected:
        raise ValueError("Genesis envelope digest mismatch")

    return TaskEnvelope(
        task_id=source["envelope_id"],
        requester=source["actor"],
        intent=source["intent"],
        scope=tuple(scope),
        mode=mode,
        created_at=source["ts"],
        payload_hash="sha256:" + expected,
    )


def decide_genesis_handoff(
    envelope: TaskEnvelope,
    *,
    gate_authorization: GateAuthorization | None,
    requested_route: str = "runtime_local",
) -> RouteDecision:
    """Executing routes require a separately issued, task-bound Gate token."""
    return decide_route(
        envelope=envelope,
        auth=gate_authorization,
        requested_route=requested_route,
    )
