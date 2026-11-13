"""Fail-closed Genesis-to-GateOne authorization adapter.

Genesis creates an immutable, hashed request. Its route decision is advisory.
This adapter verifies the envelope and its external trust proofs, binds actor,
intent and target to a Gate OperationRequest, then delegates the final decision
to GateOne's AuthorityGate. It never grants authority itself.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from sia.authority import SovereignAuthority
from sia.authority_adapters import CapabilityAdapter
from sia.authority_gate import AuthorizationDecision, OperationRequest

_REQUIRED_ENVELOPE_KEYS = frozenset({
    "envelope_id", "ts", "actor", "intent", "target", "constraints",
    "parent_hash", "approval_id", "signature_b64", "digest",
})
_REQUIRED_CONSTRAINTS = frozenset({
    "approval_id", "actor_id", "policy_epoch", "expires_at", "scope",
})
_ALLOWED_CONSTRAINTS = _REQUIRED_CONSTRAINTS | {"notes"}
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")


class GenesisEnvelopeError(ValueError):
    """Raised when a Genesis envelope fails structural or trust validation."""


@dataclass(frozen=True)
class GenesisGateResult:
    accepted: bool
    envelope_id: str
    envelope_digest: str
    reason: str
    authorization: AuthorizationDecision | None = None


SignatureVerifier = Callable[[str, bytes, str], bool]
PolicyEpochVerifier = Callable[[int], bool]
EvidenceRecorder = Callable[[Mapping[str, Any]], None]
ParentHashVerifier = Callable[[str], bool]
ReplayGuard = Callable[[str, str], bool]
ApprovalVerifier = Callable[[str, str, str, str, str], bool]


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _aware_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise GenesisEnvelopeError(f"{field} must be a non-empty ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GenesisEnvelopeError(f"{field} is not valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GenesisEnvelopeError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def authorize_genesis_envelope(
    authority: SovereignAuthority,
    envelope: Mapping[str, Any],
    request: OperationRequest,
    *,
    signature_verifier: SignatureVerifier,
    policy_epoch_verifier: PolicyEpochVerifier,
    evidence_recorder: EvidenceRecorder,
    parent_hash_verifier: ParentHashVerifier,
    replay_guard: ReplayGuard,
    approval_verifier: ApprovalVerifier,
    now: datetime | None = None,
    max_age_seconds: int = 300,
    max_future_skew_seconds: int = 30,
) -> GenesisGateResult:
    """Validate Genesis provenance and obtain GateOne's independent decision.

    The caller MUST inject real signature, parent-chain, active-policy-epoch,
    Gate approval, replay-reservation, and durable rejection-evidence checks.
    There are deliberately no permissive defaults. A digest or Genesis route
    is not authority; GateOne's independent capability and policy decision is.
    """
    if not callable(signature_verifier):
        raise TypeError("signature_verifier is required")
    if not callable(policy_epoch_verifier):
        raise TypeError("policy_epoch_verifier is required")
    if not callable(evidence_recorder):
        raise TypeError("evidence_recorder is required")
    if not callable(parent_hash_verifier):
        raise TypeError("parent_hash_verifier is required")
    if not callable(replay_guard):
        raise TypeError("replay_guard is required")
    if not callable(approval_verifier):
        raise TypeError("approval_verifier is required")
    if not isinstance(envelope, Mapping):
        raise GenesisEnvelopeError("envelope must be a mapping")
    if not isinstance(request, OperationRequest):
        raise TypeError("request must be a Gate OperationRequest")
    if not isinstance(request.metadata, Mapping):
        raise TypeError("request metadata must be a mapping")
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be a positive integer")
    if isinstance(max_future_skew_seconds, bool) or not isinstance(max_future_skew_seconds, int) or max_future_skew_seconds < 0:
        raise ValueError("max_future_skew_seconds must be a non-negative integer")
    if set(envelope) != _REQUIRED_ENVELOPE_KEYS:
        raise GenesisEnvelopeError("envelope fields do not match the strict Genesis contract")

    envelope_id = envelope.get("envelope_id")
    supplied_digest = envelope.get("digest")
    if not isinstance(envelope_id, str) or not envelope_id.strip():
        raise GenesisEnvelopeError("envelope_id is required")
    if not isinstance(supplied_digest, str) or not _HEX_256.fullmatch(supplied_digest):
        raise GenesisEnvelopeError("digest must be 64 lowercase hexadecimal characters")

    body = {key: envelope[key] for key in _REQUIRED_ENVELOPE_KEYS if key != "digest"}
    calculated_digest = hashlib.sha256(_canonical_bytes(body)).hexdigest()

    def reject(reason: str) -> GenesisGateResult:
        evidence_recorder({
            "event": "genesis.envelope.rejected",
            "envelope_id": envelope_id,
            "envelope_digest": supplied_digest,
            "reason": reason,
            "actor": envelope.get("actor"),
            "target": envelope.get("target"),
            "result": "DENY",
        })
        return GenesisGateResult(False, envelope_id, supplied_digest, reason)

    if not hmac.compare_digest(calculated_digest, supplied_digest):
        return reject("GENESIS_DIGEST_MISMATCH")

    constraints = envelope.get("constraints")
    if not isinstance(constraints, dict):
        return reject("CONSTRAINTS_NOT_OBJECT")
    if set(constraints) - _ALLOWED_CONSTRAINTS:
        return reject("UNKNOWN_CONSTRAINT_KEYS")
    if _REQUIRED_CONSTRAINTS - set(constraints):
        return reject("MISSING_REQUIRED_CONSTRAINTS")

    actor = envelope.get("actor")
    intent = envelope.get("intent")
    target = envelope.get("target")
    approval_id = envelope.get("approval_id")
    if not all(isinstance(v, str) and v.strip() for v in (actor, intent, target, approval_id)):
        return reject("MALFORMED_ACTOR_INTENT_TARGET_OR_APPROVAL")
    if constraints["actor_id"] != actor or constraints["approval_id"] != approval_id:
        return reject("ACTOR_OR_APPROVAL_BINDING_MISMATCH")

    epoch = constraints["policy_epoch"]
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        return reject("INVALID_POLICY_EPOCH")
    scope = constraints["scope"]
    if not isinstance(scope, list) or not scope or not all(
        isinstance(item, str) and item.strip() for item in scope
    ):
        return reject("INVALID_SCOPE")
    if not isinstance(envelope.get("parent_hash"), str) or not _HEX_256.fullmatch(envelope["parent_hash"]):
        return reject("INVALID_PARENT_HASH")
    try:
        parent_ok = parent_hash_verifier(envelope["parent_hash"])
    except Exception:
        return reject("GENESIS_PARENT_VERIFIER_ERROR")
    if parent_ok is not True:
        return reject("GENESIS_PARENT_NOT_FOUND_OR_INVALID")

    current_value = now or datetime.now(timezone.utc)
    if current_value.tzinfo is None or current_value.utcoffset() is None:
        return reject("CURRENT_TIME_MUST_BE_TIMEZONE_AWARE")
    current = current_value.astimezone(timezone.utc)
    try:
        created = _aware_datetime(envelope.get("ts"), "ts")
        expires = _aware_datetime(constraints.get("expires_at"), "constraints.expires_at")
    except GenesisEnvelopeError as exc:
        return reject(str(exc))
    age = (current - created).total_seconds()
    if age < -max_future_skew_seconds:
        return reject("GENESIS_TIMESTAMP_IN_FUTURE")
    if age > max_age_seconds:
        return reject("GENESIS_ENVELOPE_STALE")
    if expires <= current or expires <= created:
        return reject("GENESIS_ENVELOPE_EXPIRED_OR_INVALID")

    signature = envelope.get("signature_b64")
    if not isinstance(signature, str) or not signature.strip():
        return reject("MISSING_SIGNATURE")
    try:
        signature_ok = signature_verifier(actor, bytes.fromhex(calculated_digest), signature)
    except Exception:
        return reject("SIGNATURE_VERIFIER_ERROR")
    if signature_ok is not True:
        return reject("GENESIS_SIGNATURE_INVALID")

    try:
        epoch_ok = policy_epoch_verifier(epoch)
    except Exception:
        return reject("POLICY_EPOCH_VERIFIER_ERROR")
    if epoch_ok is not True:
        return reject("POLICY_EPOCH_STALE_OR_UNRECOGNIZED")

    if request.requester_id != actor:
        return reject("GATE_REQUEST_ACTOR_MISMATCH")
    if request.identity is None or request.identity.identity_id != actor:
        return reject("GATE_IDENTITY_MISMATCH")
    if request.resource_id != target:
        return reject("GATE_TARGET_MISMATCH")
    if request.metadata.get("genesis_intent") != intent:
        return reject("GATE_INTENT_MISMATCH")
    try:
        approval_ok = approval_verifier(
            approval_id, actor, target, intent, calculated_digest
        )
    except Exception:
        return reject("GATE_APPROVAL_VERIFIER_ERROR")
    if approval_ok is not True:
        return reject("GATE_APPROVAL_ID_MISMATCH")

    try:
        gate_capability = CapabilityAdapter().adapt(request.capability)
    except (TypeError, ValueError):
        return reject("GATE_CAPABILITY_INVALID")
    if gate_capability is None or not set(scope).issubset(gate_capability.scopes):
        return reject("GENESIS_SCOPE_EXCEEDS_GATE_CAPABILITY")

    try:
        replay_ok = replay_guard(envelope_id, calculated_digest)
    except Exception:
        return reject("GENESIS_REPLAY_GUARD_ERROR")
    if replay_ok is not True:
        return reject("GENESIS_ENVELOPE_REPLAYED")

    bound_request = replace(
        request,
        metadata={
            **request.metadata,
            "genesis_envelope_id": envelope_id,
            "genesis_envelope_digest": calculated_digest,
            "genesis_target": target,
            "genesis_policy_epoch": epoch,
            "gate_approval_id": approval_id,
        },
    )
    decision = authority.authorize_operation(bound_request)
    return GenesisGateResult(
        accepted=decision.allowed,
        envelope_id=envelope_id,
        envelope_digest=calculated_digest,
        reason=decision.reason,
        authorization=decision,
    )
