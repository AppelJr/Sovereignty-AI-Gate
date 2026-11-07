"""Gate authorization proof issuer (schema-compatible with Studio verifier).

Studio consumers verify with the same claim schema:
sovereignty.gate.authorization_proof.v1

HMAC is for offline testability. Production may swap the signer for ML-DSA-65
without changing claims.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Mapping, Sequence

PROOF_SCHEMA = "sovereignty.gate.authorization_proof.v1"
DOMAIN = b"sovereignty-gate-authorization-proof/v1\0"


class AuthorizationProofError(ValueError):
    pass


def _canonical(claims: Mapping[str, Any]) -> bytes:
    return json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def issue_gate_authorization_proof(
    *,
    proof_id: str,
    owner_id: str,
    task_id: str,
    scope: Sequence[str],
    decision: str,
    policy_hash: str,
    policy_version: str = "1",
    reason_code: str = "AUTHORIZED",
    device_id: str | None = None,
    evidence_sequence: int | None = None,
    issued_at: int | None = None,
    expires_at: int | None = None,
    ttl_seconds: int = 300,
    secret: bytes | None = None,
) -> str:
    if not proof_id or not owner_id or not task_id or not policy_hash:
        raise AuthorizationProofError("required claims missing")
    decision_u = str(decision).upper()
    now = int(time.time()) if issued_at is None else int(issued_at)
    exp = int(expires_at) if expires_at is not None else now + int(ttl_seconds)
    if exp <= now:
        raise AuthorizationProofError("expires_at must be after issued_at")

    claims = {
        "schema": PROOF_SCHEMA,
        "proof_id": str(proof_id),
        "owner_id": str(owner_id),
        "device_id": str(device_id) if device_id else None,
        "task_id": str(task_id),
        "scope": [str(s) for s in scope],
        "decision": decision_u,
        "policy_hash": str(policy_hash),
        "policy_version": str(policy_version),
        "reason_code": str(reason_code),
        "evidence_sequence": evidence_sequence,
        "issued_at": now,
        "expires_at": exp,
    }
    payload = _canonical(claims)
    if secret is None:
        raw = os.environ.get("SOVEREIGN_GATE_PROOF_KEY")
        if not raw:
            raise AuthorizationProofError("SOVEREIGN_GATE_PROOF_KEY unavailable")
        secret = raw.encode("utf-8")
    sig = hmac.new(secret, DOMAIN + payload, hashlib.sha256).digest()
    return f"{_b64url(payload)}.{_b64url(sig)}"


def decision_to_proof(
    decision: Mapping[str, Any] | object,
    *,
    proof_id: str,
    owner_id: str,
    task_id: str,
    scope: Sequence[str],
    device_id: str | None = None,
    secret: bytes | None = None,
    ttl_seconds: int = 300,
) -> str:
    """Map Gate AuthorizationDecision-like objects into a signed proof string."""
    def _get(name: str, default: Any = None) -> Any:
        if isinstance(decision, Mapping):
            return decision.get(name, default)
        return getattr(decision, name, default)

    allowed = bool(_get("allowed", False))
    decision_code = "OWNER_AUTHORIZED" if allowed else "DENY"
    if _get("reason_code") == "AUTHORIZED" and allowed:
        decision_code = "OWNER_AUTHORIZED"
    return issue_gate_authorization_proof(
        proof_id=proof_id,
        owner_id=owner_id,
        task_id=task_id,
        scope=scope,
        decision=decision_code,
        policy_hash=str(_get("policy_hash", "") or ""),
        reason_code=str(_get("reason_code", "AUTHORIZED")),
        device_id=device_id,
        evidence_sequence=_get("evidence_sequence"),
        ttl_seconds=ttl_seconds,
        secret=secret,
    )
