"""Proof-emitting wrapper around DefaultAuthorityGate.

Every ALLOW decision is paired with a Gate-signed authorization proof.
Downstream Studio/Genesis consumers must verify that proof; a bare
AuthorizationDecision is not transport authority by itself.
"""
from __future__ import annotations

from typing import Any, Sequence

from .authorization_proof import decision_to_proof, issue_gate_authorization_proof
from .authority_gate import (
    AuthorizationDecision,
    AuthorityGate,
    DefaultAuthorityGate,
    OperationRequest,
)


class ProofEmittingAuthorityGate:
    """Compose DefaultAuthorityGate with signed proof issuance on ALLOW."""

    def __init__(
        self,
        gate: AuthorityGate,
        *,
        proof_secret: bytes | None = None,
        ttl_seconds: int = 300,
    ) -> None:
        if not isinstance(gate, AuthorityGate):
            raise TypeError("gate must implement AuthorityGate")
        self._gate = gate
        self._proof_secret = proof_secret
        self._ttl_seconds = ttl_seconds

    def authorize(self, request: OperationRequest) -> AuthorizationDecision:
        return self._gate.authorize(request)

    def authorize_with_proof(
        self,
        request: OperationRequest,
        *,
        proof_id: str,
        task_id: str,
        scope: Sequence[str],
        owner_id: str | None = None,
    ) -> dict[str, Any]:
        """Return decision fields plus ``gate_proof`` when allowed.

        DENY responses do not carry a usable ALLOW proof.
        """
        decision = self._gate.authorize(request)
        owner = owner_id
        if owner is None and request.identity is not None:
            owner = request.identity.identity_id
        if not owner:
            owner = request.requester_id or "unknown"

        payload: dict[str, Any] = {
            "allowed": decision.allowed,
            "decision": "OWNER_AUTHORIZED" if decision.allowed else "DENY",
            "operation": decision.operation,
            "reason_code": decision.reason_code,
            "reason": decision.reason,
            "capability_id": decision.capability_id,
            "policy_hash": decision.policy_hash,
            "evidence_sequence": decision.evidence_sequence,
            "audit_required": decision.audit_required,
            "gate_proof": None,
        }

        if decision.allowed:
            payload["gate_proof"] = decision_to_proof(
                decision,
                proof_id=proof_id,
                owner_id=owner,
                task_id=task_id,
                scope=scope,
                device_id=(
                    request.identity.device_id if request.identity is not None else None
                ),
                secret=self._proof_secret,
                ttl_seconds=self._ttl_seconds,
            )
        return payload
