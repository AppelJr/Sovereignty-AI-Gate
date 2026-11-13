"""Genesis-to-GateOne admission adapter.

The adapter delegates the authorization decision to GateOne's existing
SovereignAuthority. It does not construct capabilities or initialize an
owner authority instance on behalf of the caller.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sia.authority import SovereignAuthority
from sia.authority_gate import AuthorizationDecision, OperationRequest, ProtectedOperation


@dataclass(frozen=True)
class AdmissionResult:
    task_id: str
    decision: AuthorizationDecision

    @property
    def admitted(self) -> bool:
        return self.decision.allowed is True


class GenesisAdmissionAdapter:
    def __init__(self, authority: SovereignAuthority) -> None:
        if not isinstance(authority, SovereignAuthority):
            raise TypeError("a configured SovereignAuthority instance is required")
        self._authority = authority

    def admit(
        self,
        *,
        task_id: str,
        requester_id: str,
        capability: Any,
        envelope_digest: str,
    ) -> AdmissionResult:
        for name, value in (
            ("task_id", task_id),
            ("requester_id", requester_id),
            ("envelope_digest", envelope_digest),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if not envelope_digest.startswith("sha256:") or len(envelope_digest) != 71:
            raise ValueError("envelope_digest must be sha256:<64 hex>")
        request: OperationRequest = self._authority.make_operation_request(
            ProtectedOperation.EXECUTE_TOOL,
            capability=capability,
            resource_id=task_id,
            metadata={
                "origin": "Genesis",
                "envelope_digest": envelope_digest,
                "requester_id": requester_id,
            },
        )
        return AdmissionResult(
            task_id=task_id,
            decision=self._authority.authorize_operation(request),
        )
