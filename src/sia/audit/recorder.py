"""
Audit: recorder.

High-level helper that records well-typed authority events to an
AuditLedger with a consistent payload schema.
"""
from __future__ import annotations

from typing import Any

from sia.audit.ledger import AuditLedger
from sia.audit.provider_events import ProviderSCAREvent


class AuditRecorder:
    """
    Wraps :class:`AuditLedger` with typed event helpers.

    All authority-related actions that must be auditable should flow
    through this recorder so that payloads have a consistent shape.
    """

    def __init__(self, ledger: AuditLedger) -> None:
        self._ledger = ledger

    @property
    def ledger(self) -> AuditLedger:
        return self._ledger

    # ── Authority events ──────────────────────────────────────────────────────

    def record_authority_init(self, actor_id: str, version: str) -> None:
        self._ledger.append(
            "authority.init",
            {"version": version},
            actor_id=actor_id,
        )

    def record_boundary_registered(
        self,
        actor_id: str,
        boundary_id: str,
        boundary_type: str,
        model_id: str,
    ) -> None:
        self._ledger.append(
            "boundary.registered",
            {
                "boundary_id": boundary_id,
                "boundary_type": boundary_type,
                "model_id": model_id,
            },
            actor_id=actor_id,
        )

    def record_delegation_issued(
        self, actor_id: str, token_id: str, grantee_id: str, scope: list[str]
    ) -> None:
        self._ledger.append(
            "delegation.issued",
            {"token_id": token_id, "grantee_id": grantee_id, "scope": scope},
            actor_id=actor_id,
        )

    def record_delegation_revoked(self, actor_id: str, token_id: str) -> None:
        self._ledger.append(
            "delegation.revoked",
            {"token_id": token_id},
            actor_id=actor_id,
        )

    def record_memory_access(
        self,
        actor_id: str,
        record_id: str,
        model_id: str,
        access_type: str,
    ) -> None:
        self._ledger.append(
            "memory.access",
            {
                "record_id": record_id,
                "model_id": model_id,
                "access_type": access_type,
            },
            actor_id=actor_id,
        )

    def record_export(self, actor_id: str, bundle_id: str) -> None:
        self._ledger.append(
            "export.created",
            {"bundle_id": bundle_id},
            actor_id=actor_id,
        )

    def record_import(self, actor_id: str, bundle_id: str) -> None:
        self._ledger.append(
            "import.loaded",
            {"bundle_id": bundle_id},
            actor_id=actor_id,
        )

    def record_conformance_result(
        self,
        actor_id: str,
        rfc: str,
        passed: bool,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._ledger.append(
            "conformance.result",
            {"rfc": rfc, "passed": passed, "details": details or {}},
            actor_id=actor_id,
        )

    def record_provider_scar_event(self, event: ProviderSCAREvent) -> None:
        """Append authority-owned evidence for a provider lifecycle event."""
        self._ledger.append(
            f"provider.{event.event_type.value}",
            event.to_payload(),
            actor_id=event.context.subject_id,
            timestamp=event.context.timestamp,
        )

    def record_mcp_operation(
        self,
        *,
        actor_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        """Append authority-owned evidence for a governed MCP operation."""
        self._ledger.append(
            event_type,
            dict(payload),
            actor_id=actor_id,
        )

    def record_tool_operation(
        self,
        *,
        actor_id: str,
        event_type: str,
        request_id: str | None = None,
        authorization_id: str | None = None,
        identity_id: str | None = None,
        workspace_id: str | None = None,
        binding_id: str | None = None,
        branch: str | None = None,
        task_id: str | None = None,
        capability_id: str | None = None,
        tool_name: str | None = None,
        operation: str | None = None,
        decision: str | None = None,
        execution_status: str | None = None,
        failure_reason: str | None = None,
        timestamp: str | None = None,
    ) -> None:
        """Append canonical sia.audit.recorder tool.operation evidence.

        Emitted at every lifecycle boundary:
        - ``tool.operation.denied``    — authorization denied before execution
        - ``tool.operation.rejected``  — execution rejected (e.g. capability mismatch)
        - ``tool.operation.started``   — authority-issued context handed to executor
        - ``tool.operation.failed``    — subprocess or validator raised an exception
        - ``tool.operation.completed`` — subprocess exited (zero or non-zero)
        """
        payload: dict[str, Any] = {
            "request_id": request_id,
            "authorization_id": authorization_id,
            "identity_id": identity_id,
            "workspace_id": workspace_id,
            "binding_id": binding_id,
            "branch": branch,
            "task_id": task_id,
            "capability_id": capability_id,
            "tool_name": tool_name,
            "operation": operation,
            "decision": decision,
            "execution_status": execution_status,
            "failure_reason": failure_reason,
            "timestamp": timestamp,
        }
        self._ledger.append(
            event_type,
            {k: v for k, v in payload.items() if v is not None},
            actor_id=actor_id,
        )
