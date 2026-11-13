"""
Sovereign Authority — top-level orchestrator.

``SovereignAuthority`` ties together all SIA subsystems: boundary
registry, policy engine, delegation authorizer, memory, audit ledger,
import/export, and conformance harness.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Sequence
from uuid import uuid4

from sia.audit.ledger import AuditLedger
from sia.audit.provider_events import ProviderEventType, create_provider_scar_event
from sia.audit.recorder import AuditRecorder
from sia.authority_adapters import (
    CapabilityAdapter,
    DefaultMemoryFirewall,
    EvidenceLedgerAdapter,
    IdentityAdapter,
    PolicyAdapter,
    VaultAdapter,
)
from sia.authority_gate import (
    AIProvider,
    AuthorizationDecision,
    DefaultAuthorityGate,
    IdentityContext,
    OperationRequest,
)
from sia.context.request_context import RequestContext
from sia.conformance.harness import ConformanceHarness
from sia.delegation.authorizer import DelegationAuthorizer
from sia.delegation.models import DelegationToken
from sia.errors.exceptions import NotInitializedError
from sia.export.models import ExportBundle
from sia.export.validator import validate_bundle
from sia.imports.loader import BundleLoader
from sia.imports.models import ImportBundle
from sia.memory.models import MemoryRecord
from sia.memory.validator import assert_read_access, validate_record
from sia.providers.router import ProviderRouter
from sia.security.authority_policy import AuthorityPolicy
from sia.security.boundary_registry import BoundaryRegistry, BoundaryType
from sia.tools.models import _issue_tool_execution_context

__version__ = "0.1.0"


class SovereignAuthority:
    """
    Top-level Sovereignty AI Gate authority instance.

    This class is the single entry point for all authority operations.
    All actions are recorded to the audit ledger.

    Usage::

        sa = SovereignAuthority(owner_id="user:alice")
        sa.initialize()
        sa.register_boundary("b001", "model:gpt4", "creator", scope=["memory.read"])
    """

    def __init__(
        self,
        owner_id: str,
        policy: dict[str, Any] | None = None,
    ) -> None:
        self._owner_id = owner_id
        self._initialized = False
        self._registry = BoundaryRegistry()
        self._policy = AuthorityPolicy(
            policy or {"default": "deny", "rules": []}
        )
        self._delegations = DelegationAuthorizer()
        self._memory: dict[str, MemoryRecord] = {}
        self._ledger = AuditLedger()
        self._recorder = AuditRecorder(self._ledger)
        self._loader = BundleLoader()
        self._conformance = ConformanceHarness()
        self._identity = IdentityAdapter.create(owner_id)
        self._authority_evidence = EvidenceLedgerAdapter(
            identity_id=owner_id,
            root_of_trust=self._identity.root_of_trust,
        )
        self._vault = VaultAdapter(
            owner_identity=owner_id,
            root_of_trust=self._identity.root_of_trust,
        )
        self._memory_firewall = DefaultMemoryFirewall()
        self._authority_gate = DefaultAuthorityGate(
            identity_verifier=self._identity,
            capability_verifier=CapabilityAdapter(),
            policy=PolicyAdapter(self._policy),
            evidence=self._authority_evidence,
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def initialize(self) -> None:
        """Mark the authority as initialized and write the init audit record."""
        self._initialized = True
        self._recorder.record_authority_init(
            actor_id=self._owner_id, version=__version__
        )

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise NotInitializedError()

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def owner_id(self) -> str:
        return self._owner_id

    @property
    def registry(self) -> BoundaryRegistry:
        return self._registry

    @property
    def ledger(self) -> AuditLedger:
        return self._ledger

    @property
    def conformance(self) -> ConformanceHarness:
        return self._conformance

    @property
    def authority_evidence(self) -> EvidenceLedgerAdapter:
        return self._authority_evidence

    @property
    def authority_gate(self) -> DefaultAuthorityGate:
        return self._authority_gate

    @property
    def vault(self) -> VaultAdapter:
        return self._vault

    def identity_context(self) -> IdentityContext:
        return self._identity.identity_context()

    def make_operation_request(
        self,
        operation: str,
        *,
        capability: object | None = None,
        parent_capability: object | None = None,
        resource_id: str = "",
        model_id: str = "",
        provider_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> OperationRequest:
        return OperationRequest(
            operation=operation,
            identity=self.identity_context(),
            capability=capability,
            parent_capability=parent_capability,
            requester_id=self._owner_id,
            resource_id=resource_id,
            model_id=model_id,
            provider_id=provider_id,
            metadata=dict(metadata or {}),
        )

    # ── Boundary management ───────────────────────────────────────────────────

    def register_boundary(
        self,
        boundary_id: str,
        model_id: str,
        boundary_type: BoundaryType,
        scope: list[str],
    ) -> None:
        """Register a model boundary and record the event."""
        self._require_initialized()
        self._registry.register(
            boundary_id=boundary_id,
            model_id=model_id,
            boundary_type=boundary_type,
            creator_id=self._owner_id,
            scope=scope,
        )
        self._recorder.record_boundary_registered(
            actor_id=self._owner_id,
            boundary_id=boundary_id,
            boundary_type=boundary_type,
            model_id=model_id,
        )

    # ── Delegation ────────────────────────────────────────────────────────────

    def issue_delegation(
        self,
        token: DelegationToken,
        parent_scope: list[str] | None = None,
    ) -> DelegationToken:
        """Issue a delegation token and record the event."""
        self._require_initialized()
        issued = self._delegations.issue(token, parent_scope=parent_scope)
        self._recorder.record_delegation_issued(
            actor_id=self._owner_id,
            token_id=issued.token_id,
            grantee_id=issued.grantee_id,
            scope=issued.scope,
        )
        return issued

    def revoke_delegation(self, token_id: str) -> None:
        """Revoke a delegation token and record the event."""
        self._require_initialized()
        self._delegations.revoke(token_id)
        self._recorder.record_delegation_revoked(
            actor_id=self._owner_id, token_id=token_id
        )

    # ── Memory ────────────────────────────────────────────────────────────────

    def store_memory(self, record: MemoryRecord) -> None:
        """Validate and store a memory record."""
        self._require_initialized()
        validate_record(record)
        self._memory[record.record_id] = record
        self._recorder.record_memory_access(
            actor_id=self._owner_id,
            record_id=record.record_id,
            model_id=record.model_id,
            access_type="write",
        )

    def store_memory_authorized(
        self,
        request: OperationRequest,
        record: MemoryRecord,
    ) -> AuthorizationDecision:
        self._require_initialized()
        decision = self.authorize_operation(request)
        if decision.allowed:
            self.store_memory(record)
            self._vault.record_memory(record, capability_id=decision.capability_id)
        return decision

    def read_memory(
        self, record_id: str, requesting_model_id: str
    ) -> MemoryRecord:
        """Read a memory record, enforcing consent rules."""
        self._require_initialized()
        record = self._memory[record_id]
        assert_read_access(record, requesting_model_id)
        self._recorder.record_memory_access(
            actor_id=requesting_model_id,
            record_id=record_id,
            model_id=record.model_id,
            access_type="read",
        )
        return record

    def read_memory_authorized(
        self,
        request: OperationRequest,
        record_id: str,
        requesting_model_id: str,
    ) -> tuple[AuthorizationDecision, MemoryRecord | None]:
        self._require_initialized()
        decision = self.authorize_operation(request)
        if not decision.allowed:
            return decision, None
        return decision, self.read_memory(record_id, requesting_model_id)

    # ── Export / Import ───────────────────────────────────────────────────────

    def create_export(
        self,
        bundle_id: str,
        payload: dict[str, Any],
        payload_hash: str,
        signature: str,
    ) -> ExportBundle:
        """Build, validate, and record an export bundle."""
        self._require_initialized()
        bundle = ExportBundle(
            bundle_id=bundle_id,
            created_by=self._owner_id,
            payload=payload,
            payload_hash=payload_hash,
            signature=signature,
        )
        validate_bundle(bundle)
        self._recorder.record_export(
            actor_id=self._owner_id, bundle_id=bundle_id
        )
        return bundle

    def create_export_authorized(
        self,
        request: OperationRequest,
        bundle_id: str,
        payload: dict[str, Any],
        payload_hash: str,
        signature: str,
    ) -> tuple[AuthorizationDecision, ExportBundle | None]:
        self._require_initialized()
        decision = self.authorize_operation(request)
        if not decision.allowed:
            return decision, None
        return decision, self.create_export(bundle_id, payload, payload_hash, signature)

    def load_import(self, bundle: ImportBundle) -> None:
        """Validate and load an import bundle."""
        self._require_initialized()
        self._loader.load(bundle)
        self._recorder.record_import(
            actor_id=self._owner_id, bundle_id=bundle.bundle_id
        )

    def load_import_authorized(
        self,
        request: OperationRequest,
        bundle: ImportBundle,
    ) -> AuthorizationDecision:
        self._require_initialized()
        decision = self.authorize_operation(request)
        if decision.allowed:
            self.load_import(bundle)
        return decision

    # ── Policy ────────────────────────────────────────────────────────────────

    def enforce_policy(self, request: dict[str, Any]) -> None:
        """Enforce the authority policy for *request*."""
        self._require_initialized()
        self._policy.enforce(request)

    def authorize_operation(self, request: OperationRequest) -> AuthorizationDecision:
        self._require_initialized()
        return self._authority_gate.authorize(request)

    def execute_tool_authorized(
        self,
        request: OperationRequest,
        *,
        executor: Any,
        tool_name: str,
        args: Sequence[str],
        capability: Any,
        input_hash: str = "",
        requester: str = "",
        runtime_version: str = "",
    ) -> tuple[AuthorizationDecision, Any | None]:
        """Authorize, issue a governed execution context, execute, and evidence.

        Flow:
          1. Authorize the operation via the AuthorityGate.
          2. On denial → emit ``tool.operation.denied`` evidence and return.
          3. Validate capability_id consistency between the decision and the
             request.  Mismatch → ``tool.operation.rejected`` + CAPABILITY_CONTEXT_MISMATCH.
          4. Issue a ``ToolExecutionContext`` via the authority-only factory.
          5. Emit ``tool.operation.started`` evidence.
          6. Call ``executor.execute_authorized(ctx)``.
          7. On exception → emit ``tool.operation.failed`` evidence and re-raise.
          8. Emit ``tool.operation.completed`` evidence.
          9. Return ``(decision, result)``.
        """
        self._require_initialized()
        request_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        identity_id = (
            request.identity.identity_id if request.identity is not None else None
        )

        decision = self.authorize_operation(request)

        if not decision.allowed:
            self._recorder.record_tool_operation(
                actor_id=self._owner_id,
                event_type="tool.operation.denied",
                request_id=request_id,
                authorization_id=str(decision.evidence_sequence)
                if decision.evidence_sequence is not None
                else None,
                identity_id=identity_id,
                capability_id=decision.capability_id,
                tool_name=tool_name,
                operation=request.operation_name,
                decision="denied",
                execution_status="denied",
                failure_reason=decision.reason,
                timestamp=timestamp,
            )
            return decision, None

        # ── Capability_id consistency ─────────────────────────────────────────
        request_capability_id = getattr(request.capability, "capability_id", None) or getattr(
            request.capability, "token_id", None
        )
        if (
            request_capability_id is not None
            and decision.capability_id is not None
            and request_capability_id != decision.capability_id
        ):
            self._recorder.record_tool_operation(
                actor_id=self._owner_id,
                event_type="tool.operation.rejected",
                request_id=request_id,
                authorization_id=str(decision.evidence_sequence)
                if decision.evidence_sequence is not None
                else None,
                identity_id=identity_id,
                capability_id=decision.capability_id,
                tool_name=tool_name,
                operation=request.operation_name,
                decision="rejected",
                execution_status="rejected",
                failure_reason="CAPABILITY_CONTEXT_MISMATCH",
                timestamp=timestamp,
            )
            from sia.authority_gate import AuthorizationDecision as _AD

            mismatch_decision = _AD(
                allowed=False,
                operation=decision.operation,
                reason_code="CAPABILITY_CONTEXT_MISMATCH",
                reason=(
                    f"capability_id in request ({request_capability_id!r}) does not match "
                    f"the decision ({decision.capability_id!r})"
                ),
                capability_id=decision.capability_id,
                policy_hash=decision.policy_hash,
                audit_required=True,
                evidence_sequence=decision.evidence_sequence,
            )
            return mismatch_decision, None

        # ── Issue authority-bound execution context ───────────────────────────
        authorization_id = (
            str(decision.evidence_sequence)
            if decision.evidence_sequence is not None
            else None
        )
        ctx = _issue_tool_execution_context(
            request_id=request_id,
            authorization_id=authorization_id,
            identity_id=identity_id or "",
            capability_id=decision.capability_id,
            tool_name=tool_name,
            operation=request.operation_name,
            tool_capability=capability,
            args=tuple(args),
            input_hash=input_hash,
            requester=requester,
            runtime_version=runtime_version,
            issued_at=timestamp,
            workspace_id=None,  # S-002 reserved
            binding_id=None,    # S-002 reserved
            branch=None,        # S-002 reserved
            task_id=None,       # S-002 reserved
        )

        self._recorder.record_tool_operation(
            actor_id=self._owner_id,
            event_type="tool.operation.started",
            request_id=request_id,
            authorization_id=authorization_id,
            identity_id=identity_id,
            capability_id=decision.capability_id,
            tool_name=tool_name,
            operation=request.operation_name,
            decision="authorized",
            execution_status="started",
            timestamp=timestamp,
        )

        try:
            result = executor.execute_authorized(ctx)
        except Exception as exc:
            failure_reason = str(exc) or type(exc).__name__
            self._recorder.record_tool_operation(
                actor_id=self._owner_id,
                event_type="tool.operation.failed",
                request_id=request_id,
                authorization_id=authorization_id,
                identity_id=identity_id,
                capability_id=decision.capability_id,
                tool_name=tool_name,
                operation=request.operation_name,
                decision="authorized",
                execution_status="failed",
                failure_reason=failure_reason,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            raise

        self._recorder.record_tool_operation(
            actor_id=self._owner_id,
            event_type="tool.operation.completed",
            request_id=request_id,
            authorization_id=authorization_id,
            identity_id=identity_id,
            capability_id=decision.capability_id,
            tool_name=tool_name,
            operation=request.operation_name,
            decision="authorized",
            execution_status="completed",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        return decision, result

    def call_provider_authorized(
        self,
        request: OperationRequest,
        *,
        provider: AIProvider,
        record_ids: Sequence[str] = (),
    ) -> tuple[AuthorizationDecision, dict[str, Any] | None]:
        """Authorize, route, execute, and evidence a provider invocation."""
        self._require_initialized()
        if request.provider_id != provider.provider_id:
            raise ValueError(
                f"Request provider_id {request.provider_id!r} does not match "
                f"the provider being executed ({provider.provider_id!r}). "
                "Build the OperationRequest with the same provider_id."
            )

        context = RequestContext.create(
            request_id=str(uuid4()),
            correlation_id=str(uuid4()),
            session_id=self._owner_id,
            operation=request.operation_name,
            subject_id=self._owner_id,
            capability_id=getattr(request.capability, "capability_id", None)
            or getattr(request.capability, "token_id", None),
            policy_hash="",
        )
        decision = self.authorize_operation(request)
        if not decision.allowed:
            self._record_provider_event(
                ProviderEventType.FAILED,
                context,
                provider_id=request.provider_id,
                error_code=decision.reason_code,
                error_category="authorization",
                retryable=False,
            )
            return decision, None

        context = RequestContext(
            request_id=context.request_id,
            correlation_id=context.correlation_id,
            session_id=context.session_id,
            operation=context.operation,
            subject_id=context.subject_id,
            capability_id=decision.capability_id,
            policy_hash=decision.policy_hash,
            timestamp=context.timestamp,
            authority_sequence=context.authority_sequence,
        )
        context = self._advance_context(context, sequence=2)
        packet = self._memory_firewall.build_context_packet(
            request,
            decision,
            provider_id=provider.provider_id,
            memory_records=[
                self.read_memory(record_id, provider.provider_id)
                for record_id in record_ids
            ],
        )
        self._record_provider_event(
            ProviderEventType.REQUESTED, context, provider_id=provider.provider_id
        )

        context = self._advance_context(context, sequence=3)
        selected_provider = ProviderRouter(
            {provider.provider_id: provider}
        ).select(request, context)
        self._record_provider_event(
            ProviderEventType.APPROVED, context, provider_id=selected_provider.provider_id
        )

        context = self._advance_context(context, sequence=4)
        try:
            result = selected_provider.execute(packet)
        except Exception as exc:
            self._record_provider_event(
                ProviderEventType.FAILED,
                context,
                provider_id=selected_provider.provider_id,
                error_code=getattr(exc, "code", "UNKNOWN"),
                error_category="execution",
                retryable=getattr(exc, "retryable", False),
            )
            raise
        self._record_provider_event(
            ProviderEventType.COMPLETED, context, provider_id=selected_provider.provider_id
        )
        return decision, result

    @staticmethod
    def _advance_context(ctx: RequestContext, *, sequence: int) -> RequestContext:
        """Return the next immutable authority context."""
        return ctx.advance(sequence)

    def _record_provider_event(
        self,
        event_type: ProviderEventType,
        ctx: RequestContext,
        *,
        provider_id: str | None,
        error_code: str | None = None,
        error_category: str | None = None,
        retryable: bool | None = None,
    ) -> None:
        """Record provider lifecycle evidence from the authority layer only."""
        self._recorder.record_provider_scar_event(
            create_provider_scar_event(
                event_type=event_type,
                ctx=ctx,
                provider_id=provider_id or "unknown",
                error_code=error_code,
                error_category=error_category,
                retryable=retryable,
            )
        )

    # ── Audit ─────────────────────────────────────────────────────────────────

    def verify_ledger(self) -> None:
        """Verify ledger chain integrity. Raises on tamper detection."""
        self._ledger.verify_chain()

    def verify_authority_evidence(self) -> bool:
        return (
            self._authority_evidence.verify_chain()
            and self._vault.verify_chain()
        )
