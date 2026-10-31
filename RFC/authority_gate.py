from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Sequence


class ProtectedOperation(StrEnum):
    READ_MEMORY = "READ_MEMORY"
    WRITE_MEMORY = "WRITE_MEMORY"
    EXPORT_ARCHIVE = "EXPORT_ARCHIVE"
    IMPORT_ARCHIVE = "IMPORT_ARCHIVE"
    EXECUTE_TOOL = "EXECUTE_TOOL"
    RELEASE_CONTEXT = "RELEASE_CONTEXT"
    CALL_PROVIDER = "CALL_PROVIDER"
    WORKSPACE_LIST = "WORKSPACE_LIST"
    WORKSPACE_READ = "WORKSPACE_READ"
    WORKSPACE_ANALYZE = "WORKSPACE_ANALYZE"
    WORKSPACE_REPO_STATUS = "WORKSPACE_REPO_STATUS"


@dataclass(frozen=True)
class IdentityContext:
    identity_id: str
    device_id: str | None = None
    verified: bool = False
    hardware_backed: bool = False
    """
    True only when the backing trust material resides in secure hardware
    (TPM 2.0, Apple Secure Enclave, Android StrongBox, or equivalent).
    Production authority gates MUST reject requests where this is False
    when operating in a production context.
    """
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CapabilityRecord:
    capability_id: str
    owner_identity: str
    scopes: frozenset[str]
    provider_id: str | None = None
    issuer_device: str | None = None
    expires_at: str | int | None = None
    revoked: bool = False
    parent_capability_id: str | None = None


@dataclass(frozen=True)
class OperationRequest:
    operation: ProtectedOperation | str
    identity: IdentityContext | None
    capability: Any | None = None
    parent_capability: Any | None = None
    requester_id: str = ""
    resource_id: str = ""
    model_id: str = ""
    provider_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def operation_name(self) -> str:
        try:
            return ProtectedOperation(self.operation).value
        except ValueError:
            return str(self.operation)


@dataclass(frozen=True)
class PolicyEvaluation:
    allowed: bool
    reason: str
    matched_rule: str | None = None


@dataclass(frozen=True)
class CapabilityVerification:
    allowed: bool
    reason_code: str
    reason: str
    capability_id: str | None = None
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    operation: str
    reason_code: str
    reason: str
    capability_id: str | None
    policy_hash: str
    audit_required: bool = True
    evidence_sequence: int | None = None


@dataclass(frozen=True)
class AuthorizedContextPacket:
    packet_id: str
    provider_id: str
    owner_identity: str
    capability_id: str | None
    operation: str
    policy_hash: str
    memory_context: tuple[dict[str, Any], ...]
    metadata: dict[str, Any] = field(default_factory=dict)
    authorized: bool = True
    audit_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "provider_id": self.provider_id,
            "owner_identity": self.owner_identity,
            "capability_id": self.capability_id,
            "operation": self.operation,
            "policy_hash": self.policy_hash,
            "memory_context": [dict(item) for item in self.memory_context],
            "metadata": dict(self.metadata),
            "authorized": self.authorized,
            "audit_required": self.audit_required,
        }


class IdentityVerifier(ABC):
    @abstractmethod
    def verify_identity(
        self, identity: IdentityContext | None
    ) -> tuple[bool, str, str]:
        raise NotImplementedError


class CapabilityVerifier(ABC):
    @abstractmethod
    def verify_capability(self, request: OperationRequest) -> CapabilityVerification:
        raise NotImplementedError


class Policy(ABC):
    @property
    @abstractmethod
    def policy_hash(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def evaluate(
        self,
        request: OperationRequest,
        capability: CapabilityVerification,
    ) -> PolicyEvaluation:
        raise NotImplementedError


class Evidence(ABC):
    @abstractmethod
    def record_decision(
        self, request: OperationRequest, decision: AuthorizationDecision
    ) -> int | None:
        raise NotImplementedError


class MemoryFirewall(ABC):
    @abstractmethod
    def build_context_packet(
        self,
        request: OperationRequest,
        decision: AuthorizationDecision,
        *,
        provider_id: str,
        memory_records: Sequence[Any],
    ) -> AuthorizedContextPacket:
        raise NotImplementedError


class AIProvider(ABC):
    @property
    @abstractmethod
    def provider_id(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def execute(self, packet: AuthorizedContextPacket) -> dict[str, Any]:
        raise NotImplementedError


class AuthorityGate(ABC):
    @abstractmethod
    def authorize(self, request: OperationRequest) -> AuthorizationDecision:
        raise NotImplementedError


class DefaultAuthorityGate(AuthorityGate):
    def __init__(
        self,
        *,
        identity_verifier: IdentityVerifier,
        capability_verifier: CapabilityVerifier,
        policy: Policy,
        evidence: Evidence,
    ) -> None:
        self._identity_verifier = identity_verifier
        self._capability_verifier = capability_verifier
        self._policy = policy
        self._evidence = evidence

    def authorize(self, request: OperationRequest) -> AuthorizationDecision:
        operation = request.operation_name
        policy_hash = self._policy.policy_hash

        identity_allowed, identity_code, identity_reason = (
            self._identity_verifier.verify_identity(request.identity)
        )
        if not identity_allowed:
            return self._record(
                request,
                AuthorizationDecision(
                    allowed=False,
                    operation=operation,
                    reason_code=identity_code,
                    reason=identity_reason,
                    capability_id=None,
                    policy_hash=policy_hash,
                ),
            )

        capability = self._capability_verifier.verify_capability(request)
        if not capability.allowed:
            return self._record(
                request,
                AuthorizationDecision(
                    allowed=False,
                    operation=operation,
                    reason_code=capability.reason_code,
                    reason=capability.reason,
                    capability_id=capability.capability_id,
                    policy_hash=policy_hash,
                ),
            )

        policy_decision = self._policy.evaluate(request, capability)
        if not policy_decision.allowed:
            return self._record(
                request,
                AuthorizationDecision(
                    allowed=False,
                    operation=operation,
                    reason_code="POLICY_DENIED",
                    reason=policy_decision.reason,
                    capability_id=capability.capability_id,
                    policy_hash=policy_hash,
                ),
            )

        return self._record(
            request,
            AuthorizationDecision(
                allowed=True,
                operation=operation,
                reason_code="AUTHORIZED",
                reason=policy_decision.reason,
                capability_id=capability.capability_id,
                policy_hash=policy_hash,
            ),
        )

    def _record(
        self,
        request: OperationRequest,
        decision: AuthorizationDecision,
    ) -> AuthorizationDecision:
        evidence_sequence = self._evidence.record_decision(request, decision)
        return AuthorizationDecision(
            allowed=decision.allowed,
            operation=decision.operation,
            reason_code=decision.reason_code,
            reason=decision.reason,
            capability_id=decision.capability_id,
            policy_hash=decision.policy_hash,
            audit_required=decision.audit_required,
            evidence_sequence=evidence_sequence,
        )


class LocalAuthorityProbeProvider(AIProvider):
    """Explicit test probe; it performs no model inference or provider call."""
    def __init__(self) -> None:
        self._last_packet: AuthorizedContextPacket | None = None

    @property
    def provider_id(self) -> str:
        return "local.authority-probe"

    @property
    def last_packet(self) -> AuthorizedContextPacket | None:
        return self._last_packet

    def execute(self, packet: AuthorizedContextPacket) -> dict[str, Any]:
        if not isinstance(packet, AuthorizedContextPacket) or not packet.authorized:
            raise ValueError("local.authority-probe requires an authorized context packet")

        payload = packet.to_dict()
        forbidden_fields = {
            "vault",
            "vault_key",
            "vault_keys",
            "keys",
            "identity_secret",
            "root_of_trust",
            "memory_store",
            "unrestricted_memory",
        }
        unexpected = forbidden_fields.intersection(payload)
        if unexpected:
            raise ValueError("local.authority-probe received forbidden authority material")

        self._last_packet = packet
        return {
            "provider_id": self.provider_id,
            "status": "ok",
            "authorized": True,
            "proof": (
                f"{self.provider_id}:{packet.operation}:"
                f"{packet.capability_id}:{len(packet.memory_context)}"
            ),
        }
