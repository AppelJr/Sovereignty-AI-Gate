from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from sia.delegation.models import DelegationToken
from sia.memory.models import MemoryRecord
from sia.security.authority_policy import AuthorityPolicy
from sia.utils.hashing import hash_object
from sovereignty_core.audit.scar import SCARActor, SCARLedger
from sovereignty_core.identity.identity import DeviceBinding, HumanIdentity
from sovereignty_core.identity.root_of_trust import RootOfTrust, SoftwareTrustBackend
from sovereignty_core.permissions.capability import CapabilityToken
from sovereignty_core.vault.memory_chain import (
    MemoryChain,
    MemoryClassification,
    MemoryProvenance,
)

from .authority_gate import (
    AuthorizedContextPacket,
    CapabilityRecord,
    CapabilityVerification,
    Evidence,
    IdentityContext,
    IdentityVerifier,
    MemoryFirewall,
    OperationRequest,
    Policy,
    PolicyEvaluation,
    ProtectedOperation,
)


@dataclass(frozen=True)
class IdentityAdapter(IdentityVerifier):
    owner_identity: HumanIdentity
    root_of_trust: RootOfTrust

    @classmethod
    def create(
        cls,
        owner_id: str,
        *,
        root_of_trust: RootOfTrust | None = None,
    ) -> "IdentityAdapter":
        trust = root_of_trust or RootOfTrust(SoftwareTrustBackend())
        identity = HumanIdentity.create(
            identity_id=owner_id,
            display_name=owner_id,
            public_identity_key=trust.identity.public_key,
        )
        identity.bind_device(
            DeviceBinding(
                device_id=trust.identity.identity_id,
                root_identity_id=trust.identity.identity_id,
                bound_at=trust.identity.created_at,
            )
        )
        return cls(owner_identity=identity, root_of_trust=trust)

    def identity_context(self) -> IdentityContext:
        return IdentityContext(
            identity_id=self.owner_identity.identity_id,
            device_id=self.root_of_trust.identity.identity_id,
            verified=True,
            hardware_backed=self.root_of_trust.identity.hardware_backed,
            metadata={"authority_source": self.owner_identity.authority_source.value},
        )

    def verify_identity(
        self, identity: IdentityContext | None
    ) -> tuple[bool, str, str]:
        if identity is None:
            return False, "NO_IDENTITY", "No identity context supplied"
        if not identity.verified:
            return False, "INVALID_IDENTITY", "Identity context is not verified"
        if identity.identity_id != self.owner_identity.identity_id:
            return False, "INVALID_IDENTITY", "Identity does not match authority owner"
        if identity.device_id is None or not self.owner_identity.is_device_trusted(
            identity.device_id
        ):
            return False, "INVALID_IDENTITY", "Identity device is not trusted"
        return True, "IDENTITY_VERIFIED", "Identity verified"


class CapabilityAdapter:
    OPERATION_SCOPES = {
        ProtectedOperation.READ_MEMORY: frozenset({"memory.read", "READ_CONTEXT_WINDOW"}),
        ProtectedOperation.WRITE_MEMORY: frozenset(
            {"memory.write", "WRITE_CONFIRMED_MEMORY", "APPEND_MEMORY_SUGGESTION"}
        ),
        ProtectedOperation.EXPORT_ARCHIVE: frozenset({"export.archive"}),
        ProtectedOperation.IMPORT_ARCHIVE: frozenset({"import.archive"}),
        ProtectedOperation.EXECUTE_TOOL: frozenset({"tool.execute"}),
        ProtectedOperation.RELEASE_CONTEXT: frozenset({"context.release"}),
        ProtectedOperation.CALL_PROVIDER: frozenset(
            {"provider.call", "READ_CONTEXT_WINDOW"}
        ),
        ProtectedOperation.WORKSPACE_LIST: frozenset({"workspace.list"}),
        ProtectedOperation.WORKSPACE_READ: frozenset({"workspace.read"}),
        ProtectedOperation.WORKSPACE_ANALYZE: frozenset({"workspace.analyze"}),
        ProtectedOperation.WORKSPACE_REPO_STATUS: frozenset({"workspace.repo_status"}),
    }

    def adapt(self, capability: Any | None) -> CapabilityRecord | None:
        if capability is None:
            return None
        if isinstance(capability, CapabilityRecord):
            return capability
        if isinstance(capability, CapabilityToken):
            return CapabilityRecord(
                capability_id=capability.token_id,
                owner_identity=capability.owner_identity,
                scopes=frozenset(scope.value for scope in capability.scopes),
                provider_id=capability.provider_id,
                issuer_device=capability.issuer_device,
                expires_at=capability.expires_at,
                revoked=capability.revoked,
            )
        if isinstance(capability, DelegationToken):
            return CapabilityRecord(
                capability_id=capability.token_id,
                owner_identity=capability.grantor_id,
                scopes=frozenset(capability.scope),
                provider_id=capability.grantee_id,
                expires_at=capability.expires_at,
                revoked=capability.revoked,
                parent_capability_id=capability.parent_id,
            )
        raise TypeError(f"Unsupported capability type: {type(capability)!r}")

    def verify_capability(self, request: OperationRequest) -> CapabilityVerification:
        adapted = self.adapt(request.capability)
        if adapted is None:
            return CapabilityVerification(
                allowed=False,
                reason_code="MISSING_CAPABILITY",
                reason="Protected operation requires a capability",
            )

        if request.identity is not None and adapted.owner_identity != request.identity.identity_id:
            return CapabilityVerification(
                allowed=False,
                reason_code="INVALID_CAPABILITY",
                reason="Capability owner does not match verified identity",
                capability_id=adapted.capability_id,
            )

        if request.provider_id and adapted.provider_id not in (None, request.provider_id):
            return CapabilityVerification(
                allowed=False,
                reason_code="INVALID_CAPABILITY",
                reason="Capability grantee does not match requested provider",
                capability_id=adapted.capability_id,
            )

        if self._is_inactive(request.capability):
            return CapabilityVerification(
                allowed=False,
                reason_code="EXPIRED_CAPABILITY",
                reason="Capability is expired or revoked",
                capability_id=adapted.capability_id,
            )

        parent = self.adapt(request.parent_capability)
        if parent is not None and not adapted.scopes.issubset(parent.scopes):
            return CapabilityVerification(
                allowed=False,
                reason_code="CHILD_SCOPE_EXCEEDED",
                reason="Child capability cannot exceed parent scope",
                capability_id=adapted.capability_id,
            )

        try:
            op = ProtectedOperation(request.operation)
        except ValueError:
            return CapabilityVerification(
                allowed=False,
                reason_code="UNKNOWN_OPERATION",
                reason=f"Unknown operation: {request.operation}",
                capability_id=adapted.capability_id,
            )
        required_scopes = self.OPERATION_SCOPES[op]
        if adapted.scopes.isdisjoint(required_scopes):
            return CapabilityVerification(
                allowed=False,
                reason_code="CAPABILITY_SCOPE_MISSING",
                reason=f"Capability does not permit {request.operation_name}",
                capability_id=adapted.capability_id,
            )

        return CapabilityVerification(
            allowed=True,
            reason_code="CAPABILITY_VERIFIED",
            reason="Capability verified",
            capability_id=adapted.capability_id,
            scopes=tuple(sorted(adapted.scopes)),
        )

    @staticmethod
    def _is_inactive(capability: Any) -> bool:
        if isinstance(capability, CapabilityToken):
            return not capability.is_active()
        if isinstance(capability, DelegationToken):
            return not capability.is_valid()
        if isinstance(capability, CapabilityRecord):
            if capability.revoked:
                return True
            if capability.expires_at is None:
                return False
            if isinstance(capability.expires_at, int):
                return capability.expires_at <= int(datetime.now(timezone.utc).timestamp())
            return datetime.fromisoformat(capability.expires_at) <= datetime.now(timezone.utc)
        return True


class PolicyAdapter(Policy):
    def __init__(self, policy: AuthorityPolicy) -> None:
        self._policy = policy
        self._policy_hash = hash_object(self._policy.to_dict())

    @property
    def policy_hash(self) -> str:
        return self._policy_hash

    def evaluate(
        self,
        request: OperationRequest,
        capability: CapabilityVerification,
    ) -> PolicyEvaluation:
        decision = self._policy.evaluate(
            {
                "operation": request.operation_name,
                "action": request.operation_name,
                "requester_id": request.requester_id,
                "resource_id": request.resource_id,
                "model_id": request.model_id,
                "provider_id": request.provider_id,
                "capability_id": capability.capability_id,
                "capability_scopes": list(capability.scopes),
            }
        )
        return PolicyEvaluation(
            allowed=decision.allowed,
            reason=decision.reason,
            matched_rule=decision.matched_rule,
        )


class EvidenceLedgerAdapter(Evidence):
    def __init__(self, *, identity_id: str, root_of_trust: RootOfTrust) -> None:
        self._ledger = SCARLedger(identity_id=identity_id, root_of_trust=root_of_trust)
        self._signing_algorithm = root_of_trust.backend.algorithm
        self._dev_mode = not root_of_trust.identity.hardware_backed
        if self._dev_mode:
            print(
                "EvidenceLedgerAdapter: audit evidence is signed by a "
                f"software {root_of_trust.backend.algorithm} backend. "
                "This is NOT hardware-backed attestation. "
                "Production deployments must use a hardware-backed TrustBackend.",
                file=sys.stderr,
            )

    @property
    def ledger(self) -> SCARLedger:
        return self._ledger

    def record_decision(self, request: OperationRequest, decision) -> int | None:
        event = self._ledger.append_event(
            "AUTHORIZATION_DECISION",
            actor=SCARActor.HUMAN,
            capability_id=decision.capability_id,
            metadata={
                "operation": decision.operation,
                "allowed": decision.allowed,
                "reason_code": decision.reason_code,
                "reason": decision.reason,
                "policy_hash": decision.policy_hash,
                "audit_required": decision.audit_required,
                "resource_id": request.resource_id,
                "provider_id": request.provider_id,
            },
        )
        return event.sequence

    def verify_chain(self) -> bool:
        return self._ledger.verify_integrity()

    def export_bundle(self) -> dict[str, Any]:
        bundle = self._ledger.export_audit_bundle()
        if self._dev_mode:
            bundle = dict(bundle)
            bundle["hardware_backed"] = False
            bundle["signing_algorithm"] = self._signing_algorithm
            bundle["hardware_warning"] = (
                "This audit bundle is signed with a real software key but does not "
                "carry hardware-backed attestation."
            )
        return bundle


class VaultAdapter:
    def __init__(self, *, owner_identity: str, root_of_trust: RootOfTrust) -> None:
        self._owner_identity = owner_identity
        self._root_of_trust = root_of_trust
        self._chain = MemoryChain()

    @property
    def chain(self) -> MemoryChain:
        return self._chain

    def record_memory(
        self,
        record: MemoryRecord,
        *,
        capability_id: str | None = None,
    ):
        return self._chain.append(
            classification=MemoryClassification.USER_CONFIRMED,
            content=record.to_dict(),
            provenance=MemoryProvenance(
                owner_identity=self._owner_identity,
                source_type="human",
                source_id=self._owner_identity,
                issuer_device=self._root_of_trust.identity.identity_id,
                capability_token_id=capability_id,
            ),
            signer=self._root_of_trust.identity.identity_id,
            sign_payload=lambda payload: self._root_of_trust.sign(payload).signature,
        )

    def verify_chain(self) -> bool:
        return self._chain.validate(self._root_of_trust.verify_signature)


class DefaultMemoryFirewall(MemoryFirewall):
    def build_context_packet(
        self,
        request: OperationRequest,
        decision,
        *,
        provider_id: str,
        memory_records: Sequence[Any],
    ) -> AuthorizedContextPacket:
        if not decision.allowed:
            raise ValueError("Authorized context packet requires an approved decision")
        if request.identity is None:
            raise ValueError("Authorized context packet requires identity context")

        sanitized_records = tuple(self._sanitize_memory_records(memory_records))
        packet_payload = {
            "provider_id": provider_id,
            "owner_identity": request.identity.identity_id,
            "capability_id": decision.capability_id,
            "operation": request.operation_name,
            "policy_hash": decision.policy_hash,
            "memory_context": list(sanitized_records),
            "resource_id": request.resource_id,
        }
        return AuthorizedContextPacket(
            packet_id=hash_object(packet_payload),
            provider_id=provider_id,
            owner_identity=request.identity.identity_id,
            capability_id=decision.capability_id,
            operation=request.operation_name,
            policy_hash=decision.policy_hash,
            memory_context=sanitized_records,
            metadata={
                "resource_id": request.resource_id,
                "model_id": request.model_id,
            },
        )

    @staticmethod
    def _sanitize_memory_records(
        memory_records: Sequence[Any],
    ) -> Iterable[dict[str, Any]]:
        _SAFE_FIELDS = ("record_id", "model_id", "content")
        for record in memory_records:
            if isinstance(record, MemoryRecord):
                yield {
                    "record_id": record.record_id,
                    "model_id": record.model_id,
                    "content": record.content,
                }
            elif hasattr(record, "keys"):
                yield {k: record[k] for k in _SAFE_FIELDS if k in record}
            else:
                yield {k: getattr(record, k) for k in _SAFE_FIELDS if hasattr(record, k)}
