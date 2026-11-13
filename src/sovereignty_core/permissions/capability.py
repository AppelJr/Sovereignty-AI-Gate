"""
Delegated capability tokens for the Sovereign AI Memory Architecture.

This layer defines temporary, least-privilege permission grants that allow
providers to borrow narrowly scoped authority without ever receiving root,
identity, or vault secrets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import json
import time
import uuid
from typing import Any, Callable, Iterable


class CapabilityScope(StrEnum):
    """Capability scopes recognized by the SAMA foundation layer."""

    READ_PREFERENCE = "READ_PREFERENCE"
    READ_CONTEXT_WINDOW = "READ_CONTEXT_WINDOW"
    APPEND_MEMORY_SUGGESTION = "APPEND_MEMORY_SUGGESTION"
    WRITE_CONFIRMED_MEMORY = "WRITE_CONFIRMED_MEMORY"
    ROOT_ACCESS = "ROOT_ACCESS"
    ADMIN_MEMORY_ACCESS = "ADMIN_MEMORY_ACCESS"
    EXPORT_VAULT = "EXPORT_VAULT"
    EXPORT_PRIVATE_KEYS = "EXPORT_PRIVATE_KEYS"
    MINT_IDENTITY = "MINT_IDENTITY"


ALLOWED_SCOPES = frozenset(
    {
        CapabilityScope.READ_PREFERENCE,
        CapabilityScope.READ_CONTEXT_WINDOW,
        CapabilityScope.APPEND_MEMORY_SUGGESTION,
        CapabilityScope.WRITE_CONFIRMED_MEMORY,
    }
)

FORBIDDEN_SCOPES = frozenset(
    {
        CapabilityScope.ROOT_ACCESS,
        CapabilityScope.ADMIN_MEMORY_ACCESS,
        CapabilityScope.EXPORT_VAULT,
        CapabilityScope.EXPORT_PRIVATE_KEYS,
        CapabilityScope.MINT_IDENTITY,
    }
)


@dataclass(frozen=True)
class CapabilityAudit:
    """Audit metadata for issuance and revocation decisions."""

    issuer_device: str
    created_by: str = "HUMAN"
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CapabilityToken:
    """
    Signed temporary provider permission token.

    Invariants:
    - provider_id != owner_identity
    - provider_id != authority_source
    - issuer == HUMAN_DEVICE
    - requested scopes exclude root access
    """

    token_id: str
    provider_id: str
    owner_identity: str
    scopes: frozenset[CapabilityScope]
    forbidden_scopes: frozenset[CapabilityScope]
    issued_at: int
    expires_at: int
    issuer_device: str
    signature: str
    issuer: str = "HUMAN_DEVICE"
    authority_source: str = "ROOT_OF_TRUST"
    revoked: bool = False
    revocation_id: str | None = None
    revoked_at: int | None = None
    audit: CapabilityAudit = field(
        default_factory=lambda: CapabilityAudit(issuer_device="unknown")
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.assert_invariants()

    @classmethod
    def create(
        cls,
        *,
        provider_id: str,
        owner_identity: str,
        scopes: Iterable[CapabilityScope | str],
        issuer_device: str,
        signature: str,
        ttl_seconds: int,
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> "CapabilityToken":
        """Create a new temporary capability token."""

        issued_at = int(time.time())
        expires_at = issued_at + int(ttl_seconds)
        normalized_scopes = frozenset(CapabilityScope(scope) for scope in scopes)
        metadata_dict = dict(metadata or {})
        return cls(
            token_id=str(uuid.uuid4()),
            provider_id=provider_id,
            owner_identity=owner_identity,
            scopes=normalized_scopes,
            forbidden_scopes=FORBIDDEN_SCOPES,
            issued_at=issued_at,
            expires_at=expires_at,
            issuer_device=issuer_device,
            signature=signature,
            audit=CapabilityAudit(
                issuer_device=issuer_device,
                reason=reason,
                metadata=metadata_dict,
            ),
            metadata=metadata_dict,
        )

    def assert_invariants(self) -> None:
        """Validate the core SAMA capability invariants."""

        if self.provider_id == self.owner_identity:
            raise ValueError("PROVIDER must not equal OWNER")
        if self.provider_id == self.authority_source:
            raise ValueError("PROVIDER must not equal AUTHORITY_SOURCE")
        if self.issuer != "HUMAN_DEVICE":
            raise ValueError("Capability issuer must be HUMAN_DEVICE")
        if not self.scopes:
            raise ValueError("Capability must include at least one scope")
        if not self.scopes.issubset(ALLOWED_SCOPES):
            raise ValueError("Capability scopes must be least-privilege allowed scopes only")
        if self.scopes & self.forbidden_scopes:
            raise ValueError("Capability scopes must not include forbidden scopes")
        if CapabilityScope.ROOT_ACCESS in self.scopes:
            raise ValueError("Capability scope must not include ROOT_ACCESS")
        if self.expires_at <= self.issued_at:
            raise ValueError("Capability expiration must be after issue time")

    def is_expired(self, now: int | None = None) -> bool:
        """Return whether the token has expired."""

        current = int(time.time()) if now is None else int(now)
        return current >= self.expires_at

    def is_active(self, now: int | None = None) -> bool:
        """Return whether the token is currently usable."""

        return not self.revoked and not self.is_expired(now)

    def revoke(self, *, revocation_id: str | None = None, revoked_at: int | None = None) -> None:
        """Revoke a previously issued capability token."""

        self.revoked = True
        self.revocation_id = revocation_id or str(uuid.uuid4())
        self.revoked_at = int(time.time()) if revoked_at is None else int(revoked_at)

    def allows(self, scope: CapabilityScope | str, now: int | None = None) -> bool:
        """Return whether a given scope is actively allowed."""

        normalized = CapabilityScope(scope)
        return self.is_active(now) and normalized in self.scopes

    def signing_payload(self) -> bytes:
        """Return canonical bytes suitable for detached signature verification."""

        document = {
            "token_id": self.token_id,
            "provider_id": self.provider_id,
            "owner_identity": self.owner_identity,
            "scopes": sorted(scope.value for scope in self.scopes),
            "forbidden_scopes": sorted(scope.value for scope in self.forbidden_scopes),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "issuer_device": self.issuer_device,
            "issuer": self.issuer,
            "authority_source": self.authority_source,
            "metadata": self.metadata,
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify_signature(self, verifier: Callable[[bytes, str], bool]) -> bool:
        """Run a caller-supplied verification hook."""

        return verifier(self.signing_payload(), self.signature)

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable token document."""

        return {
            "token_id": self.token_id,
            "provider_id": self.provider_id,
            "owner_identity": self.owner_identity,
            "scopes": sorted(scope.value for scope in self.scopes),
            "forbidden_scopes": sorted(scope.value for scope in self.forbidden_scopes),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "issuer_device": self.issuer_device,
            "signature": self.signature,
            "issuer": self.issuer,
            "authority_source": self.authority_source,
            "revoked": self.revoked,
            "revocation_id": self.revocation_id,
            "revoked_at": self.revoked_at,
            "audit": {
                "issuer_device": self.audit.issuer_device,
                "created_by": self.audit.created_by,
                "reason": self.audit.reason,
                "metadata": dict(self.audit.metadata),
            },
            "metadata": dict(self.metadata),
        }
