"""
Explicit user-consent records for the Sovereign AI Memory Architecture.

Consent is distinct from capability issuance: consent captures what the
human approved, while capability tokens capture temporary delegated use of
that approved authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import time
import uuid
from typing import Any


class ConsentStatus(StrEnum):
    """Lifecycle states for a user consent record."""

    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


@dataclass
class ConsentRecord:
    """Explicit human approval record with revocation tracking."""

    consent_id: str
    owner_identity: str
    grantee_id: str
    scopes: tuple[str, ...]
    purpose: str
    issued_at: int
    issuer_device: str
    expires_at: int | None = None
    status: ConsentStatus = ConsentStatus.ACTIVE
    revoked_at: int | None = None
    revocation_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def grant(
        cls,
        *,
        owner_identity: str,
        grantee_id: str,
        scopes: list[str] | tuple[str, ...],
        purpose: str,
        issuer_device: str,
        expires_at: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "ConsentRecord":
        """Create a consent record for an explicit user approval."""

        issued_at = int(time.time())
        if expires_at is not None and int(expires_at) <= issued_at:
            raise ValueError("Consent expiry must be after issue time")
        return cls(
            consent_id=str(uuid.uuid4()),
            owner_identity=owner_identity,
            grantee_id=grantee_id,
            scopes=tuple(scopes),
            purpose=purpose,
            issued_at=issued_at,
            issuer_device=issuer_device,
            expires_at=expires_at,
            metadata=dict(metadata or {}),
        )

    def is_active(self, now: int | None = None) -> bool:
        """Return whether the consent remains active."""

        current = int(time.time()) if now is None else int(now)
        if self.status is ConsentStatus.REVOKED:
            return False
        if self.expires_at is not None and current >= self.expires_at:
            return False
        return True

    def current_status(self, now: int | None = None) -> ConsentStatus:
        """Return the effective status, including time-based expiry."""

        if self.status is ConsentStatus.REVOKED:
            return ConsentStatus.REVOKED
        if self.expires_at is not None and (int(time.time()) if now is None else int(now)) >= self.expires_at:
            return ConsentStatus.EXPIRED
        return ConsentStatus.ACTIVE

    def revoke(self, reason: str, *, revoked_at: int | None = None) -> None:
        """Revoke a previously granted consent record."""

        self.status = ConsentStatus.REVOKED
        self.revocation_reason = reason
        self.revoked_at = int(time.time()) if revoked_at is None else int(revoked_at)

    def allows(self, scope: str, now: int | None = None) -> bool:
        """Return whether a scope is covered by active consent."""

        return self.is_active(now) and scope in self.scopes

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable consent document."""

        return {
            "consent_id": self.consent_id,
            "owner_identity": self.owner_identity,
            "grantee_id": self.grantee_id,
            "scopes": list(self.scopes),
            "purpose": self.purpose,
            "issued_at": self.issued_at,
            "issuer_device": self.issuer_device,
            "expires_at": self.expires_at,
            "status": self.current_status().value,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
            "metadata": dict(self.metadata),
        }
