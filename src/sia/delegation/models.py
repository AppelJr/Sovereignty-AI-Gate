"""
Delegation: data models.

A DelegationToken grants a subset of authority from a grantor
to a grantee, scoped to specific actions and time-bounded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class DelegationToken:
    """
    Authority delegation token.

    ``token_id``    — unique identifier.
    ``grantor_id``  — identity of the authority that granted this token.
    ``grantee_id``  — identity receiving the delegated authority.
    ``scope``       — list of permitted action strings.
    ``issued_at``   — ISO-8601 UTC timestamp.
    ``expires_at``  — ISO-8601 UTC expiry timestamp (None = no expiry).
    ``depth``       — delegation chain depth (root = 0).
    ``revoked``     — True if this token has been revoked.
    ``parent_id``   — token_id of the parent delegation, or None for root.
    """

    token_id: str
    grantor_id: str
    grantee_id: str
    scope: list[str]
    issued_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: str | None = None
    depth: int = 0
    revoked: bool = False
    parent_id: str | None = None
    schema_version: str = "1.0"

    MAX_DEPTH = 4  # maximum allowed delegation chain depth

    # ── Status helpers ────────────────────────────────────────────────────────

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.fromisoformat(self.expires_at) < datetime.now(timezone.utc)

    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired()

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "token_id": self.token_id,
            "grantor_id": self.grantor_id,
            "grantee_id": self.grantee_id,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "depth": self.depth,
            "revoked": self.revoked,
            "parent_id": self.parent_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DelegationToken":
        return cls(
            token_id=data["token_id"],
            grantor_id=data["grantor_id"],
            grantee_id=data["grantee_id"],
            scope=data["scope"],
            issued_at=data.get("issued_at", ""),
            expires_at=data.get("expires_at"),
            depth=data.get("depth", 0),
            revoked=data.get("revoked", False),
            parent_id=data.get("parent_id"),
            schema_version=data.get("schema_version", "1.0"),
        )
