"""
Export: data models.

An ExportBundle is a signed, portable authority bundle that can be
transported out-of-band between sovereign operators.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


EXPORT_SCHEMA_VERSION = "1.0"


@dataclass
class ExportBundle:
    """
    Signed export bundle.

    ``bundle_id``       — unique identifier.
    ``created_by``      — identity of the exporting operator.
    ``created_at``      — ISO-8601 UTC timestamp.
    ``payload``         — the exported data (authority records, etc.).
    ``payload_hash``    — SHA3-512 hex of the canonical payload.
    ``signature``       — hex-encoded ECDSA/Ed25519 signature over payload_hash.
    ``schema_version``  — wire format version.
    """

    bundle_id: str
    created_by: str
    payload: dict[str, Any]
    payload_hash: str
    signature: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    schema_version: str = EXPORT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "bundle_id": self.bundle_id,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "payload": self.payload,
            "payload_hash": self.payload_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExportBundle":
        return cls(
            bundle_id=data["bundle_id"],
            created_by=data["created_by"],
            payload=data["payload"],
            payload_hash=data["payload_hash"],
            signature=data["signature"],
            created_at=data.get("created_at", ""),
            schema_version=data.get("schema_version", EXPORT_SCHEMA_VERSION),
        )
