"""
Imports: data models.

RFC-0019 canonical import model.
Imported ledgers are evidence only: they can reconstruct state,
but they cannot create authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


IMPORT_SCHEMA_VERSION = "1.0"
SUPPORTED_VERSIONS = {"1.0"}


@dataclass
class ImportBundle:
    """
    Inbound import bundle.

    ``bundle_id``       — unique identifier (matches the originating ExportBundle).
    ``created_by``      — identity of the exporting operator.
    ``payload``         — the exported data (authority records, etc.).
    ``payload_hash``    — SHA3-512 hex of the canonical payload.
    ``signature``       — hex-encoded signature over payload_hash.
    ``created_at``      — ISO-8601 UTC timestamp.
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
    schema_version: str = IMPORT_SCHEMA_VERSION

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
    def from_dict(cls, data: dict[str, Any]) -> "ImportBundle":
        return cls(
            bundle_id=data["bundle_id"],
            created_by=data["created_by"],
            payload=data["payload"],
            payload_hash=data["payload_hash"],
            signature=data["signature"],
            created_at=data.get("created_at", ""),
            schema_version=data.get("schema_version", IMPORT_SCHEMA_VERSION),
        )


@dataclass(frozen=True)
class ImportedLedger:
    ledger_version: str
    ledger_hash: str
    records: tuple[dict[str, Any], ...]
    schema_version: str = IMPORT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "ledger_version": self.ledger_version,
            "ledger_hash": self.ledger_hash,
            "records": list(self.records),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImportedLedger":
        return cls(
            ledger_version=data["ledger_version"],
            ledger_hash=data["ledger_hash"],
            records=tuple(data["records"]),
            schema_version=data.get("schema_version", IMPORT_SCHEMA_VERSION),
        )


@dataclass(frozen=True)
class ImportBundle:
    """RFC-0019 canonical import bundle.

    Carries an opaque payload, its hash, and a signature.  Validation
    is intentionally kept separate (see ``sia.imports.validator``).
    """

    bundle_id: str
    created_by: str
    payload: Any
    payload_hash: str
    signature: str
    created_at: str
    schema_version: str = IMPORT_SCHEMA_VERSION

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
    def from_dict(cls, data: dict[str, Any]) -> "ImportBundle":
        return cls(
            bundle_id=data["bundle_id"],
            created_by=data["created_by"],
            payload=data["payload"],
            payload_hash=data["payload_hash"],
            signature=data["signature"],
            created_at=data["created_at"],
            schema_version=data.get("schema_version", IMPORT_SCHEMA_VERSION),
        )
