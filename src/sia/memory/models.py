"""
Memory: data models.

Defines the in-memory (runtime) and on-disk representation of a
memory record. Memory is scoped per model and encrypted at rest.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class MemoryRecord:
    """
    A single unit of AI conversation memory.

    ``model_id``   — the model that owns this memory.
    ``content``    — the decrypted content (plaintext dict or string).
    ``consent``    — set of model IDs that the owner has granted read access.
    ``created_at`` — ISO-8601 UTC timestamp.
    ``record_id``  — unique identifier (caller-supplied or auto-generated).
    """

    record_id: str
    model_id: str
    content: Any
    consent: list[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    schema_version: str = "1.0"

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_id": self.record_id,
            "model_id": self.model_id,
            "content": self.content,
            "consent": self.consent,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemoryRecord":
        return cls(
            record_id=data["record_id"],
            model_id=data["model_id"],
            content=data["content"],
            consent=data.get("consent", []),
            created_at=data.get("created_at", ""),
            schema_version=data.get("schema_version", "1.0"),
        )

    def has_consent(self, requesting_model_id: str) -> bool:
        """Return True if *requesting_model_id* is the owner or has consent."""
        return (
            requesting_model_id == self.model_id
            or requesting_model_id in self.consent
        )
