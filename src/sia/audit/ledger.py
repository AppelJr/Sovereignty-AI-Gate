"""
Audit: ledger.

Append-only audit ledger for all authority events. Each entry is
hashed and chained to the previous entry so that any tampering is
detectable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sia.errors.exceptions import AuditChainError, AuditTamperedError
from sia.utils.hashing import hash_object

GENESIS_HASH = "0" * 128  # sentinel hash for the first entry


@dataclass
class LedgerEntry:
    """
    A single append-only audit ledger entry.

    ``entry_id``    — monotonically increasing integer index.
    ``event_type``  — string identifier for the event class.
    ``payload``     — JSON-serializable event details.
    ``actor_id``    — identity of the actor who triggered the event.
    ``timestamp``   — ISO-8601 UTC timestamp.
    ``prev_hash``   — SHA3-512 hex of the previous entry's canonical form.
    ``entry_hash``  — SHA3-512 hex of this entry (excluding ``entry_hash``).
    """

    entry_id: int
    event_type: str
    payload: dict[str, Any]
    actor_id: str
    timestamp: str
    prev_hash: str
    entry_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "actor_id": self.actor_id,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        """Compute the hash for this entry (excluding entry_hash itself)."""
        return hash_object(self.to_dict())

    def verify(self) -> None:
        """Raise AuditTamperedError if the stored hash doesn't match."""
        expected = self.compute_hash()
        if self.entry_hash != expected:
            raise AuditTamperedError(
                f"Entry {self.entry_id} hash mismatch: "
                f"expected {expected}, got {self.entry_hash}."
            )


class AuditLedger:
    """
    Append-only, hash-chained audit ledger.

    Usage::

        ledger = AuditLedger()
        ledger.append("authority.init", {"version": "0.1.0"}, actor_id="user:alice")
        ledger.verify_chain()

    """

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    # ── Writing ───────────────────────────────────────────────────────────────

    def append(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        actor_id: str,
        timestamp: str | None = None,
    ) -> LedgerEntry:
        """
        Append a new entry to the ledger and return it.
        The entry hash is computed and stored immediately.
        """
        prev_hash = (
            self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        )
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        entry = LedgerEntry(
            entry_id=len(self._entries),
            event_type=event_type,
            payload=dict(payload),
            actor_id=actor_id,
            timestamp=ts,
            prev_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        return entry

    # ── Verification ──────────────────────────────────────────────────────────

    def verify_chain(self) -> None:
        """
        Verify the entire ledger chain.

        Raises:
            AuditTamperedError: if any entry's stored hash doesn't match
                its computed hash.
            AuditChainError: if the ``prev_hash`` link is broken between
                consecutive entries.
        """
        prev_hash = GENESIS_HASH
        for entry in self._entries:
            entry.verify()  # raises AuditTamperedError if hash mismatch
            if entry.prev_hash != prev_hash:
                raise AuditChainError(
                    f"Chain broken at entry {entry.entry_id}: "
                    f"expected prev_hash={prev_hash}, "
                    f"got {entry.prev_hash}."
                )
            prev_hash = entry.entry_hash

    # ── Reading ───────────────────────────────────────────────────────────────

    def tail(self, n: int = 20) -> list[LedgerEntry]:
        """Return the last *n* entries."""
        return self._entries[-n:]

    def all_entries(self) -> list[LedgerEntry]:
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)
