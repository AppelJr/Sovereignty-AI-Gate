"""
Device-signed, append-only SCAR audit ledger for the SAMA foundation.

This module owns SCAR event definitions, ledger integrity, attestations, and
Merkle integration. It does not own persistent storage, private keys, provider
authentication, or transport.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha3_512
from typing import Any
from types import MappingProxyType
from uuid import uuid4

from sia.utils.canonical import canonical_bytes
from sovereignty_core.audit.merkle import (
    MerkleProof,
    MerkleTree,
    build_merkle_from_scarlog,
    generate_proof,
)
from sovereignty_core.identity.root_of_trust import RootOfTrust
from sovereignty_core.permissions.capability import CapabilityToken
from sovereignty_core.vault.memory_chain import MemoryBlock


GENESIS_EVENT_HASH = "0" * 128


class SCARLedgerError(RuntimeError):
    """Raised when an SCAR ledger invariant or integrity check fails."""


class SCARActor(StrEnum):
    """Actors recognized in a sovereign audit event."""

    HUMAN = "HUMAN"
    PROVIDER = "PROVIDER"
    DEVICE = "DEVICE"


@dataclass(frozen=True)
class SCAREvent:
    """A single device-signed and hash-chained SCAR event."""

    sequence: int
    event_id: str
    event_type: str
    timestamp: str
    identity_id: str
    actor: SCARActor
    capability_id: str | None
    memory_hash: str | None
    previous_event_hash: str
    signature: str
    event_hash: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Detach and freeze metadata so signed event state cannot be mutated."""
        object.__setattr__(self, "metadata", _freeze(self.metadata))

    def signing_document(self) -> dict[str, Any]:
        """Return the canonical event document protected by the signature."""
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "identity_id": self.identity_id,
            "actor": self.actor.value,
            "capability_id": self.capability_id,
            "memory_hash": self.memory_hash,
            "previous_event_hash": self.previous_event_hash,
            "metadata": _thaw(self.metadata),
        }

    def to_dict(self) -> dict[str, Any]:
        """Return the complete serializable SCAR evidence record."""
        return {
            **self.signing_document(),
            "signature": self.signature,
            "event_hash": self.event_hash,
        }


@dataclass(frozen=True)
class SCARAttestation:
    """A device signature binding an audit Merkle root to an identity and count."""

    root_hash: str
    algorithm: str
    entry_count: int
    created_at: str
    identity_id: str
    device_id: str
    signature: str
    version: int = 1
    signature_algorithm: str = "ML-DSA-87"

    def signing_document(self) -> dict[str, Any]:
        """Return the canonical attestation document protected by the signature."""
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "signature_algorithm": self.signature_algorithm,
            "root_hash": self.root_hash,
            "entry_count": self.entry_count,
            "created_at": self.created_at,
            "identity_id": self.identity_id,
            "device_id": self.device_id,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable attestation without private key material."""
        return {**self.signing_document(), "signature": self.signature}


class SCARLedger:
    """In-memory sovereign audit ledger bound to one human identity and device."""

    def __init__(self, *, identity_id: str, root_of_trust: RootOfTrust) -> None:
        if not identity_id:
            raise ValueError("SCAR ledger requires a human identity_id")
        self._identity_id = identity_id
        self._root_of_trust = root_of_trust
        self._events: list[SCAREvent] = []

    @property
    def identity_id(self) -> str:
        """Return the human identity to which this ledger is bound."""
        return self._identity_id

    @property
    def device_id(self) -> str:
        """Return the public device identity that signs ledger records."""
        return self._root_of_trust.identity.identity_id

    @property
    def events(self) -> tuple[SCAREvent, ...]:
        """Return an immutable snapshot of append-only ledger records."""
        return tuple(self._events)

    def append_event(
        self,
        event_type: str,
        *,
        actor: SCARActor | str,
        capability_id: str | None = None,
        memory_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> SCAREvent:
        """Append a device-signed SCAR event and return the immutable record."""
        if not event_type:
            raise ValueError("SCAR event_type must not be empty")
        normalized_actor = SCARActor(actor)
        if normalized_actor == SCARActor.PROVIDER and capability_id is None:
            raise SCARLedgerError("Provider events require capability provenance")
        sequence = len(self._events)
        previous_event_hash = (
            self._events[-1].event_hash if self._events else GENESIS_EVENT_HASH
        )
        signing_document = {
            "sequence": sequence,
            "event_id": str(uuid4()),
            "event_type": event_type,
            "timestamp": timestamp or _utc_timestamp(),
            "identity_id": self.identity_id,
            "actor": normalized_actor.value,
            "capability_id": capability_id,
            "memory_hash": memory_hash,
            "previous_event_hash": previous_event_hash,
            "metadata": deepcopy(metadata or {}),
        }
        signature = self._root_of_trust.sign(
            canonical_bytes(signing_document)
        ).signature
        event_hash = _hash_event(signing_document, signature)
        event = SCAREvent(
            sequence=sequence,
            event_id=signing_document["event_id"],
            event_type=signing_document["event_type"],
            timestamp=signing_document["timestamp"],
            identity_id=signing_document["identity_id"],
            actor=normalized_actor,
            capability_id=signing_document["capability_id"],
            memory_hash=signing_document["memory_hash"],
            previous_event_hash=signing_document["previous_event_hash"],
            metadata=signing_document["metadata"],
            signature=signature,
            event_hash=event_hash,
        )
        self._events.append(event)
        return event

    def record_memory_change(self, memory_block: MemoryBlock) -> SCAREvent:
        """Record a memory-chain block hash without copying plaintext content."""
        provenance = memory_block.provenance
        self._assert_identity(provenance.owner_identity)
        return self.append_event(
            "MEMORY_CHANGE",
            actor=(
                SCARActor.PROVIDER
                if provenance.source_type.lower() == "provider"
                else SCARActor.HUMAN
            ),
            capability_id=provenance.capability_token_id,
            memory_hash=memory_block.block_hash,
            metadata={
                "block_id": memory_block.block_id,
                "classification": memory_block.classification.value,
                "memory_index": memory_block.index,
            },
        )

    def record_capability_issue(self, token: CapabilityToken) -> SCAREvent:
        """Record issuance of a human-owned delegated capability."""
        self._assert_identity(token.owner_identity)
        return self.append_event(
            "CAPABILITY_ISSUED",
            actor=SCARActor.HUMAN,
            capability_id=token.token_id,
            metadata={
                "provider_id": token.provider_id,
                "scopes": sorted(scope.value for scope in token.scopes),
                "issuer_device": token.issuer_device,
                "expires_at": token.expires_at,
            },
        )

    def record_provider_access(
        self,
        token: CapabilityToken,
        *,
        memory_hash: str | None = None,
        metadata: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> SCAREvent:
        """Record access performed under an active delegated capability."""
        self._assert_identity(token.owner_identity)
        if not token.is_active(now):
            raise SCARLedgerError("Provider access requires an active capability")
        return self.append_event(
            "PROVIDER_ACCESS",
            actor=SCARActor.PROVIDER,
            capability_id=token.token_id,
            memory_hash=memory_hash,
            metadata={"provider_id": token.provider_id, **dict(metadata or {})},
        )

    def _canonical_events(self) -> list[dict[str, Any]]:
        """Return detached, complete event records in append order."""
        return [event.to_dict() for event in self._events]

    def get_merkle_root(self) -> MerkleTree:
        """Build a Merkle tree over the complete append-ordered SCAR log."""
        if not self._events:
            raise SCARLedgerError("Cannot attest an empty SCAR ledger")
        return build_merkle_from_scarlog(self._canonical_events())

    def prove_event(self, index: int) -> MerkleProof:
        """Generate an inclusion proof for one append-ordered SCAR event."""
        return generate_proof(self.get_merkle_root(), index)

    def attest_merkle_root(
        self, *, created_at: str | None = None
    ) -> SCARAttestation:
        """Create a device-signed attestation for the current Merkle root."""
        tree = self.get_merkle_root()
        document = {
            "version": 1,
            "algorithm": tree.algorithm,
            "signature_algorithm": "ML-DSA-87",
            "root_hash": tree.root,
            "entry_count": len(tree.leaves),
            "created_at": created_at or _utc_timestamp(),
            "identity_id": self.identity_id,
            "device_id": self.device_id,
        }
        signed = self._root_of_trust.sign(canonical_bytes(document))
        document["signature_algorithm"] = signed.algorithm
        signed = self._root_of_trust.sign(canonical_bytes(document))
        signature = signed.signature
        return SCARAttestation(**document, signature=signature)

    def verify_attestation(self, attestation: SCARAttestation) -> bool:
        """Verify that a root attestation belongs to this ledger and device."""
        if (
            attestation.identity_id != self.identity_id
            or attestation.device_id != self.device_id
        ):
            return False
        if not self._root_of_trust.verify_signature(
            canonical_bytes(attestation.signing_document()), attestation.signature
        ):
            return False
        try:
            tree = self.get_merkle_root()
        except SCARLedgerError:
            return False
        return (
            attestation.root_hash == tree.root
            and attestation.entry_count == len(tree.leaves)
            and attestation.algorithm == tree.algorithm
        )

    def verify_integrity(self) -> bool:
        """Return whether event ordering, hashes, links, and signatures verify."""
        expected_previous_hash = GENESIS_EVENT_HASH
        for sequence, event in enumerate(self._events):
            document = event.signing_document()
            if (
                event.sequence != sequence
                or event.identity_id != self.identity_id
                or event.previous_event_hash != expected_previous_hash
                or (
                    event.actor == SCARActor.PROVIDER
                    and event.capability_id is None
                )
            ):
                return False
            if not self._root_of_trust.verify_signature(
                canonical_bytes(document), event.signature
            ):
                return False
            if event.event_hash != _hash_event(document, event.signature):
                return False
            expected_previous_hash = event.event_hash
        return True

    def export_audit_bundle(self) -> dict[str, Any]:
        """Export auditable, non-secret SCAR evidence."""
        bundle: dict[str, Any] = {
            "format": "SAMA-SCAR-AUDIT-BUNDLE-1",
            "identity_id": self.identity_id,
            "device_id": self.device_id,
            "entries": self._canonical_events(),
        }
        if self._events:
            tree = self.get_merkle_root()
            bundle["merkle_root"] = tree.root
            bundle["merkle_algorithm"] = tree.algorithm
            bundle["attestation"] = self.attest_merkle_root().to_dict()
        return bundle

    def _assert_identity(self, identity_id: str) -> None:
        if identity_id != self.identity_id:
            raise SCARLedgerError("Evidence identity does not match SCAR ledger")


def assert_scar_invariants(ledger: SCARLedger) -> None:
    """Raise AssertionError when an SCAR ledger violates core evidence invariants."""
    assert ledger.verify_integrity()
    for sequence, event in enumerate(ledger.events):
        assert event.sequence == sequence
        assert event.identity_id == ledger.identity_id
        assert event.signature != ""
        assert event.event_hash != ""
        if event.actor == SCARActor.PROVIDER:
            assert event.capability_id is not None


def _utc_timestamp() -> str:
    """Return a canonical UTC timestamp for an audit event."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash_event(document: dict[str, Any], signature: str) -> str:
    """Hash a complete signed SCAR event for append-chain linkage."""
    return sha3_512(canonical_bytes({**document, "signature": signature})).hexdigest()


def _freeze(value: Any) -> Any:
    """Recursively freeze event metadata retained by the ledger."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    return deepcopy(value)


def _thaw(value: Any) -> Any:
    """Return detached canonicalizable data from frozen event metadata."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return deepcopy(value)
