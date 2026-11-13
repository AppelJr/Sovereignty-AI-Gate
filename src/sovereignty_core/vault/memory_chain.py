"""
Append-only tamper-evident memory chain primitives for SAMA.

The memory chain records provenance-aware memory blocks with deterministic
hash chaining. It stays provider-neutral and does not expose vault or root
authority material.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import time
import uuid
from typing import Any, Callable


class MemoryClassification(StrEnum):
    """Memory classifications supported by the foundation layer."""

    USER_CONFIRMED = "USER_CONFIRMED"
    AI_SUGGESTED = "AI_SUGGESTED"
    TEMPORARY_CONTEXT = "TEMPORARY_CONTEXT"


@dataclass(frozen=True)
class MemoryProvenance:
    """Source metadata for a memory block."""

    owner_identity: str
    source_type: str
    source_id: str
    issuer_device: str | None = None
    capability_token_id: str | None = None
    consent_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MemoryBlock:
    """Single append-only memory block."""

    block_id: str
    index: int
    previous_hash: str
    block_hash: str
    classification: MemoryClassification
    content: Any
    provenance: MemoryProvenance
    created_at: int
    signature: str | None = None
    signer: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def payload(self) -> dict[str, Any]:
        """Return the canonicalized block payload excluding the block hash."""

        return {
            "block_id": self.block_id,
            "index": self.index,
            "previous_hash": self.previous_hash,
            "classification": self.classification.value,
            "content": self.content,
            "provenance": {
                "owner_identity": self.provenance.owner_identity,
                "source_type": self.provenance.source_type,
                "source_id": self.provenance.source_id,
                "issuer_device": self.provenance.issuer_device,
                "capability_token_id": self.provenance.capability_token_id,
                "consent_id": self.provenance.consent_id,
                "metadata": self.provenance.metadata,
            },
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


class MemoryChain:
    """In-memory append-only chain of tamper-evident memory blocks."""

    GENESIS_HASH = "0" * 128

    def __init__(self, blocks: list[MemoryBlock] | None = None) -> None:
        self._blocks = list(blocks or [])

    @property
    def blocks(self) -> tuple[MemoryBlock, ...]:
        """Return an immutable snapshot of the chain."""

        return tuple(self._blocks)

    def append(
        self,
        *,
        classification: MemoryClassification | str,
        content: Any,
        provenance: MemoryProvenance,
        signer: str | None = None,
        sign_payload: Callable[[bytes], str] | None = None,
        created_at: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MemoryBlock:
        """Append a new block to the chain."""

        index = len(self._blocks)
        previous_hash = self._blocks[-1].block_hash if self._blocks else self.GENESIS_HASH
        timestamp = int(time.time()) if created_at is None else int(created_at)
        block_id = str(uuid.uuid4())
        normalized = MemoryClassification(classification)
        payload = {
            "block_id": block_id,
            "index": index,
            "previous_hash": previous_hash,
            "classification": normalized.value,
            "content": content,
            "provenance": {
                "owner_identity": provenance.owner_identity,
                "source_type": provenance.source_type,
                "source_id": provenance.source_id,
                "issuer_device": provenance.issuer_device,
                "capability_token_id": provenance.capability_token_id,
                "consent_id": provenance.consent_id,
                "metadata": provenance.metadata,
            },
            "created_at": timestamp,
            "metadata": dict(metadata or {}),
        }
        payload_bytes = self._canonical_bytes(payload)
        block_hash = self._hash_bytes(previous_hash.encode("utf-8") + payload_bytes)
        signature = sign_payload(payload_bytes) if sign_payload is not None else None
        block = MemoryBlock(
            block_id=block_id,
            index=index,
            previous_hash=previous_hash,
            block_hash=block_hash,
            classification=normalized,
            content=content,
            provenance=provenance,
            created_at=timestamp,
            signature=signature,
            signer=signer,
            metadata=dict(metadata or {}),
        )
        self._blocks.append(block)
        return block

    def validate(self, verify_signature: Callable[[bytes, str], bool] | None = None) -> bool:
        """Validate the full chain and optional block signatures."""

        expected_previous = self.GENESIS_HASH
        for index, block in enumerate(self._blocks):
            if block.index != index:
                return False
            if block.previous_hash != expected_previous:
                return False
            payload_bytes = self._canonical_bytes(block.payload())
            expected_hash = self._hash_bytes(block.previous_hash.encode("utf-8") + payload_bytes)
            if expected_hash != block.block_hash:
                return False
            if verify_signature is not None and block.signature is not None:
                if not verify_signature(payload_bytes, block.signature):
                    return False
            expected_previous = block.block_hash
        return True

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable memory-chain document."""

        return {
            "blocks": [
                {
                    "block_id": block.block_id,
                    "index": block.index,
                    "previous_hash": block.previous_hash,
                    "block_hash": block.block_hash,
                    "classification": block.classification.value,
                    "content": block.content,
                    "provenance": {
                        "owner_identity": block.provenance.owner_identity,
                        "source_type": block.provenance.source_type,
                        "source_id": block.provenance.source_id,
                        "issuer_device": block.provenance.issuer_device,
                        "capability_token_id": block.provenance.capability_token_id,
                        "consent_id": block.provenance.consent_id,
                        "metadata": dict(block.provenance.metadata),
                    },
                    "created_at": block.created_at,
                    "signature": block.signature,
                    "signer": block.signer,
                    "metadata": dict(block.metadata),
                }
                for block in self._blocks
            ]
        }

    @staticmethod
    def _canonical_bytes(value: Any) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def _hash_bytes(data: bytes) -> str:
        return hashlib.sha3_512(data).hexdigest()
