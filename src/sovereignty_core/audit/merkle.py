"""
SAMA RFC-001
SCAR Merkle Tree Builder

Builds a tamper-evident Merkle root from an append-only SCAR audit log.

Responsibilities:
    - canonicalize SCAR entries
    - hash audit records
    - build Merkle tree
    - generate inclusion proofs
    - verify proofs

Non-responsibilities:
    - signing keys
    - storage backend
    - PQC implementation  (integration point reserved in MerkleTree.algorithm)
    - log transport
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha3_512
from typing import TYPE_CHECKING, Any

from sia.utils.canonical import canonical_bytes

if TYPE_CHECKING:
    from sia.audit.ledger import AuditLedger, LedgerEntry


class MerkleError(Exception):
    """Raised when a Merkle tree operation cannot be completed."""


@dataclass(frozen=True)
class MerkleProof:
    """
    Inclusion proof for a single SCAR log leaf.

    ``leaf_hash``  — SHA3-512 hex of the leaf entry.
    ``siblings``   — ordered list of (direction, sibling_hash) pairs
                     walking from the leaf up to the root.
    ``root``       — expected Merkle root after applying the proof path.
    """

    leaf_hash: str
    siblings: list[tuple[str, str]]
    root: str


@dataclass(frozen=True)
class MerkleTree:
    """
    Immutable Merkle tree built from SCAR audit log leaf hashes.

    ``root``      — single hex string representing the Merkle root.
    ``leaves``    — ordered list of leaf hashes (one per SCAR entry).
    ``levels``    — complete tree: levels[0] == leaves, levels[-1] == [root].
    ``algorithm`` — hash algorithm identifier; reserved for PQC upgrade.
    """

    root: str
    leaves: list[str]
    levels: list[list[str]]
    algorithm: str = "SHA3-512"


# ── Canonicalization ─────────────────────────────────────────────────────────


def canonicalize(entry: dict[str, Any]) -> bytes:
    """
    Produce deterministic UTF-8 bytes for a SCAR record.

    Uses canonical key-sorted JSON (NFC-normalized strings, no NaN/Inf),
    consistent with the rest of the SIA hashing pipeline.
    """
    return canonical_bytes(entry)


# ── Hashing primitives ───────────────────────────────────────────────────────


def hash_entry(entry: dict[str, Any]) -> str:
    """Hash one SCAR entry dict to a hex string."""
    return sha3_512(canonicalize(entry)).hexdigest()


def hash_pair(left: str, right: str) -> str:
    """
    Combine two Merkle node hashes into a parent hash.

    The sibling hashes are concatenated as UTF-8 hex strings before
    hashing, matching standard binary Merkle conventions.
    """
    payload = f"{left}{right}".encode("utf-8")
    return sha3_512(payload).hexdigest()


# ── Tree construction ────────────────────────────────────────────────────────


def _build_merkle_levels(leaves: list[str]) -> list[list[str]]:
    """
    Build all Merkle tree levels from a list of leaf hashes.

    Odd-length layers duplicate the last node to keep the tree complete.
    """
    if not leaves:
        raise MerkleError("Cannot build Merkle tree from empty log")

    levels: list[list[str]] = [list(leaves)]
    current = list(leaves)

    while len(current) > 1:
        if len(current) % 2:
            current.append(current[-1])
        next_level = [
            hash_pair(current[i], current[i + 1])
            for i in range(0, len(current), 2)
        ]
        levels.append(next_level)
        current = next_level

    return levels


def build_merkle_from_scarlog(
    scarlog: list[dict[str, Any]],
) -> MerkleTree:
    """
    Build a Merkle tree from an append-only SCAR log.

    Each entry is a dict with at minimum the fields required for canonical
    serialization.  Example SCAR entry::

        {
            "timestamp": "2026-07-14T02:24:00Z",
            "event": "MEMORY_APPEND",
            "actor": "device_key_id",
            "payload_hash": "<sha3-512-hex>",
            "signature": "<hex>"
        }

    The entries are expected to be in append order — the Merkle root
    commits to both content *and* order.

    Returns:
        :class:`MerkleTree` with an immutable root, leaf hashes, and the
        complete tree level structure for proof generation.

    Raises:
        MerkleError: if *scarlog* is empty.

    SCAR LOG
       |
       | SHA3-512 (canonical JSON)
       v
    Leaf Hashes
       |
       | Merkle Reduction
       v
    SCAR MERKLE ROOT
       |
       | (signed by device identity key — caller responsibility)
       v
    Immutable Audit Anchor
    """
    if not scarlog:
        raise MerkleError("SCAR log is empty")

    leaves = [hash_entry(entry) for entry in scarlog]
    levels = _build_merkle_levels(leaves)

    return MerkleTree(
        root=levels[-1][0],
        leaves=leaves,
        levels=levels,
    )


def build_merkle_from_audit_ledger(ledger: AuditLedger) -> MerkleTree:
    """
    Build a Merkle tree directly from an :class:`~sia.audit.ledger.AuditLedger`.

    Each ledger entry is serialized via its ``to_dict()`` method before
    hashing, so the Merkle leaf commits to the same canonical form that
    the ledger chain verification uses.

    Raises:
        MerkleError: if the ledger contains no entries.
    """
    entries = ledger.all_entries()
    if not entries:
        raise MerkleError("AuditLedger is empty — cannot build Merkle tree")
    return build_merkle_from_scarlog([e.to_dict() for e in entries])


# ── Proof generation and verification ───────────────────────────────────────


def generate_proof(tree: MerkleTree, index: int) -> MerkleProof:
    """
    Generate a Merkle inclusion proof for the leaf at *index*.

    The proof path walks from the leaf up to the root, recording each
    sibling hash and whether it is to the LEFT or RIGHT of the current
    node.  Pass the returned :class:`MerkleProof` to
    :func:`verify_merkle_proof` to confirm membership.

    Args:
        tree:  The :class:`MerkleTree` built by :func:`build_merkle_from_scarlog`.
        index: Zero-based position of the target leaf.

    Raises:
        IndexError: if *index* is out of range for the leaf list.
    """
    if index < 0 or index >= len(tree.leaves):
        raise IndexError(
            f"Leaf index {index} is out of range "
            f"(tree has {len(tree.leaves)} leaves)"
        )

    siblings: list[tuple[str, str]] = []
    position = index

    for level in tree.levels[:-1]:
        # Pad level to even length (mirrors _build_merkle_levels behaviour)
        padded = level if len(level) % 2 == 0 else level + [level[-1]]

        if position % 2 == 0:
            sibling_pos = position + 1
            direction = "RIGHT"
        else:
            sibling_pos = position - 1
            direction = "LEFT"

        siblings.append((direction, padded[sibling_pos]))
        position //= 2

    return MerkleProof(
        leaf_hash=tree.leaves[index],
        siblings=siblings,
        root=tree.root,
    )


def verify_merkle_proof(proof: MerkleProof) -> bool:
    """
    Verify a Merkle inclusion proof.

    Recomputes the root by applying each sibling hash in ``proof.siblings``
    in order and confirms the final value equals ``proof.root``.

    Returns:
        ``True`` if the proof is valid; ``False`` otherwise.

    Raises:
        MerkleError: if an unknown direction string is encountered.
    """
    current = proof.leaf_hash

    for direction, sibling in proof.siblings:
        if direction == "RIGHT":
            current = hash_pair(current, sibling)
        elif direction == "LEFT":
            current = hash_pair(sibling, current)
        else:
            raise MerkleError(f"Unknown proof direction: {direction!r}")

    return current == proof.root
