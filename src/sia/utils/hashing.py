"""
Utility: deterministic hashing helpers.

All hashes used inside SIA are SHA3-512. This provides 256-bit
preimage resistance against a Grover-capable adversary. The helpers
produce lowercase, 128-character hexadecimal strings.
"""
from __future__ import annotations

import hashlib
from typing import Any

from sia.utils.canonical import canonical_bytes

HASH_ALGORITHM = "sha3_512"
DEFAULT_DOMAIN = "SIA_ARTIFACT"


def hash_bytes(data: bytes) -> bytes:
    """Return the raw 64-byte SHA3-512 digest of *data*."""
    return hashlib.sha3_512(data).digest()


def hash_hex(data: bytes) -> str:
    """Return the hex-encoded SHA3-512 digest of *data*."""
    return hashlib.sha3_512(data).hexdigest()


def canonical_hash(obj: Any, *, domain: str = DEFAULT_DOMAIN) -> str:
    """Hash canonical bytes with optional domain separation."""
    domain_bytes = domain.encode("utf-8")
    payload_bytes = canonical_bytes(obj)
    return hash_hex(domain_bytes + b"\x00" + payload_bytes)


def hash_object(obj: Any) -> str:
    """Return the hex-encoded SHA3-512 digest of canonical bytes for *obj*."""
    return canonical_hash(obj)


def chain_hash(previous_hash: str, entry: Any, *, domain: str = DEFAULT_DOMAIN) -> str:
    """Compute the chained hash for an audit ledger entry."""
    prev_bytes = previous_hash.encode("utf-8")
    entry_bytes = canonical_bytes(entry)
    return hash_hex(domain.encode("utf-8") + b"\x00" + prev_bytes + b"\x00" + entry_bytes)
