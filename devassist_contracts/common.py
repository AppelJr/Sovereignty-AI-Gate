"""Shared helpers. Contracts are plain frozen dataclasses with validation.
No network, no randomness in decisions. Hashes are sha256 with a prefix.
"""
from __future__ import annotations

import hashlib
import json

MODES = ("GHOST", "HYBRID", "CLOUD")


class ContractError(ValueError):
    """A contract is malformed. Callers must treat this as DENY."""


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def digest(obj) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj).encode()).hexdigest()


def check_digest(value: str, field: str) -> None:
    if not (isinstance(value, str) and value.startswith("sha256:") and len(value) == 71):
        raise ContractError(f"{field} must be a sha256:<64 hex> digest")


def check_nonempty(value, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{field} must be a non-empty string")
