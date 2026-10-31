"""Utility: canonical bytes serialization for deterministic hashing.

All objects that enter the audit ledger or are signed must be
serialized with `canonical_bytes()` to ensure byte-for-byte
reproducibility across platforms.
"""
from __future__ import annotations

import json
import math
import unicodedata
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    """Serialize *value* to canonical UTF-8 JSON bytes.

    Rules:
    - Keys are sorted lexicographically (recursive).
    - No extra whitespace.
    - Unicode strings are normalized to NFC.
    - Datetimes are normalized to UTC ISO-8601 with trailing Z.
    - NaN and infinity values are rejected.
    - The result is UTF-8 encoded bytes.
    """
    normalized = _canonicalize(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json(value: Any) -> str:
    """Compatibility alias returning canonical UTF-8 JSON text."""
    return canonical_bytes(value).decode("utf-8")


def canonical_dict(value: Any) -> Any:
    """Return a new object with dict keys sorted recursively."""
    return _canonicalize(value)


def _canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _canonicalize(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, tuple):
        return [_canonicalize(item) for item in value]
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("Non-finite decimal values are not allowed in canonical bytes")
        return format(value.normalize(), "f")
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("Non-finite float values are not allowed in canonical bytes")
        return value
    return value
