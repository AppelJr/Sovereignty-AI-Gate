"""
Utility: serialization helpers.

Provides load/dump helpers for SIA data objects backed by the
standard `json` module. All persistence uses UTF-8 JSON.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    """Load and parse a JSON file at *path*."""
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def dump_json(obj: Any, path: Path, *, indent: int = 2) -> None:
    """Serialize *obj* to a JSON file at *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=indent, ensure_ascii=False)
        fh.write("\n")


def to_json_str(obj: Any, *, indent: int | None = None) -> str:
    """Return *obj* serialized to a JSON string."""
    return json.dumps(obj, indent=indent, ensure_ascii=False)


def from_json_str(s: str) -> Any:
    """Parse a JSON string and return the result."""
    return json.loads(s)
