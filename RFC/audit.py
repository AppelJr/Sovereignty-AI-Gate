"""
Tools: audit ledger.

Appends JSON-lines audit records to a flat file and supports
sequential read-back. Each entry includes a chained SHA3-512 hash
so that tampering with any record invalidates all subsequent hashes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


_GENESIS_HASH = "0" * 128


class AuditLedger:
    """Append-only JSONL audit ledger for tool executions."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._previous_hash = _GENESIS_HASH

    def record(self, request, result) -> None:
        """Append one execution record to the ledger."""
        entry: dict[str, Any] = {
            "request": {
                "tool_name": request.tool_name,
                "args": list(request.args),
                "input_hash": request.input_hash,
                "requester": request.requester,
            },
            "result": {
                "tool_name": result.tool_name,
                "status": result.status,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "input_hash": result.input_hash,
                "execution_hash": result.execution_hash,
                "timestamp": result.timestamp,
                "signature": result.signature,
            },
        }
        entry_bytes = json.dumps(entry, sort_keys=True).encode("utf-8")
        chain_input = (self._previous_hash + entry_bytes.decode("utf-8")).encode("utf-8")
        ledger_hash = hashlib.sha3_512(chain_input).hexdigest()
        entry["ledger_hash"] = ledger_hash
        self._previous_hash = ledger_hash
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def read_all(self) -> list[dict[str, Any]]:
        """Return all records in insertion order."""
        if not self._path.exists():
            return []
        records = []
        with self._path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records
