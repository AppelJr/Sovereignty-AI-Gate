"""Hash-chained, append-only evidence ledger for SCAR events and REPMHL
handoff records.

Chained, NOT signed. Signing needs a device key (Secure Enclave) and is not
wired here. The append path takes an exclusive file lock, reads the tail,
writes, and fsyncs, so separate processes cannot fork the chain.
Only digests and short labels go in. Never payload content, keys, or logs.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time
from pathlib import Path

from .common import ContractError, canonical
from .contracts import (
    ExecutionReceipt,
    HumanEscalationEvent,
    RouteDecision,
    TaskEnvelope,
)

GENESIS = "0" * 64


def _h(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + canonical(body)).encode()).hexdigest()


class EvidenceChain:
    def __init__(self, path):
        self.path = Path(path)
        self.lock_path = Path(str(path) + ".lock")

    def _tail(self):
        if not self.path.exists():
            return 0, GENESIS
        last = None
        with self.path.open() as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS
        e = json.loads(last)
        return e["seq"], e["entry_hash"]

    def append(self, kind: str, task_id: str, subject_digest: str, meta: dict | None = None) -> dict:
        meta = meta or {}
        for k, v in meta.items():
            if not isinstance(v, (str, int, bool)) or (isinstance(v, str) and len(v) > 200):
                raise ContractError("meta holds short labels only, never content")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            seq, prev = self._tail()
            body = {
                "seq": seq + 1,
                "kind": kind,
                "task_id": task_id,
                "subject": subject_digest,
                "meta": meta,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "signed": False,
                "prev_hash": prev,
            }
            entry = dict(body, entry_hash=_h(prev, body))
            with self.path.open("a") as fh:
                fh.write(canonical(entry) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return entry

    def verify(self) -> bool:
        prev, expect = GENESIS, 1
        if not self.path.exists():
            return True
        for line in self.path.read_text().splitlines():
            if not line.strip():
                continue
            e = json.loads(line)
            claimed = e.pop("entry_hash")
            if e["seq"] != expect or e["prev_hash"] != prev or _h(prev, e) != claimed:
                return False
            prev, expect = claimed, expect + 1
        return True


_KINDS = {
    TaskEnvelope: "TASK_ENVELOPE",
    RouteDecision: "ROUTE_DECISION",
    ExecutionReceipt: "EXECUTION_RECEIPT",
    HumanEscalationEvent: "HUMAN_ESCALATION",
}


def record_scar(chain: EvidenceChain, contract) -> dict:
    """SCAR event binding: one chained entry per contract, digest only."""
    kind = _KINDS.get(type(contract))
    if kind is None:
        raise ContractError("unknown contract type")
    meta = {}
    if isinstance(contract, RouteDecision):
        meta = {"route": contract.route, "mode": contract.mode}
    if isinstance(contract, ExecutionReceipt):
        meta = {"outcome": contract.outcome}
    return chain.append(kind, contract.task_id, contract.digest(), meta)


def record_repmhl_handoff(chain: EvidenceChain, receipt: ExecutionReceipt, scar_entry: dict) -> dict:
    """REPMHL record binding: ties a receipt to the SCAR entry that holds it."""
    if scar_entry["kind"] != "EXECUTION_RECEIPT" or scar_entry["subject"] != receipt.digest():
        raise ContractError("scar entry does not match receipt")
    return chain.append(
        "REPMHL_HANDOFF",
        receipt.task_id,
        receipt.digest(),
        {"scar_seq": scar_entry["seq"], "scar_hash": scar_entry["entry_hash"][:64]},
    )
