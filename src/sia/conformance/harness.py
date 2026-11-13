"""
Conformance: harness.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from sia.conformance.evidence import EvidenceRecord
from sia.errors.exceptions import ConformanceAssertionError

AssertionFn = Callable[[], dict[str, Any] | None]


class ConformanceHarness:
    def __init__(self) -> None:
        self._assertions: list[tuple[str, str, AssertionFn]] = []
        self._evidence: list[EvidenceRecord] = []

    def register(self, rfc: str, assertion_id: str) -> Callable[[AssertionFn], AssertionFn]:
        def decorator(fn: AssertionFn) -> AssertionFn:
            self._assertions.append((rfc, assertion_id, fn))
            return fn
        return decorator

    def add(self, rfc: str, assertion_id: str, fn: AssertionFn) -> None:
        self._assertions.append((rfc, assertion_id, fn))

    def run_all(self) -> list[EvidenceRecord]:
        self._evidence.clear()
        for rfc, assertion_id, fn in self._assertions:
            self._run_one(rfc, assertion_id, fn)
        return list(self._evidence)

    def run_rfc(self, rfc: str) -> list[EvidenceRecord]:
        results: list[EvidenceRecord] = []
        for r, assertion_id, fn in self._assertions:
            if r == rfc:
                results.append(self._run_one(r, assertion_id, fn))
        return results

    def _run_one(self, rfc: str, assertion_id: str, fn: AssertionFn) -> EvidenceRecord:
        evidence_id = str(uuid.uuid4())
        try:
            details = fn() or {}
            record = EvidenceRecord(
                evidence_id=evidence_id,
                rfc=rfc,
                assertion_id=assertion_id,
                result="pass",
                details=details if isinstance(details, dict) else {},
            )
        except ConformanceAssertionError as exc:
            record = EvidenceRecord(
                evidence_id=evidence_id,
                rfc=rfc,
                assertion_id=assertion_id,
                result="fail",
                details={"error": str(exc)},
            )
        except Exception as exc:  # noqa: BLE001
            record = EvidenceRecord(
                evidence_id=evidence_id,
                rfc=rfc,
                assertion_id=assertion_id,
                result="fail",
                details={"exception": type(exc).__name__, "message": str(exc)},
            )
        self._evidence.append(record)
        return record

    @property
    def evidence(self) -> list[EvidenceRecord]:
        return list(self._evidence)

    def passed(self) -> bool:
        return all(e.is_pass() for e in self._evidence)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {"pass": 0, "fail": 0, "skip": 0}
        for e in self._evidence:
            counts[e.result] = counts.get(e.result, 0) + 1
        return counts
