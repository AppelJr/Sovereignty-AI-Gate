"""
Conformance: evidence records.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

AssertionResult = Literal["pass", "fail", "skip"]


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    rfc: str
    assertion_id: str
    result: AssertionResult
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "rfc": self.rfc,
            "assertion_id": self.assertion_id,
            "result": self.result,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    def is_pass(self) -> bool:
        return self.result == "pass"

    def is_fail(self) -> bool:
        return self.result == "fail"
