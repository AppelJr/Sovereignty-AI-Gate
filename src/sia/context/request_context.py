"""Immutable context propagated through authority-controlled operations."""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class RequestContext:
    """Authority metadata for one request at a specific pipeline stage."""

    request_id: str
    correlation_id: str
    session_id: str
    operation: str
    subject_id: str
    capability_id: str | None
    policy_hash: str
    timestamp: str
    authority_sequence: int

    def advance(self, authority_sequence: int) -> RequestContext:
        """Return a new context for the next authority pipeline stage."""
        return replace(self, authority_sequence=authority_sequence)

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        correlation_id: str,
        session_id: str,
        operation: str,
        subject_id: str,
        capability_id: str | None,
        policy_hash: str,
    ) -> RequestContext:
        """Create the first context in an authority sequence."""
        return cls(
            request_id=request_id,
            correlation_id=correlation_id,
            session_id=session_id,
            operation=operation,
            subject_id=subject_id,
            capability_id=capability_id,
            policy_hash=policy_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            authority_sequence=1,
        )
