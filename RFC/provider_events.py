"""Provider lifecycle SCAR events created exclusively by the authority layer."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sia.context.request_context import RequestContext


class ProviderEventType(StrEnum):
    REQUESTED = "requested"
    APPROVED = "approved"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class ProviderSCAREvent:
    """An immutable, authority-owned provider invocation evidence record."""

    event_type: ProviderEventType
    context: RequestContext
    provider_id: str
    error_code: str | None = None
    error_category: str | None = None
    retryable: bool | None = None

    def to_payload(self) -> dict[str, object]:
        return {
            "event_type": self.event_type.value,
            "request_id": self.context.request_id,
            "correlation_id": self.context.correlation_id,
            "session_id": self.context.session_id,
            "operation": self.context.operation,
            "subject_id": self.context.subject_id,
            "capability_id": self.context.capability_id,
            "policy_hash": self.context.policy_hash,
            "authority_sequence": self.context.authority_sequence,
            "provider_id": self.provider_id,
            "error_code": self.error_code,
            "error_category": self.error_category,
            "retryable": self.retryable,
        }


def create_provider_scar_event(
    *,
    event_type: ProviderEventType,
    ctx: RequestContext,
    provider_id: str,
    error_code: str | None = None,
    error_category: str | None = None,
    retryable: bool | None = None,
) -> ProviderSCAREvent:
    """Create an authority-owned provider lifecycle event."""
    return ProviderSCAREvent(
        event_type=event_type,
        context=ctx,
        provider_id=provider_id,
        error_code=error_code,
        error_category=error_category,
        retryable=retryable,
    )
