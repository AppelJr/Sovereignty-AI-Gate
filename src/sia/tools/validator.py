"""
Tools: capability validator.

Validates that a ToolExecutionRequest carries a current, non-expired
ToolCapability before allowing execution.
"""
from __future__ import annotations


class CapabilityValidationError(Exception):
    """Raised when a tool capability fails validation."""


class ToolValidator:
    """Validates capability-bound execution requests."""

    def validate(self, request) -> None:
        """Raise CapabilityValidationError if the capability is expired."""
        if request.capability.is_expired():
            raise CapabilityValidationError(
                f"capability for {request.tool_name!r} has expired"
            )
