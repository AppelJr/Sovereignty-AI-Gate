from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Tuple


# ---------------------------------------------------------------------------
# Authority issuance sentinel — not exported from the package public API.
# ToolExecutionContext.__post_init__ validates this marker so that the
# dataclass cannot be constructed without going through
# _issue_tool_execution_context(), which is the authority-only factory.
# ---------------------------------------------------------------------------
_AUTHORITY_TOKEN: object = object()


class DirectExecutionDenied(Exception):
    """Raised when PlaygroundExecutor.execute() is called without an authority-issued context.

    All tool execution must flow through SovereignAuthority.execute_tool_authorized()
    which issues a ToolExecutionContext before calling execute_authorized().
    """


class ContextForgeryDenied(Exception):
    """Raised when a ToolExecutionContext is constructed without the authority marker.

    Direct callers that build a ToolExecutionContext with public fields alone will
    have this exception raised in __post_init__ because _AUTHORITY_TOKEN is not
    accessible through the package's public API.
    """


@dataclass(frozen=True)
class ToolCapability:
    tool_id: str
    allowed_commands: Tuple[str, ...]
    max_runtime_seconds: int
    owner: str
    expires_at: datetime
    signature: str

    def is_expired(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return current >= expires_at


@dataclass(frozen=True)
class ToolExecutionRequest:
    tool_name: str
    args: Tuple[str, ...]
    capability: ToolCapability
    input_hash: str
    requester: str = ""


@dataclass(frozen=True)
class ToolExecutionResult:
    tool_name: str
    status: str
    stdout: str
    stderr: str
    returncode: int
    input_hash: str
    execution_hash: str
    timestamp: str
    signature: str


@dataclass(frozen=True)
class ToolExecutionContext:
    """Authority-issued, authenticity-bounded execution context.

    This context carries the AuthorizationDecision proof and tool-binding
    parameters required by PlaygroundExecutor.execute_authorized().  It cannot
    be constructed without the module-private _AUTHORITY_TOKEN marker, so a
    caller that builds the struct from public fields alone will receive
    ContextForgeryDenied.

    S-002 fields (workspace_id, binding_id, branch, task_id) are reserved and
    must remain None until S-002 identity/workspace is implemented.
    """

    # ── Core identity & authorization ────────────────────────────────────────
    request_id: str
    authorization_id: str | None
    identity_id: str
    capability_id: str | None
    # ── Tool binding ─────────────────────────────────────────────────────────
    tool_name: str
    operation: str
    tool_capability: ToolCapability
    args: Tuple[str, ...]
    input_hash: str
    requester: str
    runtime_version: str
    issued_at: str
    # ── S-002 reserved (not implemented) ────────────────────────────────────
    workspace_id: str | None = None
    binding_id: str | None = None
    branch: str | None = None
    task_id: str | None = None
    # ── Authority marker (excluded from public repr / equality / hash) ───────
    _marker: Any = field(default=None, repr=False, compare=False, hash=False)

    def __post_init__(self) -> None:
        if self._marker is not _AUTHORITY_TOKEN:
            raise ContextForgeryDenied(
                "ToolExecutionContext must be issued by SovereignAuthority via "
                "execute_tool_authorized(); direct construction is not permitted. "
                "Attempted forgery of authority-issued execution context."
            )


def _issue_tool_execution_context(
    *,
    request_id: str,
    authorization_id: str | None,
    identity_id: str,
    capability_id: str | None,
    tool_name: str,
    operation: str,
    tool_capability: ToolCapability,
    args: Tuple[str, ...],
    input_hash: str = "",
    requester: str = "",
    runtime_version: str = "",
    issued_at: str,
    workspace_id: str | None = None,
    binding_id: str | None = None,
    branch: str | None = None,
    task_id: str | None = None,
) -> ToolExecutionContext:
    """Authority-only factory for ToolExecutionContext.

    Not part of the package public API.  Only SovereignAuthority should call
    this function.  Passing _AUTHORITY_TOKEN as the marker ensures the
    resulting context passes __post_init__ validation.
    """
    return ToolExecutionContext(
        request_id=request_id,
        authorization_id=authorization_id,
        identity_id=identity_id,
        capability_id=capability_id,
        tool_name=tool_name,
        operation=operation,
        tool_capability=tool_capability,
        args=args,
        input_hash=input_hash,
        requester=requester,
        runtime_version=runtime_version,
        issued_at=issued_at,
        workspace_id=workspace_id,
        binding_id=binding_id,
        branch=branch,
        task_id=task_id,
        _marker=_AUTHORITY_TOKEN,
    )
