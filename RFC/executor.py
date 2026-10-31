from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from typing import Sequence

from sia.utils.canonical import canonical_bytes

from .audit import AuditLedger
from .models import (
    DirectExecutionDenied,
    ToolCapability,
    ToolExecutionContext,
    ToolExecutionRequest,
    ToolExecutionResult,
)
from .registry import ToolRegistry
from .validator import CapabilityValidationError, ToolValidator


class PlaygroundExecutor:
    """Capability-bound local execution for a gated playground.

    Execution is restricted to registered tools and produces auditable results,
    but it is intentionally not a sandbox.

    .. warning::
        The public ``execute()`` method is disabled.  All execution must flow
        through ``execute_authorized(ctx)`` where *ctx* is an authority-issued
        ``ToolExecutionContext`` obtained from
        ``SovereignAuthority.execute_tool_authorized()``.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        validator: ToolValidator | None = None,
        audit_ledger: AuditLedger | None = None,
    ) -> None:
        self.registry = registry
        self.validator = validator or ToolValidator()
        self.audit_ledger = audit_ledger

    def execute(
        self,
        tool_name: str,
        args: Sequence[str],
        capability: ToolCapability,
        input_hash: str = "",
        requester: str = "",
        runtime_version: str = "",
    ) -> ToolExecutionResult:
        """Fail closed — direct execution is not permitted.

        All tool execution must be governed through
        ``SovereignAuthority.execute_tool_authorized()`` which issues an
        authority-bound ``ToolExecutionContext`` before calling
        ``execute_authorized()``.  Calling this method directly raises
        ``DirectExecutionDenied``.
        """
        raise DirectExecutionDenied(
            "Direct PlaygroundExecutor.execute() is not permitted. "
            "Tool execution requires an authority-issued ToolExecutionContext. "
            "Use SovereignAuthority.execute_tool_authorized() to obtain a "
            "governed execution context and call execute_authorized(ctx)."
        )

    def execute_authorized(self, ctx: ToolExecutionContext) -> ToolExecutionResult:
        """Execute a tool under an authority-issued ToolExecutionContext.

        *ctx* must be an instance of ``ToolExecutionContext`` issued by
        ``SovereignAuthority`` via ``execute_tool_authorized()``.  Any
        attempt to pass a forged or caller-constructed context will have been
        caught at context construction time (``ContextForgeryDenied``).
        Additional runtime checks are performed here before subprocess execution.
        """
        if not isinstance(ctx, ToolExecutionContext):
            raise DirectExecutionDenied(
                "execute_authorized() requires an authority-issued ToolExecutionContext; "
                f"received {type(ctx).__name__!r}."
            )
        # ctx._marker was validated in ToolExecutionContext.__post_init__, so
        # any existing instance is authority-issued.  Perform binding checks.
        self._check_context(ctx)

        request = ToolExecutionRequest(
            tool_name=ctx.tool_name,
            args=ctx.args,
            capability=ctx.tool_capability,
            input_hash=ctx.input_hash,
            requester=ctx.requester,
        )
        self.validator.validate(request)

        executable = self.registry.resolve(ctx.tool_name)
        result = subprocess.run(
            [executable, *ctx.args],
            capture_output=True,
            text=True,
            timeout=ctx.tool_capability.max_runtime_seconds,
            check=False,
        )

        timestamp = datetime.now(timezone.utc).isoformat()
        stdout_hash = hashlib.sha3_512(result.stdout.encode("utf-8")).hexdigest()
        stderr_hash = hashlib.sha3_512(result.stderr.encode("utf-8")).hexdigest()
        execution_hash = self._hash_execution(
            tool_name=ctx.tool_name,
            args=ctx.args,
            input_hash=ctx.input_hash,
            stdout_hash=stdout_hash,
            stderr_hash=stderr_hash,
            returncode=result.returncode,
            runtime_version=ctx.runtime_version,
        )
        signature = self._hash_signature(ctx.tool_capability.signature, execution_hash)

        output = ToolExecutionResult(
            tool_name=ctx.tool_name,
            status="success" if result.returncode == 0 else "error",
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
            input_hash=ctx.input_hash,
            execution_hash=execution_hash,
            timestamp=timestamp,
            signature=signature,
        )

        if self.audit_ledger is not None:
            self.audit_ledger.record(request, output)

        return output

    def _check_context(self, ctx: ToolExecutionContext) -> None:
        """Validate tool-binding, expiry, and allowed-command constraints."""
        if ctx.tool_capability.is_expired():
            raise CapabilityValidationError(
                f"capability for {ctx.tool_name!r} has expired"
            )
        if ctx.tool_name not in ctx.tool_capability.allowed_commands:
            raise CapabilityValidationError(
                f"tool {ctx.tool_name!r} is not in the capability's allowed_commands "
                f"{ctx.tool_capability.allowed_commands!r}"
            )

    def _hash_execution(
        self,
        *,
        tool_name: str,
        args: Sequence[str],
        input_hash: str,
        stdout_hash: str,
        stderr_hash: str,
        returncode: int,
        runtime_version: str,
    ) -> str:
        payload = {
            "tool_name": tool_name,
            "args": list(args),
            "input_hash": input_hash,
            "stdout_hash": stdout_hash,
            "stderr_hash": stderr_hash,
            "returncode": returncode,
            "runtime_version": runtime_version,
        }
        encoded = canonical_bytes(payload)
        return hashlib.sha3_512(encoded).hexdigest()

    def _hash_signature(self, capability_signature: str, execution_hash: str) -> str:
        payload = f"{capability_signature}:{execution_hash}".encode("utf-8")
        return hashlib.sha3_512(payload).hexdigest()
