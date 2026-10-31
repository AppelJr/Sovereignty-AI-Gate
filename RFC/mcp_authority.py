from __future__ import annotations

import ast
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sia.audit.recorder import AuditRecorder
from sia.authority_gate import CapabilityRecord, IdentityContext, OperationRequest, ProtectedOperation
from sia.authority import SovereignAuthority

MAX_FILE_BYTES = 1_000_000
MAX_LIST_RESULTS = 200
SENSITIVE_SUFFIXES = frozenset({".env", ".key", ".pem", ".p12", ".pfx", ".token"})


@dataclass(frozen=True)
class MCPCallResult:
    payload: dict[str, Any]
    is_error: bool = False

    def to_mcp_result(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "content": [{"type": "text", "text": json.dumps(self.payload, sort_keys=True)}]
        }
        if self.is_error:
            result["isError"] = True
        return result


class WorkspaceExecutor:
    """Bounded, read-only workspace operations."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace.resolve()

    def execute(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "workspace_list":
            return self._list_workspace(arguments.get("path", ""))
        if tool_name == "workspace_read":
            return self._read_workspace(arguments.get("path"))
        if tool_name == "workspace_analyze":
            return self._analyze_workspace(arguments.get("path"))
        if tool_name == "workspace_repo_status":
            return self._repo_status()
        raise ValueError(f"Unknown workspace tool: {tool_name}")

    def _resolve_workspace_path(self, relative_path: Any) -> Path:
        if not isinstance(relative_path, str) or not relative_path:
            raise ValueError("A non-empty relative path is required")
        candidate = (self.workspace / relative_path).resolve()
        try:
            candidate.relative_to(self.workspace)
        except ValueError as error:
            raise ValueError("Path must remain within the configured workspace") from error
        if self._is_restricted(candidate):
            raise ValueError("Hidden and sensitive files cannot be accessed")
        return candidate

    def _is_restricted(self, path: Path) -> bool:
        relative = path.relative_to(self.workspace)
        return any(
            part.startswith(".") for part in relative.parts if part not in {".", ".."}
        ) or path.suffix.lower() in SENSITIVE_SUFFIXES

    def _list_workspace(self, relative_path: Any) -> dict[str, Any]:
        directory = self.workspace if relative_path == "" else self._resolve_workspace_path(relative_path)
        if not directory.is_dir():
            raise ValueError("Path is not a directory")
        files: list[str] = []
        for item in directory.rglob("*"):
            if len(files) >= MAX_LIST_RESULTS:
                break
            resolved = item.resolve()
            if item.is_file() and resolved.is_relative_to(self.workspace) and not self._is_restricted(resolved):
                files.append(str(resolved.relative_to(self.workspace)))
        return {"files": sorted(files), "truncated": len(files) == MAX_LIST_RESULTS}

    def _read_workspace(self, relative_path: Any) -> dict[str, str]:
        file_path = self._resolve_workspace_path(relative_path)
        if not file_path.is_file():
            raise ValueError("Path is not a file")
        if file_path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds {MAX_FILE_BYTES} byte read limit")
        return {"path": str(file_path.relative_to(self.workspace)), "content": file_path.read_text("utf-8")}

    def _analyze_workspace(self, relative_path: Any) -> dict[str, Any]:
        file_path = self._resolve_workspace_path(relative_path)
        if not file_path.is_file():
            raise ValueError("Path is not a file")
        if file_path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds {MAX_FILE_BYTES} byte read limit")
        content = file_path.read_text("utf-8")
        diagnostics = [
            {"rule": "trailing-whitespace", "line": line_number}
            for line_number, line in enumerate(content.splitlines(), start=1)
            if line.rstrip() != line
        ]
        if file_path.suffix == ".py":
            try:
                ast.parse(content, filename=str(file_path))
            except SyntaxError as error:
                diagnostics.insert(
                    0,
                    {"rule": "syntax-error", "line": error.lineno or 1, "message": error.msg},
                )
        return {
            "path": str(file_path.relative_to(self.workspace)),
            "diagnostics": diagnostics,
            "writeAccess": "disabled; review and apply fixes explicitly in the agent branch",
        }

    def _repo_status(self) -> dict[str, Any]:
        status = {
            "branch": "unknown",
            "commit": "unknown",
            "staged_count": 0,
            "unstaged_count": 0,
            "untracked_count": 0,
            "clean": True,
            "workspace": str(self.workspace),
            "shell_access": "disabled; repository status is read-only",
            "status_source": "filesystem",
        }
        git_dir = self.workspace / ".git"
        head_path = git_dir / "HEAD"
        if not head_path.is_file():
            return status
        head = head_path.read_text("utf-8").strip()
        if not head:
            return status
        if head.startswith("ref: "):
            ref = head.removeprefix("ref: ").strip()
            status["branch"] = ref.split("/", maxsplit=2)[-1] or "unknown"
            ref_path = git_dir / ref
            if ref_path.is_file():
                status["commit"] = ref_path.read_text("utf-8").strip() or "unknown"
            return status
        status["branch"] = "detached"
        status["commit"] = head
        return status


class MCPAuthorityAdapter:
    """Translate MCP tool calls into governed authority operations."""

    _TOOL_ARGUMENTS = {
        "sovereignty_status": set(),
        "workspace_list": {"path"},
        "workspace_read": {"path"},
        "workspace_analyze": {"path"},
        "workspace_repo_status": set(),
    }
    _WORKSPACE_OPERATIONS = {
        "workspace_list": ProtectedOperation.WORKSPACE_LIST,
        "workspace_read": ProtectedOperation.WORKSPACE_READ,
        "workspace_analyze": ProtectedOperation.WORKSPACE_ANALYZE,
        "workspace_repo_status": ProtectedOperation.WORKSPACE_REPO_STATUS,
    }

    def __init__(
        self,
        *,
        workspace: Path,
        mode: str,
        authority: SovereignAuthority | None = None,
        workspace_executor: WorkspaceExecutor | None = None,
        audit_recorder: AuditRecorder | None = None,
    ) -> None:
        self.workspace = workspace.resolve()
        self.mode = mode
        self.authority = authority or self._build_default_authority()
        self.workspace_executor = workspace_executor or WorkspaceExecutor(self.workspace)
        self.audit_recorder = audit_recorder or AuditRecorder(self.authority.ledger)

    @staticmethod
    def _build_default_authority() -> SovereignAuthority:
        authority = SovereignAuthority(owner_id=os.environ.get("SG_MCP_OWNER_ID", "user:mcp"))
        authority.initialize()
        return authority

    def tools(self) -> list[dict[str, Any]]:
        return [
            self._tool("sovereignty_status", "Report local server security boundaries.", {}),
            self._tool(
                "workspace_list",
                "List non-hidden, non-sensitive files in the local workspace.",
                {"path": {"type": "string", "description": "Optional relative directory."}},
            ),
            self._tool(
                "workspace_read",
                "Read a bounded UTF-8 text file from the local workspace.",
                {"path": {"type": "string", "description": "Required relative file path."}},
                required=["path"],
            ),
            self._tool(
                "workspace_analyze",
                "Produce read-only syntax and whitespace diagnostics for a workspace file.",
                {"path": {"type": "string", "description": "Required relative file path."}},
                required=["path"],
            ),
            self._tool(
                "workspace_repo_status",
                "Report bounded repository status without exposing shell access.",
                {},
            ),
        ]

    @staticmethod
    def _tool(
        name: str, description: str, properties: dict[str, Any], required: list[str] | None = None
    ) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }
        if required:
            schema["required"] = required
        return {"name": name, "description": description, "inputSchema": schema}

    def call_tool(self, request_id: Any, params: dict[str, Any]) -> MCPCallResult:
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise ValueError("Tool name and arguments must be valid")
        allowed_arguments = self._TOOL_ARGUMENTS.get(name)
        if allowed_arguments is None:
            raise ValueError(f"Unknown tool: {name}")
        if set(arguments) - allowed_arguments:
            raise ValueError("Unsupported tool arguments")
        if name == "sovereignty_status":
            return MCPCallResult(
                {
                    "mode": self.mode,
                    "workspace": str(self.workspace),
                    "network": "disabled by this MCP server",
                    "credentials": "not accepted, stored, or transmitted",
                }
            )

        identity = self._coerce_identity(params.get("identity"))
        capability = self._coerce_capability(params.get("capability"))
        parent_capability = self._coerce_capability(params.get("parent_capability"))
        request = OperationRequest(
            operation=self._WORKSPACE_OPERATIONS[name],
            identity=identity,
            capability=capability,
            parent_capability=parent_capability,
            requester_id=identity.identity_id if identity is not None else "",
            resource_id=self._resource_id(name, arguments),
            metadata={"tool_name": name, "arguments": dict(arguments)},
        )
        decision = self.authority.authorize_operation(request)
        if not decision.allowed:
            denial = self._decision_payload(
                request_id=request_id,
                request=request,
                decision=decision,
                result="denied",
                failure_reason=decision.reason,
            )
            self.audit_recorder.record_mcp_operation(
                actor_id=request.requester_id or "anonymous",
                event_type="mcp.operation",
                payload=denial,
            )
            return MCPCallResult(denial, is_error=True)
        try:
            payload = self.workspace_executor.execute(name, arguments)
        except (OSError, UnicodeDecodeError, ValueError) as error:
            failure = self._decision_payload(
                request_id=request_id,
                request=request,
                decision=decision,
                result="error",
                failure_reason=str(error),
            )
            self.audit_recorder.record_mcp_operation(
                actor_id=request.requester_id or "anonymous",
                event_type="mcp.operation",
                payload=failure,
            )
            return MCPCallResult(failure, is_error=True)

        self.audit_recorder.record_mcp_operation(
            actor_id=request.requester_id or "anonymous",
            event_type="mcp.operation",
            payload=self._decision_payload(
                request_id=request_id,
                request=request,
                decision=decision,
                result="success",
            ),
        )
        return MCPCallResult(payload)

    @staticmethod
    def _resource_id(tool_name: str, arguments: dict[str, Any]) -> str:
        if tool_name == "workspace_repo_status":
            return "."
        return str(arguments.get("path", ".") or ".")

    @staticmethod
    def _coerce_identity(raw_identity: Any | None) -> IdentityContext | None:
        if raw_identity is None or isinstance(raw_identity, IdentityContext):
            return raw_identity
        if not isinstance(raw_identity, dict):
            raise ValueError("Identity context must be an object")
        identity_id = raw_identity.get("identity_id")
        verified = raw_identity.get("verified")
        device_id = raw_identity.get("device_id")
        if not isinstance(identity_id, str) or not identity_id:
            raise ValueError("Identity context requires a non-empty identity_id")
        if not isinstance(verified, bool):
            raise ValueError("Identity context requires a verified boolean")
        if device_id is not None and not isinstance(device_id, str):
            raise ValueError("Identity context device_id must be a string")
        metadata = raw_identity.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("Identity context metadata must be an object")
        return IdentityContext(
            identity_id=identity_id,
            device_id=device_id,
            verified=verified,
            metadata=dict(metadata),
        )

    @staticmethod
    def _coerce_capability(raw_capability: Any | None) -> CapabilityRecord | Any | None:
        if raw_capability is None or isinstance(raw_capability, CapabilityRecord):
            return raw_capability
        if not isinstance(raw_capability, dict):
            return raw_capability
        capability_id = raw_capability.get("capability_id")
        owner_identity = raw_capability.get("owner_identity")
        scopes = raw_capability.get("scopes")
        if not isinstance(capability_id, str) or not capability_id:
            raise ValueError("Capability requires a non-empty capability_id")
        if not isinstance(owner_identity, str) or not owner_identity:
            raise ValueError("Capability requires a non-empty owner_identity")
        if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
            raise ValueError("Capability scopes must be a list of strings")
        expires_at = raw_capability.get("expires_at")
        if expires_at is not None and not isinstance(expires_at, (str, int)):
            raise ValueError("Capability expires_at must be a string or integer timestamp")
        revoked = raw_capability.get("revoked", False)
        if not isinstance(revoked, bool):
            raise ValueError("Capability revoked must be a boolean")
        provider_id = raw_capability.get("provider_id")
        issuer_device = raw_capability.get("issuer_device")
        parent_capability_id = raw_capability.get("parent_capability_id")
        for value, label in (
            (provider_id, "provider_id"),
            (issuer_device, "issuer_device"),
            (parent_capability_id, "parent_capability_id"),
        ):
            if value is not None and not isinstance(value, str):
                raise ValueError(f"Capability {label} must be a string")
        return CapabilityRecord(
            capability_id=capability_id,
            owner_identity=owner_identity,
            scopes=frozenset(scopes),
            provider_id=provider_id,
            issuer_device=issuer_device,
            expires_at=expires_at,
            revoked=revoked,
            parent_capability_id=parent_capability_id,
        )

    @staticmethod
    def _decision_payload(
        *,
        request_id: Any,
        request: OperationRequest,
        decision,
        result: str,
        failure_reason: str | None = None,
    ) -> dict[str, Any]:
        identity_id = request.identity.identity_id if request.identity is not None else None
        return {
            "request_id": request_id,
            "operation": request.operation_name,
            "identity_id": identity_id,
            "capability_id": decision.capability_id,
            "policy_hash": decision.policy_hash,
            "decision": decision.reason_code,
            "result": result,
            "failure_reason": failure_reason,
        }
