"""Gate authorizes. Genesis routes. DevAssist/Runtime execute. Evidence records.

Contracts only. Nothing here executes a tool or grants authority by itself.
Anything malformed or uncertain resolves to deny or escalate, never allow.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Optional

from .common import MODES, ContractError, check_digest, check_nonempty, digest

EXECUTING_ROUTES = ("devassist_local", "runtime_local", "runtime_external")
ROUTES = EXECUTING_ROUTES + ("deny", "escalate")
OUTCOMES = ("completed", "failed", "denied")


class _Contract:
    def to_dict(self) -> dict:
        return asdict(self)

    def digest(self) -> str:
        return digest(self.to_dict())


@dataclass(frozen=True)
class TaskEnvelope(_Contract):
    task_id: str
    requester: str
    intent: str
    scope: tuple
    mode: str
    created_at: str
    payload_hash: str

    def __post_init__(self):
        for f in ("task_id", "requester", "intent", "created_at"):
            check_nonempty(getattr(self, f), f)
        if self.mode not in MODES:
            raise ContractError(f"mode must be one of {MODES}")
        if not self.scope:
            raise ContractError("scope must not be empty")
        for p in self.scope:
            if not isinstance(p, str) or not p or p.startswith("/") or ".." in p.split("/"):
                raise ContractError(f"scope path not allowed: {p!r}")
        check_digest(self.payload_hash, "payload_hash")


@dataclass(frozen=True)
class GateAuthorization(_Contract):
    """Issued by the Gate only. Genesis can read it, never mint it."""
    auth_id: str
    task_id: str
    allowed: bool
    expires_at: float
    issued_by: str

    def is_valid_for(self, task_id: str, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return self.allowed is True and self.task_id == task_id and now < self.expires_at


@dataclass(frozen=True)
class RouteDecision(_Contract):
    decision_id: str
    task_id: str
    route: str
    mode: str
    reason: str
    gate_auth_id: Optional[str] = None
    owner_approval_id: Optional[str] = None
    external_target: Optional[str] = None

    def __post_init__(self):
        check_nonempty(self.decision_id, "decision_id")
        check_nonempty(self.task_id, "task_id")
        if self.route not in ROUTES:
            raise ContractError(f"route must be one of {ROUTES}")
        if self.mode not in MODES:
            raise ContractError(f"mode must be one of {MODES}")
        if self.route in EXECUTING_ROUTES and not self.gate_auth_id:
            raise ContractError("executing route requires gate_auth_id")
        if self.route == "runtime_external":
            if self.mode == "GHOST":
                raise ContractError("GHOST mode forbids external routes")
            if not self.external_target:
                raise ContractError("external route requires external_target")
            if self.mode == "HYBRID" and not self.owner_approval_id:
                raise ContractError("HYBRID external route requires owner_approval_id")


@dataclass(frozen=True)
class ExecutionReceipt(_Contract):
    receipt_id: str
    task_id: str
    decision_digest: str
    executor: str
    outcome: str
    finished_at: str
    output_hash: Optional[str] = None

    def __post_init__(self):
        for f in ("receipt_id", "task_id", "executor", "finished_at"):
            check_nonempty(getattr(self, f), f)
        check_digest(self.decision_digest, "decision_digest")
        if self.outcome not in OUTCOMES:
            raise ContractError(f"outcome must be one of {OUTCOMES}")
        if self.outcome == "completed":
            if not self.output_hash:
                raise ContractError("completed receipt requires output_hash")
            check_digest(self.output_hash, "output_hash")


@dataclass(frozen=True)
class HumanEscalationEvent(_Contract):
    event_id: str
    task_id: str
    raised_by: str
    reason: str
    requested_action: str
    created_at: str

    def __post_init__(self):
        for f in ("event_id", "task_id", "raised_by", "reason", "requested_action", "created_at"):
            check_nonempty(getattr(self, f), f)


def decide_route(
    envelope: TaskEnvelope,
    auth: Optional[GateAuthorization],
    requested_route: str,
    external_allowlist: frozenset = frozenset(),
    owner_approval_id: Optional[str] = None,
    external_target: Optional[str] = None,
    decision_id: str = "",
    now: Optional[float] = None,
) -> RouteDecision:
    """Fail closed. Missing, expired, mismatched, or denied authorization
    means deny. Genesis never invents authority."""
    def out(route, reason, **kw):
        return RouteDecision(
            decision_id or f"rd-{envelope.task_id}",
            envelope.task_id,
            route,
            envelope.mode,
            reason,
            **kw,
        )

    if requested_route not in EXECUTING_ROUTES:
        return out("deny", "requested route is not an executing route")
    if auth is None or not auth.is_valid_for(envelope.task_id, now):
        return out("deny", "no valid gate authorization")
    if requested_route == "runtime_external":
        if envelope.mode == "GHOST":
            return out("deny", "GHOST mode: no external transport")
        if external_target not in external_allowlist:
            return out("deny", "external target not on allowlist")
        if envelope.mode == "HYBRID" and not owner_approval_id:
            return out(
                "escalate",
                "HYBRID external route needs owner approval",
                gate_auth_id=auth.auth_id,
            )
        return out(
            "runtime_external",
            "authorized external route",
            gate_auth_id=auth.auth_id,
            owner_approval_id=owner_approval_id,
            external_target=external_target,
        )
    return out(requested_route, "authorized local route", gate_auth_id=auth.auth_id)
