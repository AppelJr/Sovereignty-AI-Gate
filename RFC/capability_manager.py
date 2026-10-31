"""Explicit capability management for Sovereignty AI Gate.

Identity answers who is requesting.  This module answers what that identity may
 do, while the audit recorder provides evidence for the decision.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sia.audit.recorder import AuditRecorder
from sia.delegation.authorizer import DelegationAuthorizer
from sia.delegation.models import DelegationToken
from sia.errors.exceptions import (
    DelegationExpiredError,
    DelegationInvalidError,
    DelegationRevokedError,
    DelegationScopeError,
)


@dataclass(frozen=True)
class CapabilityGrant:
    """A delegation token plus its resource and constraint boundary."""

    token: DelegationToken
    resource_id: str | None = None
    constraints: dict[str, Any] | None = None

    @property
    def capability_id(self) -> str:
        return self.token.token_id

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.token.to_dict(),
            "resource_id": self.resource_id,
            "constraints": dict(self.constraints or {}),
        }


@dataclass(frozen=True)
class CapabilityDecision:
    """Auditable result of checking a capability against a request."""

    allowed: bool
    capability_id: str
    subject_id: str
    action: str
    resource_id: str | None
    reason_code: str
    reason: str
    evidence_sequence: int | None = None


class CapabilityManager:
    """Issue, revoke, and evaluate explicit least-privilege capabilities.

    The manager deliberately delegates token lifecycle validation to the
    existing ``DelegationAuthorizer`` and adds subject/resource binding plus
    auditable decisions. It does not create identity or cryptographic keys.
    """

    def __init__(
        self,
        *,
        owner_identity: str,
        authorizer: DelegationAuthorizer | None = None,
        recorder: AuditRecorder | None = None,
    ) -> None:
        if not owner_identity:
            raise ValueError("owner_identity must not be empty")
        self._owner_identity = owner_identity
        self._authorizer = authorizer or DelegationAuthorizer()
        self._recorder = recorder
        self._grants: dict[str, CapabilityGrant] = {}

    @property
    def owner_identity(self) -> str:
        return self._owner_identity

    def issue(
        self,
        *,
        capability_id: str,
        subject_id: str,
        scope: list[str],
        resource_id: str | None = None,
        expires_at: str | None = None,
        parent_capability_id: str | None = None,
        constraints: dict[str, Any] | None = None,
    ) -> CapabilityGrant:
        """Issue a root-owned or parent-delegated capability.

        A child grant may only be issued by the parent capability's grantee and
        may not exceed the parent's scope. The manager records successful
        issuance only after all validation succeeds.
        """
        if not capability_id or not subject_id:
            raise DelegationInvalidError("capability_id and subject_id are required")
        if not scope:
            raise DelegationInvalidError("capability scope must not be empty")
        if capability_id in self._grants:
            raise DelegationInvalidError(f"Capability '{capability_id}' already exists")

        parent: CapabilityGrant | None = None
        grantor_id = self._owner_identity
        depth = 0
        parent_scope: list[str] | None = None
        if parent_capability_id is not None:
            parent = self._get(parent_capability_id)
            grantor_id = parent.token.grantee_id
            depth = parent.token.depth + 1
            parent_scope = parent.token.scope
            if grantor_id != self._owner_identity and not parent.token.is_valid():
                raise DelegationInvalidError("Parent capability is not active")
            if parent.token.grantee_id != subject_id and subject_id == self._owner_identity:
                # A parent grants authority onward; the root cannot be used as a
                # child subject through an arbitrary parent token.
                raise DelegationScopeError("Child subject is not bound to parent grant")

        token = DelegationToken(
            token_id=capability_id,
            grantor_id=grantor_id,
            grantee_id=subject_id,
            scope=list(dict.fromkeys(scope)),
            expires_at=expires_at,
            depth=depth,
            parent_id=parent_capability_id,
        )
        issued = self._authorizer.issue(token, parent_scope=parent_scope)
        grant = CapabilityGrant(
            token=issued,
            resource_id=resource_id,
            constraints=dict(constraints or {}),
        )
        self._grants[capability_id] = grant
        self._record(
            "capability.issued",
            {
                "capability_id": capability_id,
                "subject_id": subject_id,
                "resource_id": resource_id,
                "scope": sorted(issued.scope),
                "parent_capability_id": parent_capability_id,
                "expires_at": expires_at,
            },
        )
        return grant

    def revoke(self, capability_id: str) -> None:
        """Revoke a capability and record the authority change."""
        grant = self._get(capability_id)
        self._authorizer.revoke(capability_id)
        self._record(
            "capability.revoked",
            {
                "capability_id": capability_id,
                "subject_id": grant.token.grantee_id,
                "resource_id": grant.resource_id,
            },
        )

    def authorize(
        self,
        *,
        capability_id: str,
        subject_id: str,
        action: str,
        resource_id: str | None = None,
    ) -> CapabilityDecision:
        """Evaluate a capability without raising for ordinary denial."""
        grant = self._get(capability_id)
        token = grant.token
        reason_code = "AUTHORIZED"
        reason = "Capability authorizes the requested action"
        allowed = True

        if token.grantee_id != subject_id:
            allowed = False
            reason_code = "SUBJECT_MISMATCH"
            reason = "Capability subject does not match requester"
        elif not token.is_valid():
            allowed = False
            reason_code = "CAPABILITY_INACTIVE"
            reason = "Capability is expired or revoked"
        elif grant.resource_id is not None and grant.resource_id != resource_id:
            allowed = False
            reason_code = "RESOURCE_MISMATCH"
            reason = "Capability is not bound to the requested resource"
        else:
            try:
                self._authorizer.authorize(capability_id, action)
            except DelegationExpiredError:
                allowed = False
                reason_code = "CAPABILITY_EXPIRED"
                reason = "Capability has expired"
            except DelegationRevokedError:
                allowed = False
                reason_code = "CAPABILITY_REVOKED"
                reason = "Capability has been revoked"
            except DelegationScopeError:
                allowed = False
                reason_code = "SCOPE_MISSING"
                reason = "Capability does not include the requested action"

        decision = CapabilityDecision(
            allowed=allowed,
            capability_id=capability_id,
            subject_id=subject_id,
            action=action,
            resource_id=resource_id,
            reason_code=reason_code,
            reason=reason,
        )
        sequence = self._record(
            "capability.authorization",
            {
                "capability_id": capability_id,
                "subject_id": subject_id,
                "action": action,
                "resource_id": resource_id,
                "allowed": allowed,
                "reason_code": reason_code,
            },
        )
        return CapabilityDecision(**{**decision.__dict__, "evidence_sequence": sequence})

    def get(self, capability_id: str) -> CapabilityGrant:
        return self._get(capability_id)

    def list(self, subject_id: str | None = None) -> list[CapabilityGrant]:
        grants = list(self._grants.values())
        if subject_id is None:
            return grants
        return [grant for grant in grants if grant.token.grantee_id == subject_id]

    def _get(self, capability_id: str) -> CapabilityGrant:
        try:
            return self._grants[capability_id]
        except KeyError as exc:
            raise DelegationInvalidError(
                f"Capability '{capability_id}' is not registered"
            ) from exc

    def _record(self, event_type: str, payload: dict[str, Any]) -> int | None:
        if self._recorder is None:
            return None
        entry = self._recorder.ledger.append(
            event_type,
            payload,
            actor_id=self._owner_identity,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        return entry.entry_id
