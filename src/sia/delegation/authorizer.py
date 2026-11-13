"""
Delegation: authorizer.

Validates delegation tokens and authorizes delegated actions per
RFC-0015 semantics.
"""
from __future__ import annotations

from sia.delegation.models import DelegationToken
from sia.errors.exceptions import (
    DelegationExpiredError,
    DelegationInvalidError,
    DelegationRevokedError,
    DelegationScopeError,
)
from sia.errors import codes
from sia.errors.exceptions import SIAError

REQUIRED_TOKEN_FIELDS = {
    "token_id", "grantor_id", "grantee_id", "scope",
    "issued_at", "schema_version",
}


class DelegationAuthorizer:
    """
    Authorizer for delegation tokens.

    Maintains a registry of issued tokens and enforces delegation rules:
    - Tokens must not be expired or revoked.
    - Granted scope cannot exceed the parent's scope.
    - Chain depth cannot exceed DelegationToken.MAX_DEPTH.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, DelegationToken] = {}

    # ── Token lifecycle ───────────────────────────────────────────────────────

    def issue(
        self,
        token: DelegationToken,
        parent_scope: list[str] | None = None,
    ) -> DelegationToken:
        """
        Register and validate a new delegation token.

        If *parent_scope* is provided, the token's scope is validated
        against it. Raises on structural or scope violations.
        """
        self._validate_structure(token)
        if parent_scope is not None:
            self._validate_scope_subset(token.scope, parent_scope)
        if token.depth > DelegationToken.MAX_DEPTH:
            raise SIAError(
                codes.E_DELEGATION_CHAIN_TOO_DEEP,
                f"Depth {token.depth} exceeds maximum {DelegationToken.MAX_DEPTH}.",
            )
        self._tokens[token.token_id] = token
        return token

    def revoke(self, token_id: str) -> None:
        """Mark a token as revoked."""
        token = self._get(token_id)
        token.revoked = True

    # ── Authorization ─────────────────────────────────────────────────────────

    def authorize(self, token_id: str, action: str) -> None:
        """
        Assert that the token identified by *token_id* is valid and
        permits *action*.

        Raises an appropriate ``SIAError`` subclass on failure.
        """
        token = self._get(token_id)
        if token.revoked:
            raise DelegationRevokedError(f"Token '{token_id}' has been revoked.")
        if token.is_expired():
            raise DelegationExpiredError(f"Token '{token_id}' has expired.")
        if action not in token.scope and "*" not in token.scope:
            raise DelegationScopeError(
                f"Action '{action}' is not in the scope of token '{token_id}'."
            )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get(self, token_id: str) -> DelegationToken:
        try:
            return self._tokens[token_id]
        except KeyError:
            raise DelegationInvalidError(
                f"Token '{token_id}' is not registered."
            )

    @staticmethod
    def _validate_structure(token: DelegationToken) -> None:
        d = token.to_dict()
        missing = REQUIRED_TOKEN_FIELDS - d.keys()
        if missing:
            raise DelegationInvalidError(f"Missing fields: {missing}")
        if not d["token_id"]:
            raise DelegationInvalidError("'token_id' must not be empty.")
        if not isinstance(d["scope"], list):
            raise DelegationInvalidError("'scope' must be a list.")

    @staticmethod
    def _validate_scope_subset(
        child_scope: list[str], parent_scope: list[str]
    ) -> None:
        if "*" in parent_scope:
            return
        excess = set(child_scope) - set(parent_scope) - {"*"}
        if excess:
            raise DelegationScopeError(
                f"Delegation scope {excess} exceeds parent scope {parent_scope}."
            )

    def list_tokens(self, grantee_id: str | None = None) -> list[DelegationToken]:
        if grantee_id is None:
            return list(self._tokens.values())
        return [t for t in self._tokens.values() if t.grantee_id == grantee_id]
