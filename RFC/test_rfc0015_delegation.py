"""
RFC-0015: Delegation conformance tests.

Tests delegation issuance, scope enforcement, expiry, revocation,
and chain depth limits.
"""
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from sia.delegation.models import DelegationToken
from sia.delegation.authorizer import DelegationAuthorizer
from sia.errors.exceptions import (
    DelegationExpiredError,
    DelegationInvalidError,
    DelegationRevokedError,
    DelegationScopeError,
)
from sia.errors import codes
from sia.errors.exceptions import SIAError

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def authorizer():
    return DelegationAuthorizer()


def test_valid_delegation_fixture():
    data = json.loads((FIXTURES / "valid_delegation.json").read_text())
    token = DelegationToken.from_dict(data)
    a = DelegationAuthorizer()
    a.issue(token)
    a.authorize(token.token_id, "memory.read")  # must not raise


def test_delegation_issue_and_authorize(authorizer):
    token = DelegationToken(
        token_id="t001",
        grantor_id="user:alice",
        grantee_id="model:gpt4",
        scope=["memory.read"],
    )
    authorizer.issue(token)
    authorizer.authorize("t001", "memory.read")


def test_delegation_scope_denied(authorizer):
    token = DelegationToken(
        token_id="t002",
        grantor_id="user:alice",
        grantee_id="model:gpt4",
        scope=["memory.read"],
    )
    authorizer.issue(token)
    with pytest.raises(DelegationScopeError):
        authorizer.authorize("t002", "memory.write")


def test_delegation_revocation(authorizer):
    token = DelegationToken(
        token_id="t003",
        grantor_id="user:alice",
        grantee_id="model:gpt4",
        scope=["*"],
    )
    authorizer.issue(token)
    authorizer.revoke("t003")
    with pytest.raises(DelegationRevokedError):
        authorizer.authorize("t003", "memory.read")


def test_delegation_expiry(authorizer):
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    token = DelegationToken(
        token_id="t004",
        grantor_id="user:alice",
        grantee_id="model:gpt4",
        scope=["*"],
        expires_at=past,
    )
    authorizer.issue(token)
    with pytest.raises(DelegationExpiredError):
        authorizer.authorize("t004", "memory.read")


def test_delegation_scope_exceeds_parent(authorizer):
    token = DelegationToken(
        token_id="t005",
        grantor_id="user:alice",
        grantee_id="model:gpt4",
        scope=["memory.read", "memory.write"],
    )
    with pytest.raises(DelegationScopeError):
        authorizer.issue(token, parent_scope=["memory.read"])


def test_delegation_chain_depth_exceeded(authorizer):
    token = DelegationToken(
        token_id="t006",
        grantor_id="user:alice",
        grantee_id="model:gpt4",
        scope=["*"],
        depth=DelegationToken.MAX_DEPTH + 1,
    )
    with pytest.raises(SIAError) as exc_info:
        authorizer.issue(token)
    assert exc_info.value.code == codes.E_DELEGATION_CHAIN_TOO_DEEP


def test_delegation_wildcard_authorizes_any(authorizer):
    token = DelegationToken(
        token_id="t007",
        grantor_id="user:alice",
        grantee_id="model:gpt4",
        scope=["*"],
    )
    authorizer.issue(token)
    authorizer.authorize("t007", "any.action.at.all")


def test_delegation_roundtrip():
    token = DelegationToken(
        token_id="t008",
        grantor_id="user:alice",
        grantee_id="model:gpt4",
        scope=["memory.read"],
    )
    restored = DelegationToken.from_dict(token.to_dict())
    assert restored.token_id == token.token_id
    assert restored.scope == token.scope
