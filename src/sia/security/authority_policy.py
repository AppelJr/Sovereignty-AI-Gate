"""
Security: authority policy engine.

This module enforces the frozen authority boundary model.
Representation and transformation may proceed, but canonical authority
objects may only be minted by registered boundaries.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from sia.errors.exceptions import AuthorityFailure, PolicyDeniedError
from sia.security.boundary_registry import (
    CANONICAL_BOUNDARIES,
    ensure_boundary_registry_is_canonical,
    find_creator_for_type,
)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    matched_rule: str | None = None


class AuthorityPolicy:
    def __init__(self, policy: dict[str, Any]) -> None:
        self._default: str = policy.get("default", "deny")
        self._rules: list[dict[str, Any]] = policy.get("rules", [])

    def evaluate(self, request: dict[str, Any]) -> PolicyDecision:
        for rule in self._rules:
            if self._matches(rule.get("match", {}), request):
                effect = rule.get("effect", "deny")
                return PolicyDecision(
                    allowed=(effect == "allow"),
                    reason=f"Matched rule '{rule.get('id', '?')}'",
                    matched_rule=rule.get("id"),
                )
        return PolicyDecision(
            allowed=self._default == "allow",
            reason=f"No matching rule; default is '{self._default}'",
        )

    def enforce(self, request: dict[str, Any]) -> None:
        decision = self.evaluate(request)
        if not decision.allowed:
            raise PolicyDeniedError(decision.reason)

    @staticmethod
    def _matches(pattern: dict[str, Any], request: dict[str, Any]) -> bool:
        for key, value in pattern.items():
            if value == "*":
                continue
            if request.get(key) != value:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {"default": self._default, "rules": list(self._rules)}


def enforce_authority_creation_path(converter: Callable[[], object], *, rfc: str) -> object:
    ensure_boundary_registry_is_canonical()
    result = converter()
    boundary = find_creator_for_type(type(result))
    if boundary is None:
        return result
    raise AuthorityFailure(
        rfc=rfc,
        code="sia.error.unregistered_authority_creation",
        message=(
            f"{type(result).__name__} was produced outside {boundary.creator_rfc}"
        ),
    )
