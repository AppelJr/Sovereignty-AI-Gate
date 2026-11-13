"""
Security: boundary registry.

Canonical registry of authority-producing boundaries.

This module implements the frozen SIA governance model:
- exact-type authority registration
- explicit RFC ownership
- one canonical creator per authority type
- transformer / creator disjointness
- no conversion from representation into authority
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Type

from sia.errors import codes
from sia.errors.exceptions import (
    AuthorityFailure,
    CreatorLockedError,
    RegistryDuplicateError,
    RegistryNotFoundError,
    SIAError,
)

# ── Type alias ─────────────────────────────────────────────────────────────────

BoundaryType = str  # "creator" | "transformer" | "reader" | "delegate"


# ── Record ─────────────────────────────────────────────────────────────────────

@dataclass
class BoundaryRecord:
    """A registered authority boundary."""

    boundary_id: str
    model_id: str
    boundary_type: BoundaryType
    creator_id: str
    scope: list[str]
    active: bool = True


# ── Registry ───────────────────────────────────────────────────────────────────

class BoundaryRegistry:
    """Runtime registry of authority boundaries."""

    def __init__(self) -> None:
        self._records: dict[str, BoundaryRecord] = {}

    def register(
        self,
        boundary_id: str,
        model_id: str,
        boundary_type: BoundaryType,
        creator_id: str,
        scope: list[str],
    ) -> BoundaryRecord:
        """Register a new boundary; raises RegistryDuplicateError if it already exists."""
        if boundary_id in self._records:
            raise RegistryDuplicateError()
        record = BoundaryRecord(
            boundary_id=boundary_id,
            model_id=model_id,
            boundary_type=boundary_type,
            creator_id=creator_id,
            scope=list(scope),
        )
        self._records[boundary_id] = record
        return record

    def get(self, boundary_id: str) -> BoundaryRecord:
        """Return a boundary record; raises RegistryNotFoundError if missing."""
        if boundary_id not in self._records:
            raise RegistryNotFoundError()
        return self._records[boundary_id]

    def list_active(self) -> list[BoundaryRecord]:
        """Return all active boundary records."""
        return [r for r in self._records.values() if r.active]

    def list_for_model(self, model_id: str) -> list[BoundaryRecord]:
        """Return all active records for a given model."""
        return [r for r in self._records.values() if r.active and r.model_id == model_id]

    def deactivate(self, boundary_id: str) -> None:
        """Mark a boundary as inactive."""
        record = self.get(boundary_id)
        record.active = False

    def update_scope(self, boundary_id: str, scope: list[str]) -> None:
        """Update the scope of an existing boundary without changing its creator."""
        record = self.get(boundary_id)
        record.scope = list(scope)

    def assert_creator_locked(self, boundary_id: str, creator_id: str) -> None:
        """Raise CreatorLockedError if *creator_id* differs from the registered creator."""
        record = self.get(boundary_id)
        if record.creator_id != creator_id:
            raise CreatorLockedError()

    def assert_no_conversion(self, boundary_id: str, new_type: BoundaryType) -> None:
        """Raise SIAError if *new_type* differs from the boundary's registered type."""
        record = self.get(boundary_id)
        if record.boundary_type != new_type:
            raise SIAError(
                code=codes.E_REGISTRY_CONVERSION_DENIED,
                message=(
                    f"boundary {boundary_id!r}: conversion from "
                    f"{record.boundary_type!r} to {new_type!r} is not permitted"
                ),
            )


# ── Canonical governance model ─────────────────────────────────────────────────

@dataclass(frozen=True)
class BoundaryDefinition:
    boundary_type: Type
    owning_rfc: str
    success_type: Type
    rejection_type: Type
    creator_rfc: str
    creator: Callable
    requires_exact_type: bool = True


# NOTE: These imports are intentionally local to avoid circular import issues
# in module loading. The canonical boundaries are declared as concrete runtime
# registrations in the governance layer.
CANONICAL_BOUNDARIES: tuple[BoundaryDefinition, ...] = ()


def find_creator_for_type(output_type: type) -> BoundaryDefinition | None:
    for boundary in CANONICAL_BOUNDARIES:
        if boundary.success_type is output_type:
            return boundary
    return None


def ensure_boundary_registry_is_canonical() -> None:
    creators: dict[type, str] = {}
    for boundary in CANONICAL_BOUNDARIES:
        if boundary.creator_rfc != boundary.owning_rfc:
            raise AuthorityFailure(
                rfc=boundary.owning_rfc,
                code="sia.error.boundary.creator_rfc_mismatch",
                message="creator RFC must equal owning RFC",
            )
        if boundary.success_type in creators:
            raise AuthorityFailure(
                rfc=boundary.owning_rfc,
                code="sia.error.boundary.duplicate_creator",
                message="canonical authority type has multiple creators",
            )
        creators[boundary.success_type] = boundary.creator_rfc


def enforce_no_implicit_authority_conversion(converter: Callable[[], object], *, rfc: str) -> object:
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
