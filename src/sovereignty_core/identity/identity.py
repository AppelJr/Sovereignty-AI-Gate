"""
Persistent human identity model for the Sovereign AI Memory Architecture.

This layer defines who owns authority. It does not generate keys, sign
objects, or store identity state in any provider-controlled system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import time
from typing import Any


class IdentityOwner(StrEnum):
    """Identity owner types supported by the foundation layer."""

    HUMAN = "HUMAN"


class AuthoritySource(StrEnum):
    """Authority roots allowed for human identity records."""

    ROOT_OF_TRUST = "ROOT_OF_TRUST"


@dataclass(frozen=True)
class DeviceBinding:
    """Binding between a human identity and a trusted device root."""

    device_id: str
    root_identity_id: str
    bound_at: int
    active: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RecoveryPolicy:
    """
    Declarative recovery metadata for a human-owned identity.

    Recovery execution belongs to higher layers or platform tooling.
    """

    policy_type: str = "manual"
    threshold: int = 1
    trusted_contacts: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.threshold < 1:
            raise ValueError("Recovery threshold must be at least 1")


@dataclass
class HumanIdentity:
    """
    Provider-independent human identity.

    Invariants:
    - owner == HUMAN
    - provider is None
    - authority_source == ROOT_OF_TRUST
    """

    identity_id: str
    display_name: str
    public_identity_key: str
    created_at: int = field(default_factory=lambda: int(time.time()))
    recovery_policy: RecoveryPolicy = field(default_factory=RecoveryPolicy)
    device_bindings: list[DeviceBinding] = field(default_factory=list)
    version: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)
    provider: None = None
    authority_source: AuthoritySource = AuthoritySource.ROOT_OF_TRUST
    owner: IdentityOwner = IdentityOwner.HUMAN

    def __post_init__(self) -> None:
        self.assert_invariants()

    def assert_invariants(self) -> None:
        """Validate the core SAMA identity invariants."""

        if self.owner is not IdentityOwner.HUMAN:
            raise ValueError("Identity owner must be HUMAN")
        if self.provider is not None:
            raise ValueError("Identity must remain provider-independent")
        if self.authority_source is not AuthoritySource.ROOT_OF_TRUST:
            raise ValueError("Identity authority source must be ROOT_OF_TRUST")

    def bind_device(self, binding: DeviceBinding) -> None:
        """Attach or refresh a trusted device binding."""

        self.device_bindings = [
            existing
            for existing in self.device_bindings
            if existing.device_id != binding.device_id
        ]
        self.device_bindings.append(binding)

    def deactivate_device(self, device_id: str) -> bool:
        """Deactivate a trusted device binding by device id."""

        updated = False
        bindings: list[DeviceBinding] = []
        for binding in self.device_bindings:
            if binding.device_id == device_id and binding.active:
                bindings.append(
                    DeviceBinding(
                        device_id=binding.device_id,
                        root_identity_id=binding.root_identity_id,
                        bound_at=binding.bound_at,
                        active=False,
                        metadata=dict(binding.metadata),
                    )
                )
                updated = True
            else:
                bindings.append(binding)
        self.device_bindings = bindings
        return updated

    def is_device_trusted(self, device_id: str) -> bool:
        """Return whether a device binding is present and active."""

        return any(
            binding.device_id == device_id and binding.active
            for binding in self.device_bindings
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable identity document."""

        return {
            "identity_id": self.identity_id,
            "display_name": self.display_name,
            "public_identity_key": self.public_identity_key,
            "created_at": self.created_at,
            "recovery_policy": {
                "policy_type": self.recovery_policy.policy_type,
                "threshold": self.recovery_policy.threshold,
                "trusted_contacts": list(self.recovery_policy.trusted_contacts),
                "metadata": dict(self.recovery_policy.metadata),
            },
            "device_bindings": [
                {
                    "device_id": binding.device_id,
                    "root_identity_id": binding.root_identity_id,
                    "bound_at": binding.bound_at,
                    "active": binding.active,
                    "metadata": dict(binding.metadata),
                }
                for binding in self.device_bindings
            ],
            "version": self.version,
            "metadata": dict(self.metadata),
            "provider": self.provider,
            "authority_source": self.authority_source.value,
            "owner": self.owner.value,
        }

    @classmethod
    def create(
        cls,
        *,
        identity_id: str,
        display_name: str,
        public_identity_key: str,
        recovery_policy: RecoveryPolicy | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "HumanIdentity":
        """Create a new human identity with default SAMA invariants."""

        return cls(
            identity_id=identity_id,
            display_name=display_name,
            public_identity_key=public_identity_key,
            recovery_policy=recovery_policy or RecoveryPolicy(),
            metadata=dict(metadata or {}),
        )
