"""Identity and trust-boundary primitives for SAMA."""

from sovereignty_core.identity.identity import (
    AuthoritySource,
    DeviceBinding,
    HumanIdentity,
    IdentityOwner,
    RecoveryPolicy,
)
from sovereignty_core.identity.root_of_trust import (
    DeviceIdentity,
    RootOfTrust,
    SignedObject,
    SoftwareTrustBackend,
    TrustBackend,
)

__all__ = [
    "AuthoritySource",
    "DeviceBinding",
    "DeviceIdentity",
    "HumanIdentity",
    "IdentityOwner",
    "RecoveryPolicy",
    "RootOfTrust",
    "SignedObject",
    "SoftwareTrustBackend",
    "TrustBackend",
]
