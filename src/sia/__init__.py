"""
Sovereignty AI Gate (SIA) — User-rooted authority framework.

This package provides deterministic, offline-first AI governance:
authority management, delegation, conformance, memory, audit, and
import/export of signed authority bundles.
"""

from sia.authority import SovereignAuthority
from sia.authority_gate import (
    AuthorizationDecision,
    AuthorizedContextPacket,
    IdentityContext,
    LocalAuthorityProbeProvider,
    OperationRequest,
    ProtectedOperation,
)

__all__ = [
    "AuthorizationDecision",
    "AuthorizedContextPacket",
    "IdentityContext",
    "LocalAuthorityProbeProvider",
    "OperationRequest",
    "ProtectedOperation",
    "SovereignAuthority",
]
__version__ = "0.1.0"
