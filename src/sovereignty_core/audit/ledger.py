"""Backward-compatible imports for the dedicated SCAR audit module."""

from sovereignty_core.audit.scar import (
    GENESIS_EVENT_HASH,
    SCARActor,
    SCARAttestation,
    SCAREvent,
    SCARLedger,
    SCARLedgerError,
    assert_scar_invariants,
)

__all__ = [
    "GENESIS_EVENT_HASH",
    "SCARActor",
    "SCARAttestation",
    "SCAREvent",
    "SCARLedger",
    "SCARLedgerError",
    "assert_scar_invariants",
]
