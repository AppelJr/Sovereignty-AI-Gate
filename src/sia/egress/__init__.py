"""Portable protection for explicit cloud egress."""

from sia.egress.envelope import CloudEgressEnvelope, EgressEnvelopeError

__all__ = ["CloudEgressEnvelope", "EgressEnvelopeError"]
