# RFC-0020 — Compatibility

**Status:** Active  
**Version:** 0.1.0  

## Abstract

Defines compatibility requirements between SIA instances: that export bundles produced
by one instance can be successfully imported by another.

## Specification

Two SIA instances are compatible if:
1. They share the same export/import schema version.
2. The consuming instance can verify the producer's signature (requires key exchange).
3. All RFC-0013 through RFC-0019 conformance tests pass on both instances.

## Cross-Instance Test

The `test_rfc0020_compatibility.py` test validates a full producer → consumer pipeline
using two independent `SovereignAuthority` instances.

## Conformance

- Full compatibility pipeline MUST complete without errors.
- Consumer ledger after import MUST contain exactly `init + import` events.
