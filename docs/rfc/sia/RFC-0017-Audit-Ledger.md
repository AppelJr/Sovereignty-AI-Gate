# RFC-0017 — Audit Ledger

**Status:** Active  
**Version:** 0.1.0  

## Abstract

Defines the append-only, hash-chained audit ledger for all authority events.

## Specification

### Chain Hash

```
H_0 = SHA3-512(GENESIS_HASH || canonical_json(entry_0))
H_n = SHA3-512(H_{n-1} || canonical_json(entry_n))
```

Where `GENESIS_HASH = "0" * 128`.

### LedgerEntry Schema

```json
{
  "entry_id": 0,
  "event_type": "<string>",
  "payload": {},
  "actor_id": "<string>",
  "timestamp": "<ISO-8601>",
  "prev_hash": "<hex-128>",
  "entry_hash": "<hex-128>"
}
```

### Tamper Detection

`verify_chain()` MUST detect:
1. Entries where `entry_hash` does not match `SHA3-512(to_dict())`.
2. Entries where `prev_hash` does not match the preceding entry's `entry_hash`.

## Conformance

All assertions in `tests/conformance/test_rfc0017_audit_ledger.py` MUST pass.
