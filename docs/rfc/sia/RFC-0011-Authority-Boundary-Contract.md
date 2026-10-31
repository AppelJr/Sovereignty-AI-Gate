# RFC-0011 — Authority Boundary Contract

**Status:** Reserved extension implemented.  
**Version:** 0.1.0  

## Abstract
RFC-0011 defines the authority-bearing boundary contract between a granted human authority context and governed execution components.

RFC-0011 is authority-bearing. It does not emit evidence; it authorizes validated transitions.

## Canonical Type

```text
AuthorityBoundaryContract.v1
```

## Lifecycle

```text
PROPOSED -> VALIDATED -> ACTIVE -> SUSPENDED -> REVOKED
```

## Required Fields

- authority_id
- scope
- issuer
- subject
- capabilities
- expiry
- policy_digest

## Failure Codes

| Code | Meaning |
|---|---|
| AUTH-001 | Missing authority identity |
| AUTH-002 | Invalid scope |
| AUTH-003 | Expired authority |
| AUTH-004 | Capability exceeds grant |
| AUTH-005 | Policy digest mismatch |

## Rules

- No implicit authority escalation.
- No execution without an active boundary.
- All state transitions must be deterministic.
