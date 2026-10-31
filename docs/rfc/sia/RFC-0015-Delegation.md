# RFC-0015 — Delegation

**Status:** Active  
**Version:** 0.1.0  

## Abstract

Defines the delegation model: how a user grants a subset of authority to an AI model,
and the rules governing scope, depth, expiry, and revocation.

## Specification

### DelegationToken Schema (v1.0)

```json
{
  "schema_version": "1.0",
  "token_id": "<string>",
  "grantor_id": "<string>",
  "grantee_id": "<string>",
  "scope": ["<action>", ...],
  "issued_at": "<ISO-8601>",
  "expires_at": "<ISO-8601> | null",
  "depth": 0,
  "revoked": false,
  "parent_id": "<token_id> | null"
}
```

### Rules

- Scope cannot exceed parent scope.
- `depth` cannot exceed `MAX_DEPTH` (4).
- Revoked tokens raise `E_DELEGATION_REVOKED`.
- Expired tokens raise `E_DELEGATION_EXPIRED`.
- Scope violation raises `E_DELEGATION_SCOPE_EXCEEDED`.

## Conformance

All assertions in `tests/conformance/test_rfc0015_delegation.py` MUST pass.
