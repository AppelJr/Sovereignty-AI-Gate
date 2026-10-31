# RFC-0012 — Extension Registry Contract

**Status:** Reserved extension implemented.  
**Version:** 0.1.0  

## Abstract
RFC-0012 defines deterministic registration and validation of future protocol extensions.

RFC-0012 is authority-bearing for extension admission rules. Extension artifacts themselves remain evidence-bearing when emitted.

## Canonical Type

```text
ExtensionRegistryEntry.v1
```

## Lifecycle

```text
REQUESTED -> REVIEWED -> ACCEPTED -> ACTIVE -> DEPRECATED
```

## Required Fields

- extension_id
- version
- owner
- schema_digest
- compatibility_range
- activation_policy

## Failure Codes

| Code | Meaning |
|---|---|
| EXT-001 | Duplicate extension id |
| EXT-002 | Invalid schema digest |
| EXT-003 | Unsupported compatibility range |
| EXT-004 | Missing activation policy |
| EXT-005 | Unauthorized extension owner |

## Rules

- Registry changes require deterministic validation.
- Extensions cannot override core authority semantics.
- Evidence records reference registry state but do not replace it.
