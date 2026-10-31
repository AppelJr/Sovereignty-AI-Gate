# RFC-0022 — Capability Grammar

**Status:** Draft  
**Version:** 0.1.0  
**Author:** Appel420  

---

## Abstract

Defines the grammar and semantics of capability scope strings used in SIA delegation
tokens and authority gates. A capability scope string expresses what a grantee is
permitted to do, to what resource, and under what conditions.

---

## Motivation

The initial `CapabilityScope` enum defines scopes as opaque strings. As the system grows
it needs a compositional grammar so that scopes can be evaluated programmatically,
compared for subset relations, and audited unambiguously.

---

## Scope String Grammar

```
scope       ::= resource "." action ["." qualifier]
resource    ::= token
action      ::= token
qualifier   ::= token
token       ::= [a-z0-9_]+
wildcard    ::= "*"
```

Examples:

| Scope string | Meaning |
|---|---|
| `memory.read` | Read any memory record |
| `memory.write.confirmed` | Write a user-confirmed memory record |
| `memory.suggest` | Append an AI-suggested memory record (non-persistent) |
| `memory.delete` | Tombstone a memory record |
| `capability.issue` | Issue a new capability token |
| `capability.revoke` | Revoke an existing capability token |
| `delegation.grant` | Grant delegated authority to a sub-grantee |
| `delegation.revoke` | Revoke a delegated grant |
| `audit.read` | Read SCAR audit events |
| `export.bundle` | Produce an export bundle |
| `import.bundle` | Consume an import bundle |
| `policy.read` | Read policy definitions |
| `policy.mutate` | Modify policy definitions (authority-bearing) |
| `identity.read` | Read identity records |
| `*` | Full owner wildcard — MUST NOT be delegated to non-owner |

---

## Scope Tiers

Scopes are organized into tiers. A grantee MUST NOT receive a scope from a tier higher
than the grantee's trust level.

| Tier | Label | Delegatable to AI? | Examples |
|---|---|---|---|
| 0 | Owner | Never | `*`, `identity.*`, `capability.revoke` |
| 1 | Privileged | Human-explicit only | `policy.mutate`, `delegation.grant`, `export.bundle` |
| 2 | Standard | Human-confirmed | `memory.write.confirmed`, `capability.issue`, `import.bundle` |
| 3 | Restricted | AI-assisted | `memory.suggest`, `memory.read`, `audit.read` |

---

## Policy Mutation is Authority-Bearing

`policy.mutate` is **Tier 1 (Privileged)** and is treated as an authority-bearing scope.
This means:

- It requires a `PolicyProof` evaluated by `ProofVerifier.verify(proof, context)`.
- Issuance of a capability including `policy.mutate` MUST be recorded as a SCAR event
  with actor `HUMAN`.
- A capability with `policy.mutate` MUST NOT be granted to a Tier-3 or lower grantee.

---

## Subset Evaluation

A scope set `S` is a subset of scope set `P` (parent) if every scope in `S` is covered
by at least one scope in `P`, where:

- An exact match covers a scope.
- A prefix wildcard `resource.*` in `P` covers any `resource.action[.qualifier]` in `S`.
- The top-level wildcard `*` in `P` covers any scope in `S`.
- No upward expansion is permitted; `P` can never be derived from `S`.

Subset evaluation MUST be used to validate delegation depth: a delegatee's scope set
MUST be a strict subset of the delegator's scope set.

---

## AuthorityTypeRegistry Boundary

Exact-type enforcement applies **only** to authority-bearing value objects. These are
objects that carry an evaluated authority grant. The registry boundary is planned for
RFC-0023 (AuthorityTypeRegistry).

The following object types are **NOT** subject to exact-type enforcement by the registry:

- Proof data objects (they carry evidence, not authority)
- Serializers and deserializers
- Audit events and SCAR records
- Export/import bundle representations

---

## Existing Scope Mapping

The table below maps the existing `CapabilityScope` enum values to the new grammar:

| Enum value | New scope string | Tier |
|---|---|---|
| `READ_PREFERENCE` | `memory.read.preference` | 3 |
| `READ_CONTEXT_WINDOW` | `memory.read.context` | 3 |
| `APPEND_MEMORY_SUGGESTION` | `memory.suggest` | 3 |
| `WRITE_CONFIRMED_MEMORY` | `memory.write.confirmed` | 2 |
| `ROOT_ACCESS` | `*` | 0 (forbidden to delegate) |
| `ADMIN_MEMORY_ACCESS` | `memory.*` | 0 (forbidden to delegate) |
| `EXPORT_VAULT` | `export.bundle` | 1 |
| `EXPORT_PRIVATE_KEYS` | `identity.export.keys` | 0 (forbidden) |
| `MINT_IDENTITY` | `identity.mint` | 0 (forbidden) |

The enum values are preserved for backward compatibility. New code SHOULD use scope
strings; the enum is a legacy alias layer.

---

## Conformance

Implementations MUST:
- [ ] Accept scope strings matching the grammar above
- [ ] Reject scope strings that do not match the grammar
- [ ] Enforce tier constraints when delegating
- [ ] Evaluate `policy.mutate` as authority-bearing (requires `PolicyProof`)
- [ ] Evaluate delegation scope as a strict subset of the delegator's scope
- [ ] Record capability issuance that includes Tier 0–1 scopes as SCAR `CAPABILITY_ISSUED` events with actor `HUMAN`
