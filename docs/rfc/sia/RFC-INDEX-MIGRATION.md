# RFC Index and Migration Map

**Purpose**: This document explains the canonical RFC numbering for the Sovereignty AI Gate
(SIA) and records how any externally referenced numbers map to current canonical documents.
It is a living document that MUST be updated whenever an RFC is added, renumbered, superseded,
or retired.

---

## Foundation Layer (RFC-0014 – RFC-0020)

The RFCs below were produced by the first implementation sprint and form the **stable foundation**
of the SIA specification. They MUST NOT be deleted or renumbered. Later RFCs build on these.

| Canonical RFC | Title | Status |
|---|---|---|
| RFC-0013 | Root Boundary | Active |
| RFC-0014 | Memory Model | Active — state-machine expansion in progress |
| RFC-0015 | Delegation | Active |
| RFC-0016 | Conformance Harness | Active |
| RFC-0017 | Audit Ledger | Active |
| RFC-0018 | Export Bundle | Active |
| RFC-0019 | Import Bundle | Active — boundary layer expansion in progress |
| RFC-0020 | Compatibility | Active |

---

## Pre-Foundation Layer (RFC-0000 – RFC-0010)

These RFCs define the pipeline, authority lifecycle, and protocol invariants.

| Canonical RFC | Title | Status |
|---|---|---|
| RFC-0000 | Core Protocol | Proposed (reconciliation in progress) |
| RFC-0001 | Authority Lifecycle | Active |
| RFC-0002 | Pipeline Stage 2 | Active |
| RFC-0003 | Pipeline Stage 3 | Active |
| RFC-0004 | Pipeline Stage 4 | Active |
| RFC-0005 | Pipeline Stage 5 | Active |
| RFC-0006 | Pipeline Stage 6 | Active |
| RFC-0007 | Pipeline Stage 7 | Active |
| RFC-0008 | Pipeline Stage 8 | Active |
| RFC-0009 | Pipeline Stage 9 | Active |
| RFC-0010 | Pipeline Stage 10 | Active |

---

## New Specification Layer (RFC-0021+)

New specifications produced during architectural reconciliation are assigned numbers starting
at RFC-0021 so that they do not conflict with or "steal" foundation RFC numbers.

| Canonical RFC | Title | Status |
|---|---|---|
| RFC-0021 | Cryptographic Profile | Draft |
| RFC-0022 | Capability Grammar | Draft |

### Assignment reserved but not yet authored

| Reserved RFC | Intended Topic |
|---|---|
| RFC-0023 | Authority Type Registry (AuthorityTypeRegistry boundary) |
| RFC-0024 | Proof Verifier Protocol |

---

## Historical Namespace Clarification

The PR review raised concern that a "proof-gated authority specification" was being assigned
RFC-0002, which would conflict with the existing Pipeline Stage 2 document. This conflict is
resolved as follows:

- **RFC-0002** remains Pipeline Stage 2 (no change).
- The proof-gated authority specification is assigned **RFC-0021** (Cryptographic Profile)
  and **RFC-0022** (Capability Grammar) as separate focused documents.
- RFC-0020 remains the Compatibility RFC as originally written.

No existing RFC file is deleted or renumbered.

---

## Lifecycle Reference

All RFC lifecycle transitions follow the scheme defined in RFC-0000:

```
Draft → Proposed → Accepted → Active → Superseded → Retired
```

Changes to a document's status MUST be recorded in this index at the same time as the RFC file
is updated.
