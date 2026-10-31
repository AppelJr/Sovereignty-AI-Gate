# RFC-0000 — Sovereignty AI Gate Core Protocol

**Status:** Proposed Architecture Specification (reconciliation in progress — see RFC-INDEX-MIGRATION.md)  
**Version:** 0.1.0  
**Author:** Appel420  

## RFC Lifecycle

```
Draft → Proposed → Accepted → Active → Superseded → Retired
```

- **Draft**: under active authoring; not yet ready for review.
- **Proposed**: submitted for review; implementation may begin but is not authoritative.
- **Accepted**: approved; implementations MUST conform.
- **Active**: deployed and enforced in at least one conformance-tested release.
- **Superseded**: replaced by a later RFC; legacy implementations may remain for compatibility.
- **Retired**: no longer applicable; implementations MUST NOT rely on this RFC.


## Abstract

This RFC defines the foundational protocol for the Sovereignty AI Gate (SIA). It establishes
the authority model, identity semantics, initialization lifecycle, and the minimal invariants
that all subsequent RFCs build upon.

## Motivation

AI systems increasingly act on behalf of users but lack a verifiable, user-controlled trust
boundary. SIA establishes a human-rooted authority framework where every AI action is
traceable to an explicit, time-bounded, auditable human grant.

## Specification

### 1. Authority Initialization

A SIA instance MUST be explicitly initialized before any operation. The initialization
event MUST be recorded as the first entry in the audit ledger with `event_type = "authority.init"`.

### 2. Owner Identity

Every SIA instance has exactly one `owner_id`. The owner is the root of trust. All
boundaries registered by the instance inherit the `owner_id` as their `creator_id`.

### 3. Offline-First

All core operations MUST function without network access. External interoperability is
opt-in and uses signed, portable bundles.

### 4. Determinism

All cryptographic operations MUST be deterministic given the same inputs. `Math.random()` or
equivalent non-deterministic entropy sources are PROHIBITED in any authority pipeline code.

### 5. Proof Model

Proofs are **immutable data/evidence objects**. They carry cryptographic evidence of an
authority decision but do not themselves execute authoritative behavior.

- Proof objects MUST NOT expose a `.verify()` method that evaluates authorization.
- Proof evaluation is centralized in `ProofVerifier.verify(proof, context)`.
- A valid signature or hash NEVER by itself equals authority; evaluation of context is always required.

See the **Proof Matrix** in the authority lifecycle documentation for the full list of proof types
and their evaluation semantics.

### 6. SCAR Transaction Order

The canonical order for every authority-mutating SCAR transaction is:

1. Receive proof  
2. Verify proof (`ProofVerifier.verify(proof, context)`)  
3. Reserve audit sequence number  
4. Begin protected transaction  
5. Apply mutation  
6. Append SCAR events  
7. Update Merkle root  
8. Generate attestation  
9. Verify post-state  
10. Commit atomically  

**Failure semantics**: on any failure between steps 4 and 10, the protected state is rolled back
and a `TRANSACTION_ABORTED` audit event is appended before the rollback completes. This event is
written outside the failed transaction so that rollback itself is auditable without violating
atomicity of the original mutation.

## Conformance

Implementations MUST:
- [x] Initialize before any operation (`E_NOT_INITIALIZED` on violation)
- [x] Record an `authority.init` event as the first ledger entry
- [x] Populate `version` in the init event payload
- [x] Reject operations before initialization with `E0001`
- [ ] Centralize proof evaluation in `ProofVerifier.verify(proof, context)` (RFC-0020+)
- [ ] Follow the 10-step SCAR transaction order for all authority-mutating operations
