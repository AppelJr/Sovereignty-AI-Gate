# SBP-0000 — Core Principles and Terminology

**Status:** Draft  
**Version:** 0.1.0  
**Applies to:** Sovereign Branch Protocol (SBP)

---

## 1. Abstract

The Sovereign Branch Protocol (SBP) defines a minimal, implementation-independent framework for sovereign computing. SBP separates authority, storage, synchronization, execution, and publication into independent protocol concerns while preserving user-controlled ownership anchored in Root Authority.

SBP is local-first by default, cryptographically verifiable, and transport/storage neutral.

---

## 2. Normative Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119 and RFC 8174.

---

## 3. Goals

SBP has five primary goals:

1. Preserve user ownership of digital assets.
2. Enable interoperable implementations across languages and platforms.
3. Enforce local-first authority by default.
4. Prevent vendor lock-in via replaceable components.
5. Ensure cryptographic verifiability of authority and history.

---

## 4. Non-Goals

SBP does not define:

- user interface requirements,
- programming language APIs,
- cloud provider preferences,
- operating system requirements,
- business models,
- model-vendor behavior.

These are implementation-level choices.

---

## 5. Core Axioms

### SBP-A1 — User Sovereignty

The Root Authority SHALL be the sole cryptographic source of authority.

No implementation, storage provider, service, or third party SHALL supersede, revoke, escrow, or assume Root Authority without explicit cryptographic delegation by the Root owner.

### SBP-A2 — Local Authority

Authoritative state SHALL reside on user-controlled hardware unless explicitly delegated otherwise by Root policy.

Replicated copies SHALL NOT become authoritative solely by synchronization.

### SBP-A3 — Branch Isolation

Each Branch SHALL maintain:

- independent derived cryptographic material,
- independent policy scope,
- independent audit history,
- independent object namespace.

Compromise of one Branch SHALL NOT imply compromise of sibling branches.

### SBP-A4 — Storage Neutrality

SBP defines storage semantics, not storage vendors.

Conforming implementations SHALL be able to replace storage adapters without changing object identity, authority ownership, or audit semantics.

### SBP-A5 — Transport Neutrality

SBP objects SHALL be transport-independent.

The protocol SHALL NOT require HTTP or any specific network stack.

### SBP-A6 — Cryptographic Portability

All cryptographic protocol objects SHALL have:

- canonical serialization,
- deterministic encoding,
- published test vectors,
- language-independent verification behavior.

Equivalent inputs across conforming implementations SHALL produce equivalent outputs.

### SBP-A7 — Explicit Egress

No protected object SHALL leave an authority boundary without explicit authorization.

Cloud or third-party storage SHALL receive no implicit authority.

### SBP-A8 — Auditability

Authority-changing operations SHALL produce append-only cryptographically verifiable audit events.

Deletion or mutation of accepted audit history is not a protocol operation.

### SBP-A9 — Operational Truthfulness

Production behavior SHALL accurately represent operational reality.

Production systems SHALL NOT expose simulated success, placeholder production flows, or deceptive status reporting.

Test doubles MAY exist only in isolated test environments.

### SBP-A10 — Replaceability

Identity, authority, storage, sync, execution, and provider integrations SHALL remain independently replaceable.

Replacing one component SHALL NOT require replacing another.

### SBP-A11 — Provider Independence

**Objective:** Preserve protocol interoperability and implementation portability.

Core protocol operations MUST NOT require any specific external AI provider, cloud service, identity provider, or compute vendor.

Provider integrations MUST be implemented as replaceable adapters behind a stable interface.

Canonical SBP objects MUST NOT contain provider-specific fields.

Implementations MAY include provider metadata outside canonical protocol objects provided it does not affect protocol semantics.

### SBP-A12 — Explicit Egress Governance

**Objective:** Make all external communication intentional and auditable.

Network egress MUST be denied by default.

External requests MUST require explicit authorization through implementation policy.

Every authorized external request MUST generate an auditable event.

Implementations SHOULD identify the destination, purpose, timestamp, and requesting component for each authorized egress event.

### SBP-A13 — Local Authority

**Objective:** Define the authoritative state.

Local persistent state MUST be the authoritative state for protocol operation.

External services MAY provide computation, synchronization, or replication.

External services MUST NOT become the authoritative source for protocol state unless explicitly defined by a separate deployment profile.

Loss of external connectivity MUST NOT invalidate locally committed protocol state.

### SBP-A14 — Portable Data

Export formats MUST be publicly documented.

Export formats MUST be verifiable.

Export formats SHOULD remain independent of any single provider or implementation.

### SBP-A15 — Transparent External Dependencies

All configured external endpoints MUST be discoverable through implementation configuration.

Hidden or undocumented network destinations MUST NOT be required for compliant implementations.

Implementations SHOULD expose an audit mechanism that identifies external destinations contacted during protocol execution.

---

## 6. Terminology

- **Root Authority**: the top-level cryptographic authority anchor.
- **Branch**: a cryptographically isolated authority and policy namespace derived from a Root.
- **Canonical Object**: a deterministic, serializable object covered by protocol hashing/signing rules.
- **Storage Adapter**: implementation that satisfies SBP storage semantics for a backend.
- **Synchronization**: replication and reconciliation of protocol objects between peers/adapters.
- **Egress**: explicit authorization to move protected state outside an authority boundary.
- **Audit Event**: append-only, hash-linked record proving an authority-relevant operation.

---

## 7. Layer Model

Conforming implementations SHALL preserve this conceptual ordering:

```text
Root Authority
      ↓
Branch Protocol
      ↓
Canonical Object Model
      ↓
Storage Adapter
      ↓
Synchronization
      ↓
Optional Egress
```

Cloud infrastructure, where used, is a replication and transport substrate rather than an ownership authority.

---

## 8. Compliance Baseline

An implementation claiming **SBP Core** conformance MUST implement all axioms in this document.

Further capability claims (e.g., storage, sync, audit proofs, AI branch constraints, egress envelopes) SHOULD reference additional SBP documents and conformance suites.

---

## 9. Security and Privacy Notes

This document defines invariants, not concrete algorithms.

Algorithm choices (e.g., signature suites, KDFs, envelope encryption) MUST be specified in downstream SBP specifications with test vectors and interoperability criteria.

---

## 10. Next Specifications

This document is intended to precede at minimum:

- SBP-0001 Root Authority
- SBP-0002 Branch Protocol
- SBP-0003 Canonical Object Model
- SBP-0004 Storage Semantics
- SBP-0005 Synchronization
- SBP-0006 Egress Envelope
- SBP-0007 Audit Proofs

---

## 11. Protocol Stability Policy (Initial)

SBP specifications SHOULD classify changes as:

- **Core**: breaking changes require major version increment.
- **Stable**: backward-compatible extensions only.
- **Experimental**: non-required, subject to change.
- **Deprecated**: retained for transition period before removal.

This policy helps preserve interoperability while allowing controlled evolution.
