# Implementation Plan — RFC-002 Proof-Gated Authority

This document defines the implementation sequence for RFC-002. The codebase MUST follow this plan; the plan MUST NOT be redefined by downstream implementation PRs.

## Phase 1 — `src/sia/proofs/`

Create the core proof infrastructure as the single trust boundary for privileged authorization.

```text
src/sia/proofs/
├── __init__.py
├── base.py              # Abstract immutable Proof contract
├── verifier.py          # ProofVerifier
├── replay.py            # ReplayRegistry
├── models.py            # Bootstrap/Capability/Consent/Export/Import proofs
├── algorithms.py        # Signature algorithm abstraction (ML-DSA, Ed25519, etc.)
├── policy.py            # Scope and capability validation helpers
└── exceptions.py        # Domain-specific proof exceptions
```

### Responsibilities

#### `base.py`
Defines the immutable proof contract shared by every proof type.

Responsibilities:
- common proof fields
- canonical serialization
- signing document generation
- hash computation
- validation hooks

#### `models.py`
Defines the concrete proof types:
- `BootstrapProof`
- `CapabilityProof`
- `ConsentProof`
- `ExportProof`
- `ImportProof`

Each specialization MUST extend the shared proof contract and add only the fields unique to that authorization type.

#### `verifier.py`
Defines the centralized verification engine.

Verification pipeline:
1. structural validation
2. canonical serialization
3. signature verification
4. identity binding
5. device binding
6. capability validation
7. scope validation
8. expiration check
9. replay protection
10. return verified authorization context

All privileged code MUST call only `ProofVerifier`; proof objects MUST NOT verify themselves independently.

#### `replay.py`
Defines the replay prevention subsystem.

Tracks:
- `proof_id`
- `nonce`
- sequence number
- issuance time
- expiration
- revocation status

Provides:
- `register()`
- `is_replayed()`
- `consume()`
- `revoke()`
- `purge_expired()`

#### `algorithms.py`
Defines the pluggable signature backend.

Suggested interface:

```python
class SignatureAlgorithm(Protocol):
    name: str
    def sign(self, data: bytes, private_key: bytes) -> bytes: ...
    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool: ...
```

Initial implementations:
- ML-DSA-87
- Ed25519 (development/testing)
- future PQC algorithms without API changes

#### `policy.py`
Defines capability enforcement helpers.

Responsibilities:
- scope hierarchy
- least-privilege checks
- capability implication
- policy evaluation
- action authorization

#### `exceptions.py`
Defines the proof-specific exception hierarchy.

```text
ProofError
├── InvalidProofError
├── ExpiredProofError
├── ReplayDetectedError
├── SignatureVerificationError
├── ScopeViolationError
├── CapabilityViolationError
├── OwnerBindingError
├── DeviceBindingError
└── PolicyViolationError
```

## Phase 2 — `src/sia/authority/transaction.py`

Introduce the transactional privilege boundary.

Every privileged mutation MUST occur through:

```python
with authority.transaction(proof):
    ...
```

The transaction framework MUST:
1. verify the proof
2. verify replay state
3. verify policy
4. verify capability scope
5. emit `PROOF_VERIFIED`
6. begin transaction
7. perform mutation
8. emit SCAR lifecycle events
9. rebuild the Merkle root
10. generate signed attestation
11. verify post-state
12. commit

Any failure MUST abort the transaction.

## Phase 3 — `src/sia/memory/vault.py`

Replace the direct dictionary-backed memory store with a dedicated vault.

Required interface:
- `store()`
- `retrieve()`
- `search()`
- `delete()`
- `append()`
- `snapshot()`

The vault MUST:
- mediate every memory access
- enforce proof-gated reads and writes
- preserve memory classification semantics
- emit audit metadata through SCAR
- prevent direct dictionary bypasses

## Phase 4 — SCAR, Merkle, and attestation integration

Integrate the full post-verification chain:
- `PROOF_VERIFIED`
- transaction lifecycle events
- Merkle updates after every mutation
- signed attestations for every commit

The resulting history MUST be tamper-evident and independently verifiable.

## Phase 5 — Repository-wide proof requirements

Migrate all privileged APIs to require typed proof objects.

At minimum:
- `initialize()` → `BootstrapProof`
- `register_boundary()` → `CapabilityProof`
- `issue_delegation()` → `CapabilityProof`
- `revoke_delegation()` → `CapabilityProof`
- `store_memory()` → `ConsentProof`
- `read_memory()` → `CapabilityProof`
- `create_export()` → `ExportProof`
- `load_import()` → `ImportProof`
- `recover_identity()` → `RecoveryProof`

## Phase 6 — Repository invariants and regression tests

Add regression tests asserting:
- no state transition without verified proof
- no memory access without capability
- no export without export proof
- no import without import proof
- no replay of a valid proof
- every commit updates Merkle
- every commit generates attestation
- every proof generates SCAR event
- provider never obtains root authority
- provider never receives private keys
- vault is the only memory entry point

## Implementation Principle

RFC-002 is the specification. Implementation PRs MUST conform to it and MUST NOT redefine it.
