# RFC-002 — Proof-Gated Authority

- **Status:** Draft
- **Author:** Derek Appel
- **Repository:** Appel420/Sovereignty-AI-Gate
- **Requires:** RFC-001 (SAMA)
- **Version:** 0.1.0

## 1. Abstract

RFC-002 defines the mandatory authorization model for every privileged operation within the Sovereign AI ecosystem.

No operation that modifies sovereign state may execute solely because a caller possesses a reference to an object or method. Authority exists only through successful verification of a cryptographic proof.

This RFC establishes proofs — not APIs — as the authoritative security boundary.

## 2. Motivation

RFC-001 establishes that the human owns identity, memory, and continuity. RFC-002 defines how privileged actions are authorized in support of that ownership.

A repository that stores identity, memory, delegation, audit history, exports, and imports must not rely on implicit trust in object construction, method invocation, or caller identity strings. Those patterns are convenient, but they are not sufficient to establish a verifiable trust boundary.

Proof-gated authority makes the security model explicit, testable, and independently auditable. It also ensures that future modules follow a single authorization contract instead of inventing local variations that drift over time.

## 3. Scope

This RFC applies to every module, subsystem, and future extension in the repository that can affect sovereign state.

It covers, at minimum:

- identity
- root of trust
- memory vault
- SCAR ledger and audit records
- Merkle commitments and attestations
- capabilities and delegations
- exports and imports
- policy and trust registry state
- provider bindings
- recovery metadata

This RFC does not define the cryptographic algorithms themselves, but it does require that any chosen implementation provide verifiable proof semantics, replay resistance, and object binding.

## 4. Terminology

- **Proof**: a cryptographically verifiable authorization artifact that binds a human identity to a specific action, object, scope, and validity window.
- **Proof verifier**: the centralized subsystem responsible for validating proofs.
- **Authority transaction**: an atomic mutation context in which a verified proof authorizes a privileged state change.
- **Replay protection**: mechanisms that prevent re-use of a proof beyond its intended lifecycle.
- **SCAR**: sovereign change audit record; an immutable event emitted when proof verification or privileged mutation occurs.
- **Merkle attestation**: a cryptographic commitment that anchors ledger or state transitions in a verifiable tree structure.
- **Memory vault**: the sole enforcement boundary for persistent memory operations.
- **Protected state**: any state whose mutation requires a successfully verified proof.

## 5. Normative Language

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are to be interpreted as described in RFC 2119.

Where this RFC uses normative language, it defines repository requirements, not suggestions.

## 6. Core Invariant

For every privileged state transition:

**Method invocation alone is never authority.**

Authority is established only after successful verification of a valid proof bound to:

- the human identity
- the trusted device
- the requested capability
- the affected object
- the requested operation
- a bounded validity period
- replay protection

No state transition affecting identity, authority, memory, audit, import, export, delegation, or vault state MAY occur without successful proof verification.

## 7. Protected State

Proof verification is REQUIRED before modifying any of the following:

- Identity
- Root of Trust
- Memory Vault
- SCAR Ledger
- Merkle Tree
- Audit Records
- Capabilities
- Delegations
- Exports
- Imports
- Policy
- Trust Registry
- Provider Bindings
- Recovery Metadata

A protected state transition MUST be treated as unauthorized unless a proof has been successfully verified for that exact transition.

## 8. Proof Model

Every proof SHALL derive from a single immutable base type.

```python
@dataclass(frozen=True)
class Proof:
    proof_id: str
    owner_id: str
    device_id: str
    issued_at: int
    expires_at: int
    nonce: str
    signature: bytes

    def verify(self) -> VerificationResult:
        ...
```

Specializations include:

- BootstrapProof
- CapabilityProof
- ConsentProof
- ExportProof
- ImportProof
- RecoveryProof
- DelegationProof

Only the payload differs. Verification semantics remain identical.

Every proof MUST be immutable, replay resistant, time bounded, and bound to a specific authority subject.

## 9. Proof Verification Pipeline

Every privileged operation MUST execute in the following order:

1. Caller
2. Proof supplied
3. Cryptographic verification
4. Replay protection
5. Policy verification
6. Capability verification
7. Object binding verification
8. SCAR event: `PROOF_VERIFIED`
9. Atomic transaction begins
10. State mutation
11. Merkle root rebuilt
12. Signed attestation generated
13. Transaction commit

If any verification stage fails:

- No mutation
- No commit
- No attestation

No subsystem MAY perform partial verification and then defer the rest of the checks to another layer.

## 10. Authority Transactions

State mutation SHALL occur only inside an authority transaction.

Example:

```python
with authority.transaction(proof):
    vault.store(memory)
```

The transaction manager SHALL:

1. verify proof
2. verify ledger integrity
3. begin transaction
4. perform mutation
5. append SCAR event
6. rebuild Merkle root
7. sign attestation
8. verify post-state
9. commit

If any step fails, the transaction MUST abort and no state change MAY persist.

## 11. Replay Protection

Every proof SHALL contain:

- proof_id
- nonce
- issued_at
- expires_at

The replay subsystem SHALL reject:

- reused proof IDs
- reused nonces
- expired proofs
- revoked proofs

Replay detection is mandatory.

A proof MAY transition through lifecycle states such as:

- ISSUED
- USED
- ARCHIVED

Any second use of a previously accepted proof MUST be rejected and logged.

## 12. Memory Vault Enforcement

Memory transitions SHALL be classified:

- TEMPORARY_CONTEXT
- AI_SUGGESTED
- USER_CONFIRMED

Only USER_CONFIRMED memory becomes permanent.

Promotion to permanent memory requires a verified ConsentProof.

Providers MUST NOT directly create USER_CONFIRMED memory.

Memory access SHALL occur only through MemoryVault.

Direct dictionary access is prohibited.

Required interface:

- store()
- retrieve()
- delete()
- search()
- append()
- snapshot()

The vault SHALL reject operations lacking verified proofs.

## 13. SCAR Audit Requirements

Every successful proof verification SHALL emit a `PROOF_VERIFIED` SCAR event.

Fields:

- proof_id
- proof_type
- owner_id
- device_id
- capability_id
- scope
- verification_result
- timestamp
- merkle_sequence

The event SHALL be included in the Merkle tree.

Every successful authority transaction SHOULD emit lifecycle events such as:

- TRANSACTION_BEGIN
- STATE_MUTATION
- MERKLE_UPDATED
- ATTESTATION_SIGNED
- TRANSACTION_COMMIT

Failures SHOULD emit TRANSACTION_ABORTED.

## 14. Merkle Attestation Requirements

All privileged mutations MUST produce a verifiable attestation anchored to the resulting ledger or state commitment.

The Merkle commitment SHALL:

- reflect the post-mutation state
- be reproducible from the recorded SCAR events
- change whenever protected state changes
- be verifiable independently of any provider

A successful commit MUST be paired with an attestation that matches the resulting Merkle root.

## 15. Provider Capability Rules

Providers are compute engines, not roots of trust.

Providers SHALL:

- operate under least privilege
- receive only the minimum capability necessary for the requested task
- never mint identity, authority, or recovery state
- never access private keys unless explicitly mediated by the vault and proof system

Providers SHALL NOT:

- create proofs on behalf of humans
- directly create USER_CONFIRMED memory
- bypass the proof verifier
- mutate protected state without a verified proof
- become the source of record for sovereignty decisions

## 16. Security Considerations

Proof-gated authority reduces the risk of accidental authority escalation, unverified mutation, and trust-by-construction bugs.

Implementations MUST defend against:

- replay attacks
- proof forgery
- scope confusion
- object binding mismatch
- stale proofs
- cross-device proof reuse
- provider impersonation
- unauthorized privileged access

The repository MUST treat proof verification as a security boundary, not as a convenience utility.

## 17. Privacy Considerations

Proofs SHOULD minimize disclosure to only the information needed to authorize a transition.

Implementations SHOULD:

- avoid over-broad scopes
- avoid exposing private keys
- avoid logging sensitive payload contents in plaintext
- avoid retaining more proof metadata than required for auditability

Memory, identity, and recovery flows MUST preserve the human’s control over disclosure and portability.

## 18. Repository Invariants

Every module SHALL satisfy:

- `assert mutation_requires_verified_proof`
- `assert proof_verification_precedes_policy`
- `assert policy_precedes_state_change`
- `assert scar_event_precedes_commit`
- `assert merkle_root_updates_after_commit`
- `assert attestation_matches_merkle_root`

These invariants MUST be reflected in code, tests, and future RFCs.

## 19. Regression Requirements

Every proof-gated subsystem SHALL include tests covering:

- missing proof
- invalid signature
- expired proof
- replayed proof
- revoked proof
- incorrect owner binding
- incorrect device binding
- incorrect capability scope
- object binding mismatch
- transaction rollback
- SCAR event emission
- Merkle root update
- attestation verification
- audit integrity after mutation

These tests are REQUIRED for every future implementation PR that touches protected state.

## 20. Future Work

Future RFCs and implementation PRs MAY define:

- concrete cryptographic algorithms
- proof serialization formats
- Merkle tree construction details
- attestation formats
- recovery workflows
- cross-provider delegation constraints
- encrypted vault storage formats
- proof revocation distribution strategies

Any such future work MUST remain consistent with the core invariant established here.

## Implementation Sequence

After this RFC is committed, the implementation sequence SHOULD be:

1. `src/sia/proofs/` — `Proof`, `ProofVerifier`, `ReplayRegistry`, proof models, and exception hierarchy.
2. `src/sia/authority/transaction.py` — transactional proof-gated state mutation.
3. `src/sia/memory/vault.py` — replace direct dictionary-backed memory access.
4. Integrate SCAR events (`PROOF_VERIFIED`, transaction lifecycle), Merkle updates, and signed attestations.
5. Migrate all privileged APIs to require typed proof objects and add regression tests for every protected boundary.

This sequence preserves RFC-001’s ownership model while ensuring RFC-002 governs authorization by cryptographically verifiable proof rather than by possession of an object reference.
