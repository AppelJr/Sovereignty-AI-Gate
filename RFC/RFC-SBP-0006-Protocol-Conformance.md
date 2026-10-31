# RFC-SBP-0006 — SBP v0.2 Protocol Conformance

- **Status:** Implemented
- **Version:** 0.2.0
- **Applies to:** `src/sbp/protocol.py` and `tests/sbp_protocol/`
- **Transport:** none required; records are transport-independent

## 1. Scope

This RFC defines the executable wire contracts for capability negotiation,
authority exchange, delegation, branch creation, audit events, and encrypted
replication.  The JSON files in `tests/sbp_protocol/vectors/` are normative
inputs and boundary cases.  They contain no private keys and are reproducible
offline.

The algorithm suite is:

`SBP-INTEROP-0.2/Ed25519-SHA3-512-AES-256-GCM`

Records use canonical UTF-8 JSON from `sia.utils.canonical.canonical_bytes`.
Object keys are sorted, lists preserve their defined order, and protocol
capability lists are sorted and unique.

## 2. Contracts

### Capability negotiation

Peers exchange `CapabilityOffer` records containing `protocol`, `version`,
`suite`, `peer_id`, and a sorted unique capability list.  Negotiation fails
closed on protocol, version, or suite mismatch and returns the sorted
intersection.  An empty intersection is valid and means no protocol operation
was agreed.

### Authority exchange

An `AuthorityExchange` binds a peer identifier to a public root identifier and
Ed25519 public key.  The root signs the canonical record without `signature`.
Verification uses only the advertised public key; private root material is
never serialized or transferred.

### Delegation

A `Delegation` is root-signed and names exactly one grantee, branch, capability
set, and optional expiry.  A child delegation must be a subset of its parent
capabilities.  Expired, wrong-root, missing-capability, or invalid-signature
records are rejected.

### Branch creation and audit events

Branches retain the existing deterministic SBP identity derivation and explicit
parent linkage.  Audit events use the existing signed append-only chain:
sequence zero links to the genesis sentinel, later entries link to the prior
entry hash, and every event is verified with the root signature.

### Replication

`ReplicationRecord` carries an encrypted `ObjectEnvelope`, object and branch
identifiers, source root identifier, and a replica identifier.  It never
contains root private material, signing keys, or authority-transfer claims.
Replication is therefore backup/synchronization only; a replica cannot become
authoritative.

Conflicts are accepted only for the same object and branch.  The deterministic
winner is the lexicographically smallest `(replica_id, serialized record)`
tuple.  This rule is local, offline, and independent of transport ordering.
Invalid ciphertext metadata and mismatched identity fields fail closed.

## 3. Vector and versioning rules

        # copilot/add-fedramp-schema-support
Each vector is a JSON object whose top-level keys are contract-specific (commonly `inputs` and, where useful, `expected`).

Each vector is a JSON object with `inputs` and, where useful, `expected`.
        main
Vector filenames identify the contract and must remain closed under the
inventory assertion in `test_protocol_vectors.py`.  A wire-breaking change
requires a new protocol version and new vector directory; a compatible
extension must preserve existing required fields and vectors.

Signatures and AES-GCM ciphertext are deterministic in vectors only when all
inputs, including nonce, timestamp, and identifiers, are explicit.  Production
replication uses fresh nonces through `seal_manifest`; fixed nonces are test
fixtures only.

## 4. Independent implementation requirement

An implementation conforms only if it reproduces canonical records, validates
signatures and lineage, enforces delegation scope and expiry, rejects tampered
records, and applies the replication conflict rule without network access.
Passing structural examples alone is insufficient; negative and boundary
vectors are part of the contract.
