# RFC-SBP-v0.1 — Sovereignty Boundary Protocol Reference Implementation

- **Status:** Draft
- **Version:** 0.1.0
- **Author:** Derek Appel
- **Repository:** Appel420/Sovereignty-AI-Gate
- **Location:** `src/sbp/`
- **Requires:** RFC-0001 (SAMA), RFC-0013 (Root Boundary)

---

## 1. Abstract

This document defines the first milestone of the **Sovereignty Boundary Protocol (SBP)**, a device-first protocol for managing cryptographic namespaces, encrypted objects, and append-only audit evidence under a verifiable root chain of authority.

SBP v0.1 implements the minimal coherent set of protocol primitives: Root Authority, Branch, Object Manifest/Envelope, Audit Chain, and Canonical Codec.  It does not implement network transport, provider bindings, replication, or AI features.

---

## 2. Design Constraints

| Constraint | Rationale |
|------------|-----------|
| Offline-first by default | Local device state is authoritative; no required network calls or cloud dependencies |
| Private root material is caller-controlled | Root secrets live in a `TrustBackend` and are never serialized or logged |
| Real signatures only | All Ed25519 signatures are produced by real cryptographic operations |
| No third-party authority | The root chain of authority is self-issued from local device material |
| Reuse existing utilities | `sia.utils.canonical` and `sovereignty_core.identity.root_of_trust` are used directly |

---

## 3. Boundary Definitions

SBP explicitly distinguishes five boundaries.  Confusion between them is a design error:

| Boundary | What it means in SBP |
|----------|----------------------|
| **Authority** | The Root Authority and its key material.  Private root material is always caller-controlled and never leaves the `TrustBackend` interface. |
| **Storage** | Encrypted object envelopes and serialized Root/Branch records.  Git, GitHub, or any file system can store these encrypted replicas.  Storage replicas are **not** authorities. |
| **Execution** | Application code that calls SBP primitives.  Execution happens locally on the owner's device by default. |
| **Synchronization** | Replication of encrypted envelopes to backup locations.  Synchronization does not grant authority to the replica destination. |
| **Egress** | Disclosure of SBP records to external parties.  Authorization and disclosure boundaries are described per-operation; SBP does not claim zero third-party data leakage — it provides explicit controls over what is disclosed. |

> **Local device state is authoritative by default.**  Backups, Git repositories, and GitHub are encrypted replicas, not authorities.

---

## 4. Protocol Primitives

### 4.1 Root Authority (`src/sbp/root.py`)

The Root Authority is the device-local trust anchor.

**Public fields (safe to serialize):**

| Field | Description |
|-------|-------------|
| `root_id` | SHA3-512 of the signing public key, domain-tagged with `SBP_ROOT_SIGNING_IDENTITY:` |
| `signing_public_key` | Hex-encoded raw Ed25519 public key (32 bytes → 64 hex chars) |
| `enc_public_key` | Hex-encoded derived encryption public material (32 bytes → 64 hex chars) |
| `created_at` | Unix timestamp (seconds, UTC) |
| `algorithm_suite` | Dict of algorithm identifiers (see §5) |
| `policy_hash` | SHA3-512 of the canonical policy document |
| `version` | Schema version (currently `1`) |

**Private fields (never serialized):**

- Root secret bytes (held by the `TrustBackend`)
- Ed25519 private key (held by the `TrustBackend`)
- Encryption private key (derived on demand via `derive_branch_key`; never stored)

**Key-encryption boundary:**  The `enc_public_key` field is derived from root secret material but is safe to expose for key-transport purposes.  The corresponding private bytes are available to the owner via `root.derive_branch_key("__enc__")` on demand.

### 4.2 Branch (`src/sbp/branch.py`)

A Branch is a cryptographic namespace derived from a Root Authority.

**Identity derivation:**

```
identity_doc = {
    "root_id": ...,
    "parent_branch_id": ...,  # None for first-generation
    "owner_id": ...,
    "capabilities": [...],    # sorted
    "policy_hash": ...,
    "created_at": ...,
    "label": ...,
}
branch_id = SHA3-512("SBP_BRANCH_ID:" || canonical_bytes(identity_doc))
```

The same inputs always produce the same `branch_id`.

**Sibling-branch key isolation:**

```
branch_key = TrustBackend.derive_key("SBP_BRANCH_KEY:" || branch_id)
```

Two sibling branches have distinct keys because their `branch_id` values differ.  Neither key can be recovered from the other without root secret material.

**Capabilities:**  Each branch carries an explicit, sorted capability tuple from `BranchCapability`:

| Capability | Meaning |
|------------|---------|
| `READ` | Actors may read objects in this branch |
| `WRITE` | Actors may write objects |
| `APPEND_AUDIT` | Actors may append audit entries |
| `ISSUE_OBJECT` | Actors may create object manifests |
| `DELEGATE` | Actors may create child branches |
| `ADMIN` | Full administrative control |

### 4.3 Object Manifest and Envelope (`src/sbp/object.py`)

An **ObjectManifest** binds an object to its branch and records authorization metadata:

| Field | Description |
|-------|-------------|
| `object_id` | SHA3-512 of core identity fields, domain-tagged `SBP_OBJECT_ID:` |
| `branch_id` | Branch this object belongs to |
| `content_hash` | SHA3-512 of raw object content (caller-supplied) |
| `owner_id` | Root authority owner |
| `encryption_algorithm` | `"AES-256-GCM"` |
| `created_at` | Unix timestamp |
| `metadata` | Optional authorization/descriptive metadata |

An **ObjectEnvelope** is the AES-256-GCM encrypted form of a canonical manifest, using branch-scoped key material:

```
key   = branch.derive_key(length=32)  # 256-bit branch key
nonce = os.urandom(12)               # fresh 96-bit nonce per seal
ciphertext = AES-256-GCM.encrypt(key, nonce, canonical_bytes(manifest))
```

The ciphertext authenticates the manifest.  Decryption with the wrong branch key or a tampered ciphertext fails with an authentication error.

### 4.4 Audit Chain (`src/sbp/audit.py`)

An AuditChain is an append-only, hash-chained, device-signed log for one branch.

**Entry fields:**

| Field | Description |
|-------|-------------|
| `sequence` | Monotonically increasing sequence number |
| `entry_id` | UUID4 |
| `timestamp` | UTC ISO-8601 with trailing Z |
| `branch_id` | Branch this entry belongs to |
| `actor_id` | Identifier of the acting party |
| `action` | Action string (e.g. `"OBJECT_ISSUED"`) |
| `object_id` | Optional object manifest ID |
| `metadata_hash` | SHA3-512 of additional metadata (plaintext not stored) |
| `previous_hash` | SHA3-512 of the previous entry; genesis sentinel `"0" * 128` for sequence 0 |
| `signature` | Ed25519 hex signature over `canonical_bytes(signing_document)` |
| `entry_hash` | SHA3-512 of `canonical_bytes({...signing_doc..., "signature": sig})` |

**Chain linkage:**

```
entry[0].previous_hash == "0" * 128   # genesis sentinel
entry[n].previous_hash == entry[n-1].entry_hash  (n > 0)
```

No fake signatures are used.  `AuditChain.verify_integrity()` performs real Ed25519 verification for every entry.

The chain is suitable for later Merkle verification: the sequence of `entry_hash` values can be fed into the existing `MerkleTree` implementation in `sovereignty_core.audit.merkle`.

### 4.5 Canonical Codec (`src/sbp/codec.py`)

The codec provides strict encode/decode round-trips for Root and Branch records.

- **Unknown fields:** Rejected with `CodecError`.
- **Missing required fields:** Rejected with `CodecError`.
- **Encoding:** Uses `sia.utils.canonical.canonical_bytes` for byte-for-byte reproducibility.

---

## 5. Algorithm Suite

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Signing | Ed25519 | Via `cryptography` library; real signatures only |
| Hashing | SHA3-512 | 128-character hex digests throughout |
| KDF | SHA3-512 counter mode | Domain-separated per-purpose derivation |
| Symmetric encryption | AES-256-GCM | Via `cryptography.hazmat.primitives.ciphers.aead.AESGCM` |
| Key wrap | Raw derivation | Branch keys derived from root secret, not wrapped |
| PQC (future) | ML-DSA-87 | Optional; requires `liboqs-python`; not active in v0.1 |

---

## 6. What Is Not Implemented in v0.1

The following items are explicitly deferred to later milestones.  They are not
invented or faked in this implementation:

| Deferred item | Reason for deferral |
|---------------|---------------------|
| Network transport | Requires a formal protocol decision on wire format and peer authentication |
| Merkle attestation for audit chain | Foundation is in place; `MerkleTree` integration is straightforward but deferred for a focused v0.2 milestone |
| Post-quantum signing | Requires `liboqs-python` and a formal algorithm negotiation protocol |
| Multi-device root sync | Requires a replication and conflict-resolution protocol |
| Provider bindings | Out of scope for the v0.1 primitives milestone |
| AI/dashboard/voice features | Explicitly excluded per the problem statement |

---

## 7. Security Considerations

- **Private root material never leaves the TrustBackend.**  `RootMetadata.to_dict()` and all serialization paths contain only public fields.
- **Branch key isolation** is enforced by including the unique `branch_id` in the KDF context.  Two siblings cannot recover each other's keys.
- **Authentication** in AES-GCM means ciphertext tampering is detected at decryption time.
- **The software backend** (`SoftwareTrustBackend`) stores private material in process memory and is not hardware-backed.  Production deployments should supply a hardware-rooted backend.
- **SBP v0.1 does not claim zero third-party data leakage.**  Authorization boundaries are explicit: Root metadata, Branch metadata, and Audit bundles are safe to serialize; encrypted Envelopes protect object content.

---

## 8. Privacy Considerations

- Audit entry plaintext metadata is never stored in the chain.  Only the SHA3-512 hash of metadata is retained.
- Object content is always encrypted before storage; the manifest records only the content hash.
- The `owner_id` and `branch_id` fields in manifests and audit entries are public identifiers, not content.

---

## 9. Compatibility

SBP v0.1 is additive:

- Existing `src/sia/` and `src/sovereignty_core/` public APIs are unchanged.
- The `sbp` package lives at `src/sbp/` and is a separate namespace.
- The `sbp` package reuses `sia.utils.canonical` and `sovereignty_core.identity.root_of_trust` directly.

Breaking changes to the Root or Branch wire format require a version bump (`version` field) and an update to this document.
