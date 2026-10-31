# RFC-SBP-0005 — SBP v0.2 Interoperability Test Vectors

- **Status:** Frozen for interoperability hardening
- **Version:** 0.2.0
- **Repository:** `Appel420/Sovereignty-AI-Gate`
- **Applies to:** `src/sbp/`, `vectors/`, `tests/vectors/test_sbp_vectors.py`
- **Supersedes:** no protocol primitives; defines executable vector contract for SBP v0.1/v0.2 verification

---

## 1. Purpose

This RFC defines the frozen, executable interoperability contract for the existing SBP core primitives:

- Root Authority
- Branch derivation
- Object manifest / envelope sealing
- Audit chain
- Canonical codec

It does **not** add storage adapters, cloud adapters, UI changes, AI changes, delegation protocols, descriptors, or later SBP features. It freezes deterministic vectors so an independent implementation can reproduce the same bytes, hashes, signatures, identifiers, and failure modes.

---

## 2. Algorithm suite identifier

All vectors in `vectors/` use this interoperability suite identifier:

```text
SBP-INTEROP-0.2/Ed25519-SHA3-512-AES-256-GCM
```

The suite binds the following algorithm identifiers:

| Purpose | Algorithm |
|---|---|
| Signing | `Ed25519` |
| Hashing | `SHA3-512` |
| KDF | `SHA3-512-counter` |
| Symmetric encryption | `AES-256-GCM` |
| Key wrap / branch-key exposure model | `raw-derive` |

The current root metadata `algorithm_suite` object remains part of the signed/canonical root record and must match the implementation output.

---

## 3. Canonical serialization rules

All vectors use canonical UTF-8 JSON bytes from `sia.utils.canonical.canonical_bytes`.

Rules:

1. **Byte ordering:** canonical bytes are UTF-8 encoded JSON text.
2. **Field ordering:** object keys are sorted lexicographically at every nesting level.
3. **Integer representation:** integers are emitted as JSON numbers, not quoted strings.
4. **String normalization:** strings are normalized to Unicode NFC before serialization.
5. **Whitespace:** no extra whitespace is permitted (`","` and `":"` separators only).
6. **Lists / tuples:** list order is preserved; tuples serialize as JSON arrays.
7. **Datetime handling:** where used by the serializer, timestamps normalize to UTC ISO-8601 with trailing `Z`.
8. **Non-finite values:** `NaN` and `Infinity` are forbidden.
9. **Required fields:** closed-schema codec records must contain every required field.
10. **Unknown fields:** closed-schema codec records must reject unknown fields deterministically.

Canonical fixture outputs are frozen in:

- `vectors/root/creation.json`
- `vectors/branch/derivation.json`
- `vectors/object/manifest.json`
- `vectors/codec/canonical.json`

Invalid-schema vectors are frozen in:

- `vectors/codec/invalid_schema.json`

---

## 4. Root Authority contract

Root metadata is public, canonical, and closed-schema.

Required fields:

- `version`
- `root_id`
- `signing_public_key`
- `enc_public_key`
- `created_at`
- `algorithm_suite`
- `policy_hash`

Root ID derivation:

```text
root_id = SHA3-512("SBP_ROOT_SIGNING_IDENTITY:" || signing_public_key_bytes)
```

Policy hash derivation:

```text
policy_hash = SHA3-512(canonical_bytes(policy_document))
```

Signing / verification:

- signatures are Ed25519 over exact payload bytes;
- verification must fail for tampered payloads;
- verification must fail under the wrong root.

Canonical root bytes are frozen in `vectors/root/creation.json`. Signature and verification vectors are frozen in `vectors/root/signing.json`. Policy-hash vectors are frozen in `vectors/root/policy_hash.json`.

Private root material is never serialized into the fixture outputs.

---

## 5. Branch contract

Branch metadata is public, canonical, and closed-schema.

Required fields:

- `version`
- `branch_id`
- `root_id`
- `parent_branch_id`
- `owner_id`
- `capabilities`
- `policy_hash`
- `created_at`
- `label`

Branch root / parent / path references:

- `root_id` binds the branch to a Root Authority;
- `parent_branch_id` is `null` for first-generation branches;
- child lineage is expressed only by parent reference and deterministic re-derivation from explicit inputs.

Branch ID derivation:

```text
branch_id = SHA3-512("SBP_BRANCH_ID:" || canonical_bytes(identity_doc))
```

where `identity_doc` contains:

- `root_id`
- `parent_branch_id`
- `owner_id`
- sorted `capabilities`
- `policy_hash`
- `created_at`
- `label`

Branch-key derivation input:

```text
"SBP_BRANCH_KEY:" || branch_id
```

Required interoperability properties:

- deterministic re-derivation for the same inputs;
- parent/child lineage preservation;
- sibling isolation;
- root isolation;
- path isolation by distinct `parent_branch_id` / `label` inputs.

Vectors:

- `vectors/branch/derivation.json`
- `vectors/branch/lineage.json`
- `vectors/branch/isolation.json`

---

## 6. Object manifest and envelope contract

### 6.1 Manifest identity and branch binding

Object manifests are deterministic and branch-bound.

Required manifest fields:

- `version`
- `object_id`
- `branch_id`
- `content_hash`
- `owner_id`
- `encryption_algorithm`
- `created_at`
- `metadata`

Object identity derivation:

```text
object_id = SHA3-512("SBP_OBJECT_ID:" || canonical_bytes(identity_doc))
```

where `identity_doc` contains:

- `branch_id`
- `content_hash`
- `owner_id`
- `encryption_algorithm`
- `created_at`
- `metadata`
- `version`

Vectors:

- `vectors/object/manifest.json`

### 6.2 Encryption metadata and fixture nonce handling

Envelope fields:

- `version`
- `object_id`
- `branch_id`
- `nonce_hex`
- `ciphertext_hex`
- `encryption_algorithm`
- `created_at`

Seal / unseal contract:

```text
key        = branch.derive_key(length=32)
plaintext  = canonical_bytes(manifest)
ciphertext = AES-256-GCM(key, nonce, plaintext)
```

For interoperability vectors only, `nonce_hex` is fixed and explicit so independent implementations can reproduce the ciphertext exactly.

> **Production requirement:** AES-GCM nonce generation remains cryptographically random by default. Fixed nonce injection exists only for deterministic vectors/tests and **must not** be the default production API behavior.

Vectors:

- `vectors/object/seal.json`
- `vectors/object/unseal.json`
- `vectors/object/failure_cases.json`

Required failure behavior:

- wrong branch key must fail closed;
- ciphertext tampering must fail closed.

---

## 7. Audit chain contract

Audit entries are deterministic only when every input is explicit, including timestamp and entry identifier.

Genesis sentinel:

```text
previous_hash = "0" * 128
```

Required entry fields:

- `sequence`
- `entry_id`
- `timestamp`
- `branch_id`
- `actor_id`
- `action`
- `object_id`
- `metadata_hash`
- `previous_hash`
- `signature`
- `entry_hash`

Entry linkage:

- sequence `0` uses the genesis sentinel;
- sequence `n > 0` uses the prior entry's `entry_hash`.

Entry hash derivation:

```text
entry_hash = SHA3-512(canonical_bytes({signing_document..., "signature": signature}))
```

Signing / verification:

- signatures are Ed25519 over `canonical_bytes(signing_document)`;
- verification must fail on action tampering;
- verification must fail on broken chain linkage.

Vectors:

- `vectors/audit/genesis.json`
- `vectors/audit/append.json`
- `vectors/audit/verification.json`

---

## 8. Invalid-schema behavior and negative vectors

The codec is closed-schema for root and branch metadata.

Required behavior:

- reject unknown top-level fields;
- reject missing required fields;
- preserve deterministic error semantics suitable for fixture testing.

Negative vectors included in this RFC scope:

- `vectors/codec/invalid_schema.json`
- `vectors/object/failure_cases.json`
- `vectors/root/signing.json` (tampered payload / wrong root)
- `vectors/audit/verification.json` (tampered entry / broken linkage)

---

## 9. Fixture inventory

This RFC freezes exactly these fixture paths:

```text
vectors/root/creation.json
vectors/root/signing.json
vectors/root/policy_hash.json
vectors/branch/derivation.json
vectors/branch/lineage.json
vectors/branch/isolation.json
vectors/object/manifest.json
vectors/object/seal.json
vectors/object/unseal.json
vectors/object/failure_cases.json
vectors/audit/genesis.json
vectors/audit/append.json
vectors/audit/verification.json
vectors/codec/canonical.json
vectors/codec/invalid_schema.json
```

No additional SBP vector fixture paths are defined by this RFC.

---

## 10. Acceptance criterion

This repository satisfies **fixture-contract readiness** when:

1. every vector file above is loaded by `tests/vectors/test_sbp_vectors.py`;
2. the existing `src/sbp` implementation reproduces every frozen expected output exactly;
3. negative vectors fail exactly as required by this RFC.

An **independent implementation passes interoperability** only when a separate implementation reproduces the frozen vectors exactly.

> This RFC and its tests do **not** claim that an independent implementation has already passed. They freeze the contract required for future cross-language verification.

---

## 11. Explicit non-goals

Out of scope for this RFC:

- storage adapters
- cloud adapters
- dashboards
- AI or Nexus application changes
- descriptor files
- migration systems
- later SBP delegation / capability protocols

This document is a hardening layer over the existing SBP core, not a feature-expansion RFC.
