# RFC-0019 — Import Bundle

**Status:** Active  
**Version:** 0.1.0  

## Abstract

Defines the import bundle validation and loading process. Import is a multi-stage
pipeline; each stage has distinct failure semantics and error codes.

## Import Boundary Layers

Import validation is separated into four ordered stages. Each stage MUST complete
successfully before the next begins.

### Stage 1: Representation Validation

Ensure the bundle is structurally valid JSON with all required fields present and
the schema version supported.

- **Passes when**: required fields present, `schema_version` is `"1.0"`.
- **Fails with**: `E_EXPORT_BUNDLE_INCOMPLETE` (missing fields), `E_IMPORT_VERSION_UNSUPPORTED` (bad version).

### Stage 2: Integrity Validation

Recompute `SHA3-512(canonical_json(payload))` and compare to `payload_hash`.

- **Passes when**: computed hash matches the stored `payload_hash`.
- **Fails with**: `E_IMPORT_SCHEMA_INVALID`.
- **Note**: A passing integrity check proves the payload was not corrupted or tampered
  _after_ the hash was recorded. It does not prove the bundle was created by an authorized
  entity; that requires Stage 4.

### Stage 3: Duplicate Detection

Check that `bundle_id` has not been imported before in this instance.

- **Passes when**: `bundle_id` is not present in the local bundle registry.
- **Fails with**: `E_IMPORT_DUPLICATE`.

### Stage 4: Authority Reconstruction Gate

Verify the bundle's cryptographic signature using the signer's public key. Evaluate the
associated `ImportProof` with `ProofVerifier.verify(proof, context)`.

- **Passes when**: signature is cryptographically valid AND the associated proof is accepted.
- **Fails with**: `E_IMPORT_SIGNATURE_INVALID`, `E_IMPORT_AUTHORITY_DENIED`.
- **Critical invariant**: A valid signature combined with a passing integrity check is **not**
  sufficient to grant authority. Authority is granted only when `ProofVerifier` accepts the
  associated proof in the current context. Signature and hash verify _provenance and integrity_;
  they never equal _authority_ by themselves.

> Stage 4 requires the signer's public key and an active authority context. Callers that do
> not possess the signer's key may complete Stages 1–3 and defer Stage 4 to a later, keyed
> invocation.

## Bundle Schema

Import bundles are structurally identical to export bundles (RFC-0018) with the addition of
`imported_at`. The full schema is:

```json
{
  "schema_version": "1.0",
  "bundle_id": "<string>",
  "created_by": "<string>",
  "created_at": "<ISO-8601>",
  "payload": {},
  "payload_hash": "<sha3-512-hex>",
  "signature": "<hex-encoded signature>",
  "imported_at": "<ISO-8601>"
}
```

## Conformance

- Unsupported schema version MUST raise `E_IMPORT_VERSION_UNSUPPORTED`
- Duplicate bundle_id MUST raise `E_IMPORT_DUPLICATE`
- `payload_hash` mismatch MUST raise `E_IMPORT_SCHEMA_INVALID`
- Stage 4 failure MUST raise `E_IMPORT_AUTHORITY_DENIED` when proof is rejected
- A valid signature without proof acceptance MUST NOT grant authority
