# RFC-0014 — Memory Model

**Status:** Active  
**Version:** 0.1.0  

## Abstract

Defines the encrypted, per-model memory model. Memory is scoped to a single model,
stored on-device encrypted, and shared cross-model only with explicit user consent.

## Memory State Machine

Each memory record passes through the following states. Transitions require the proof
type shown; evaluation is performed by `ProofVerifier.verify(proof, context)`.

| State | Description | Required Proof | Persistent? |
|---|---|---|---|
| **Context** | Transient AI workspace; not saved | None | No |
| **AI Suggested** | AI proposes a fact for long-term storage | `CapabilityProof` | No |
| **User Confirmed** | User explicitly approves persistence | `ConsentProof` | Yes |
| **Shared Memory** | Record readable by another model | `ConsentProof` + `DelegationProof` | Yes |
| **Deleted** | Tombstoned; content removed but provenance retained | `DeleteProof`¹ | Yes (tombstone) |

> ¹ `DeleteProof` is either a specialization of `ConsentProof` (when the user explicitly
> consents to deletion) or an alias for a `PolicyProof` that evaluates a retention policy.
> The project will resolve this in RFC-0023 (AuthorityTypeRegistry). Until then treat
> `DeleteProof` as a `ConsentProof` with `action = "memory.delete"`.

### Transition Rules

```
Context ──[CapabilityProof]──▶ AI Suggested
AI Suggested ──[ConsentProof]──▶ User Confirmed
User Confirmed ──[ConsentProof + DelegationProof]──▶ Shared Memory
User Confirmed ──[DeleteProof]──▶ Deleted
Shared Memory  ──[DeleteProof]──▶ Deleted
AI Suggested   ──[no proof needed]──▶ Context  (suggestion rejected / session end)
```

## MemoryChain vs. MemoryVault

- **MemoryChain** (`sovereignty_core.vault.memory_chain`): storage and provenance engine.
  Manages append-only, hash-chained blocks. Has no knowledge of authority grants.
- **MemoryVault** (`sia.memory`): authority and enforcement boundary. Evaluates proofs before
  allowing state transitions, enforces consent rules, and manages AES-256-GCM encryption.

## MemoryRecord Schema (v1.0)

```json
{
  "schema_version": "1.0",
  "record_id": "<string>",
  "model_id": "<string>",
  "content": "<any>",
  "consent": ["<model_id>", ...],
  "created_at": "<ISO-8601>"
}
```

## Consent Rules

- A model MAY read its own records (implicit).
- A model MAY read another model's record only if its `model_id` appears in `consent`.
- Violation raises `E_MEMORY_CONSENT_DENIED`.

## On-Disk Encryption

Memory files MUST be encrypted with AES-256-GCM using a key derived from the user's
root key material. Plaintext MUST NOT be persisted.

## Conformance

- Missing `record_id` or `model_id` raises `E_MEMORY_SCHEMA_INVALID`
- Cross-model access without consent raises `E_MEMORY_CONSENT_DENIED`
- State transitions without the required proof raise `E_PROOF_REQUIRED`

