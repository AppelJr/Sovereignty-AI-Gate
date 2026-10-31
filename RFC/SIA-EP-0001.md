# SIA Egress Protocol v1

## Status

This document defines the portable `sia.cloud-egress.v1` envelope. The envelope
is an offline cryptographic object; it performs no networking and does not
authorize egress.

## Envelope

Implementations MUST serialize the following object using the repository's
canonical JSON rules. Fields are exact and additional fields MUST be rejected.

| Field | Requirement |
| --- | --- |
| `schema` | `sia.cloud-egress.v1` |
| `suite` | `SIA-E1` |
| `kdf` | `argon2id` |
| `kdf_params` | `iterations: 3`, `lanes: 4`, `memory_cost: 65536`, `length: 32` |
| `recipient_id` | Registered namespace plus non-empty name |
| `content_type` | Non-empty media type or application-defined content type |
| `created` | ISO-8601 UTC timestamp ending in `Z` |
| `expires` | Optional ISO-8601 UTC timestamp ending in `Z`, later than `created` |
| `salt` | 16 random bytes, URL-safe base64 |
| `nonce` | 12 random bytes, URL-safe base64 |
| `ciphertext` | AES-256-GCM ciphertext with 16-byte tag, URL-safe base64 |
| `envelope_id` | Lowercase SHA-256 hexadecimal digest specified below |

`SIA-E1` derives a 32-byte AES key with Argon2id from the UTF-8 passphrase and
salt, then encrypts with AES-256-GCM. Implementations MUST generate a new random
salt and nonce for every envelope and MUST NOT permit callers to supply either.

## Authentication and identifiers

AES-GCM additional authenticated data is the canonical JSON object containing:
`schema`, `suite`, `kdf`, `kdf_params`, `recipient_id`, `content_type`,
`created`, and `expires`. Authentication failure, malformed encodings,
unsupported parameters, expiration, recipient mismatch, or an invalid envelope
identifier MUST fail closed without returning plaintext.

`envelope_id` is the SHA-256 digest, hex encoded in lowercase, of canonical JSON
for the complete envelope excluding `envelope_id`. Recipients MUST verify it
before accepting an envelope. It supports audit references and deduplication
without revealing plaintext.

Recipient IDs MUST use one of these namespaces: `provider:`, `vault:`,
`device:`, `storage:`, or `peer:`. The namespace identifies the recipient class;
the suffix identifies the recipient within that class.

## Version negotiation

Recipients MUST reject unknown schemas, suites, KDFs, or KDF parameters.
Additional suites use a new `SIA-E<n>` suite value. A schema change is reserved
for incompatible envelope structure changes.

## Security boundary

CloudEgressEnvelope protects data at rest and during transport to an authorized
recipient. It is not intended to provide end-to-end confidentiality from hosted
inference providers that require plaintext to execute a request.

## Interoperability requirements

Implementations MUST use canonical JSON, URL-safe base64 with padding, UTF-8
passphrases, the exact Argon2id parameters, a 16-byte salt, a 12-byte nonce, and
the authenticated-data field order expressed above. The following deterministic
test vector MUST decrypt to UTF-8 bytes `SIA-EP-0001 test vector` with passphrase
`correct horse battery staple`:

```json
{"ciphertext":"fQBjRpHNUQBTSknN3tskfusjcTr2RjBYBR-bcPWQaqbr2pWUHzBk","content_type":"application/sia-test","created":"2026-01-01T00:00:00Z","envelope_id":"0b5042d2935884f1d663239cd1af4ed022404835e9854e1453ad73175dbb1045","expires":"2026-12-31T23:59:59Z","kdf":"argon2id","kdf_params":{"iterations":3,"lanes":4,"length":32,"memory_cost":65536},"nonce":"EBESExQVFhcYGRob","recipient_id":"storage:test-vector","salt":"AAECAwQFBgcICQoLDA0ODw==","schema":"sia.cloud-egress.v1","suite":"SIA-E1"}
```

The vector uses the 16-byte salt `00` through `0f` and the 12-byte nonce `10`
through `1b`. Implementations MUST provide an equivalent test.
