# RFC-0018 — Export Bundle

**Status:** Active  
**Version:** 0.1.0  

## Abstract

Defines the signed export bundle format for portable authority interchange.

## Specification

### ExportBundle Schema (v1.0)

```json
{
  "schema_version": "1.0",
  "bundle_id": "<string>",
  "created_by": "<string>",
  "created_at": "<ISO-8601>",
  "payload": {},
  "payload_hash": "<sha3-512-hex>",
  "signature": "<hex-encoded signature>"
}
```

`payload_hash = SHA3-512(canonical_json(payload))`

## Conformance

- `payload_hash` mismatch MUST raise `E_EXPORT_SCHEMA_INVALID`
- Missing required fields MUST raise `E_EXPORT_BUNDLE_INCOMPLETE`
