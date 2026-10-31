# RFC-0013 — Root Boundary

**Status:** Active  
**Version:** 0.1.0  

## Abstract

Defines the root boundary: the first boundary registered by the owner, which forms the
trust anchor for the authority chain.

## Specification

### Root Boundary Properties

- `boundary_type`: MUST be `"creator"`
- `creator_id`: MUST equal the owner's identity
- `scope`: SHOULD be `["*"]` for a root boundary (owner controls all actions)
- Once registered, the `creator_id` is permanently locked

### Uniqueness

Each `boundary_id` is unique within a registry instance.

## Conformance

- `creator_id` MUST equal `owner_id` for owner-registered boundaries
- Duplicate `boundary_id` MUST raise `E_REGISTRY_DUPLICATE`
- `creator_id` MUST NOT be modifiable after registration
