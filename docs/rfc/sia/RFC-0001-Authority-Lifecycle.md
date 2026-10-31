# RFC-0001 — Authority Lifecycle

**Status:** Active  
**Version:** 0.1.0  

## Abstract

Defines the lifecycle stages of a SIA authority instance: creation, initialization, operation, suspension, and termination.

## Lifecycle Stages

1. **Created** — Instance allocated, no ledger entries, no operations permitted.
2. **Initialized** — `initialize()` called; `authority.init` ledger entry written.
3. **Operational** — Boundaries may be registered; delegations issued; memory stored.
4. **Suspended** — Operations blocked; ledger sealed (future capability).
5. **Terminated** — No further operations; final ledger entry written (future capability).

## Conformance

- Implementations MUST prevent any operation in the `Created` state.
- The transition from `Created` to `Initialized` is irreversible within a session.
