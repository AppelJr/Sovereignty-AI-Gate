# RFC-0016 — Conformance Harness

**Status:** Active  
**Version:** 0.1.0  

## Abstract

Defines the conformance harness: the mechanism for registering, running, and recording
RFC conformance assertions.

## Specification

The `ConformanceHarness` accepts assertion callables, runs them, and records
`EvidenceRecord` objects. Each evidence record captures:
- `rfc`: the RFC being tested
- `assertion_id`: unique identifier for the assertion
- `result`: "pass", "fail", or "skip"
- `details`: optional detail payload

## Conformance

- Empty harness run MUST return `[]`
- Passing assertions MUST produce `result = "pass"`
- `ConformanceAssertionError` MUST produce `result = "fail"`
- `summary()` MUST return counts for each result type
