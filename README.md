# Sovereignty-AI-Gate

Imported from the suspended Appel420/Sovereignty-AI-Studio archive (commit 116bb2f8e36a47627667320bbc9e96f06345fe11).

This repository contains the Sovereignty AI Gate — on-device AI infrastructure, policy boundary, SCAR ledger, MCP server, dashboard, and conformance tests.

**Owner:** AppelJr (Sovereignty One)

See original README content in subsequent commits as the full tree is restored.
# Sovereignty AI Gate

@claude @codex @copilot @grok @duckai

This is the main dedicated branch. All changes by Claude DuckAI Grok/Ara GPT/Codex Copilot must be made in their dedicated branch. Do not push directly to main. Create a Pull Request for review.

## README Guide

- [Purpose and guarantees](#what-this-project-guarantees)
- [Repository guide](#repository-guide)
- [Architecture and protocol documentation](#architecture-and-protocol-documentation)
- [Development workflow](#development-workflow)
- [Policy and contribution requirements](#provider-and-platform-policy)
- [FedRAMP Phase 4 hardening (internal evidence phase)](#fedramp-phase-4-hardening-internal-evidence-phase)

## Provider policy

This repository is offline-first and provider-neutral in implementation. Dashboard configuration, documentation, and test fixtures must not hard-code vendor model lists or promotional provider catalogs.

---

Sovereignty AI Gate is a **user-rooted authority framework** for AI governance.
It is built to be **offline-first, deterministic, auditable, and enforceable**.

This project is serious by design:
- It says what it does.
- It does what it says.
- Every critical behavior is expected to be verifiable in code and tests.

## Global Government / DoD-Grade Posture

This project is engineered for high-assurance environments where failure, ambiguity, and hidden behavior are unacceptable.

- **Mission-critical reliability**: core workflows are deterministic, testable, and reproducible.
- **Operational sovereignty**: critical authority paths remain functional in offline and air-gapped deployments.
- **Cryptographic accountability**: identity, delegation, and audit evidence are signed, chained, and tamper-evident.
- **Policy enforcement over preference**: security-critical behavior is enforced by code paths and tests, not documentation alone.
- **Evidence-first governance**: claims must be backed by verifiable artifacts, logs, and repeatable validation runs.

Compliance note: this repository targets defense-grade engineering rigor, but no formal certification is implied unless explicitly documented in governed release artifacts.

## What This Project Guarantees

- **Human authority is explicit**: AI actions must trace back to a human grant.
- **Offline-first operation**: core workflows run locally without required cloud calls.
- **Deterministic execution**: random behavior in authority-critical paths is not allowed.
- **Tamper-evident auditability**: authority events are recorded in an append-only chain.
- **Provider independence**: governance logic is not tied to a single vendor stack.

## Non-Negotiable Rules

- No hidden synchronization.
- No silent external persistence.
- No backdoors.
- No fake demos or non-functional flows presented as real.
- No implicit network behavior in core local workflows.

## Provider and Platform Policy

- Supported providers: OpenAI, Anthropic/Claude, Grok, GitHub Copilot.
- Prohibited stacks in this governance surface: Google/Gemini, Meta/Llama, Firebase, Vertex.
- Dashboard configs, docs, and fixtures must not hard-code promotional vendor catalogs.

## Branch and Contribution Policy

Do not push directly to `main`.

Use dedicated branches for agent work and open a Pull Request for review:
- `ara-hardened` for direct owner hardening work
- `copilot` for GitHub Copilot changes
- `GPT` for GPT/Codex changes

## Quick Verification

Run the checks used in this repository:

```bash
npm install
npm test
python -m pip install -e '.[dev]'
pytest
```

Note: `npm run lint` currently requires an `eslint.config.*` file for ESLint v9.

## Start Here

- Governance intent: `CHARTER.md`
- Collaboration mode: `PLAYGROUND.md`
- Security expectations: `SECURITY.md`

If a behavior cannot be audited, explained, and tested, it does not belong in this project.

## Repository Guide

The repository is organized so that the authority protocol, core primitives, dashboard, documentation, deployment assets, and tests can be reviewed independently.

| Location | What it contains |
|----------|------------------|
| `src/sia/` | The authority-gate protocol: authority lifecycle, boundaries and policy enforcement, delegation, memory, import/export validation, audit recording, conformance evidence, shared utilities, and tool execution. |
| `src/sovereignty_core/` | Lower-level sovereignty primitives for identity and root-of-trust material, consent and capability permissions, encrypted memory chains, and tamper-evident SCAR/Merkle audit records. |
| `src/dashboard/` | The local deterministic dashboard, including its interface, styles, model view, and deterministic compliance, signature, TPM, and threat-feed modules. |
| `tests/` | Python governance, conformance, core, runtime, and smoke tests, plus dashboard determinism tests and reusable protocol fixtures. |
| `docs/architecture/` | Focused explanations of the authority lifecycle, boundary rules, deployment model, registry governance, and deterministic dashboard behavior. |
| `docs/compliance/fedramp_phase4/` | Internal FedRAMP Rev. 5 hardening evidence: cloud/dependency inventory, SBOM, control matrix, monitoring model, and security decision index. |
| `docs/rfc/` and `RFC/` | Protocol specifications and implementation-planning records that define authority semantics and compatibility expectations. |
| `docs/conformance/` | The conformance test matrix and documented failure codes used to evaluate protocol behavior. |
| `scripts/` | Local development helpers for bootstrapping dependencies, running tests and conformance checks, linting the dashboard, and building releases. |
| `deploy/` | Docker, Nginx, and Kubernetes deployment assets. Review these as deployment configuration; they do not replace the offline local workflow. |
| Root policy files | `CHARTER.md`, `ARCHITECTURE_RULES.md`, `SECURITY.md`, `CONTRIBUTING.md`, and `PLAYGROUND.md` define project governance, security, contribution, and collaboration expectations. |

### Project Tree

```text
.
├── .github/
│   └── workflows/             # Python, conformance, and dashboard CI checks
├── deploy/
│   ├── docker/                # Container image and Compose configuration
│   └── nginx/                 # Reverse-proxy configuration
├── docs/
│   ├── architecture/          # Architecture decisions and system models
│   ├── conformance/           # Test matrix and failure-code reference
│   └── rfc/                   # Current protocol RFCs
├── RFC/                       # Legacy RFC records and implementation plans
├── scripts/                   # Bootstrap, test, lint, conformance, and release helpers
├── src/
│   ├── dashboard/             # Local deterministic dashboard
│   ├── sia/                   # Authority-gate protocol implementation
│   └── sovereignty_core/      # Identity, permissions, vault, and audit primitives
├── tests/
│   ├── conformance/           # Protocol conformance tests
│   ├── dashboard/             # Dashboard determinism tests
│   ├── fixtures/              # Reusable protocol test data
│   ├── governance/            # Authority-boundary governance tests
│   └── sovereignty_core/      # Core primitive tests
├── ARCHITECTURE_RULES.md
├── CHARTER.md
├── CONTRIBUTING.md
├── PLAYGROUND.md
├── README.md
├── SECURITY.md
├── mcp_server.py              # Governed MCP server entry point
├── package.json               # Dashboard tooling
└── pyproject.toml             # Python package and test configuration
```

### Authority Protocol Modules

| Module | Responsibility |
|--------|----------------|
| `authority.py` and `authority_gate.py` | Establish and operate the user-rooted authority lifecycle. |
| `security/` | Register immutable authority boundaries and apply authority policy. |
| `delegation/` | Create and verify constrained authority delegations. |
| `memory/` | Define and validate scoped AI memory records. |
| `imports/` and `export/` | Validate portable authority data entering or leaving the system. |
| `audit/` and `sovereignty_core/audit/` | Record, chain, and verify audit evidence. |
| `conformance/` | Produce and evaluate protocol conformance evidence. |
| `tools/` | Register, validate, execute, and audit governed tools. |
| `errors/` and `utils/` | Provide protocol failure codes, exceptions, canonical data handling, serialization, and hashing. |

## Architecture and Protocol Documentation

Read these documents by purpose rather than treating the repository as a single monolith:

1. **Governance:** Start with `CHARTER.md` and `ARCHITECTURE_RULES.md` for non-negotiable system rules.
2. **Authority model:** Read `docs/architecture/authority_lifecycle.md` and `docs/architecture/boundary_model.md` to understand how authority is initialized, scoped, delegated, and audited.
3. **Implementation details:** Consult the remaining `docs/architecture/` documents for deployment, registry, and dashboard decisions.
4. **Protocol requirements:** Use `docs/rfc/` and `RFC/` when changing authority semantics, data formats, or compatibility behavior.
5. **Verification:** Use `docs/conformance/test_matrix.md` and `docs/conformance/failure_codes.md` with the tests in `tests/`.

## Development Workflow

1. Install local development dependencies with `bash scripts/bootstrap.sh`, or use the commands in [Quick Verification](#quick-verification).
2. Make a focused change in the module that owns the behavior.
3. Run `bash scripts/run_tests.sh` for the Python suite and `npm test` for dashboard checks.
4. Run `bash scripts/lint_dashboard.sh` when dashboard JavaScript changes.
5. Review the relevant architecture and RFC documents when a change affects authority semantics.
6. Follow the branch and pull-request rules above before sharing work.

## FedRAMP Phase 4 Hardening (Internal Evidence Phase)

This branch includes FedRAMP Rev. 5 Phase 4 internal hardening work focused on evidence-readiness and repeatable controls verification:

- Deterministic and pinned Python and npm dependency baselines.
- SBOM generation with freshness validation checks.
- Pinned GitHub Actions usage and read-only workflow permissions defaults.
- Fail-closed Docker/Nginx and offline deployment defaults.
- Cloud and dependency inventory evidence artifacts.
- Continuous monitoring and evidence-check workflows.
- Internal control-to-evidence mapping and security decision records.
- Portable `sia.cloud-egress.v1` envelope documentation in `docs/architecture/cloud_egress_protection.md` and `RFC/SIA-EP-0001.md`.

This hardening is for internal FedRAMP Rev. 5 evidence-readiness only and does **not** claim FedRAMP authorization, ATO, or certification.

The phase keeps core workflows offline-first and records optional cloud integrations, CI dependencies, deployment boundaries, and supporting evidence in:

## FedRAMP Phase 4 Hardening (Internal)

This repository's FedRAMP Phase 4 work is an internal FedRAMP Rev. 5 evidence-readiness and cloud/dependency-hardening phase. It is not a FedRAMP authorization or certification claim.

The phase keeps the core workflow offline-first and records optional cloud integrations, CI dependencies, deployment boundaries, and their evidence sources in:

- [`cloud_dependency_inventory.json`](docs/compliance/fedramp_phase4/cloud_dependency_inventory.json) — machine-readable dependency and trust-boundary inventory.
- [`control_evidence_matrix.md`](docs/compliance/fedramp_phase4/control_evidence_matrix.md) — internal mapping to NIST SP 800-53 control families.
- [`continuous_monitoring.md`](docs/compliance/fedramp_phase4/continuous_monitoring.md) — repeatable evidence checks and exception requirements.
- [`security_decision_record_index.md`](docs/compliance/fedramp_phase4/security_decision_record_index.md) — security decisions and supporting evidence.
- [`sbom.json`](docs/compliance/fedramp_phase4/sbom.json) — reproducible software bill of materials.

### Verification

Run:

```bash
python scripts/check_dependency_policy.py
python scripts/generate_sbom.py --check docs/compliance/fedramp_phase4/sbom.json
python scripts/validate_cloud_config.py
pytest
npm test
```

Run the phase-specific checks locally:

```bash
python scripts/check_dependency_policy.py
python scripts/validate_cloud_config.py
python scripts/generate_sbom.py --check docs/compliance/fedramp_phase4/sbom.json
```

---

## What's New — FedRAMP Schema Support & SBP v0.2

This section documents the improvements added in the `copilot/add-fedramp-schema-support` branch.

### FedRAMP Package Overview Schema (`docs/compliance/fedramp/`)

Two JSON Schema Draft 2020-12 definitions were added to support FedRAMP evidence automation:

| File | Purpose |
|------|---------|
| `fedramp-package-overview.schema.json` | Core FedRAMP Certification Package Overview metadata (FRC-CSO-PKG) |
| `x-sovereignty-extension.schema.json` | `x-sovereignty` extension namespace for authority-chain, Merkle-ledger, and ML-DSA attestation metadata (v1.1.0) |
| `SCHEMA_LAYERING.md` | Layering guide: how the core FedRAMP schema and the `x-sovereignty` extension relate, plus NIST SP 800-53 Rev. 5 control mapping and ML-DSA attestation examples |

The `x-sovereignty` extension (v1.1.0) declares:

- **Versioned authority**: `authorityId`, `authorityVersion`, `authorityFingerprint`, `authorityPolicyVersion`, `evidenceDigest`
- **Merkle evidence**: `merkleRoot`, `merkleRootAlgorithm`, `merkleTreeFormat`, `canonicalizationVersion`, `leafHashAlgorithm`
- **SCAR audit chain**: `auditChainId`, `scarLedgerReference`
- **ML-DSA attestation**: inline signature or external attestation-bundle reference (supports `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`)
- **SBP capability negotiation**: `sovereigntyProtocol` block declaring SBP name, semantic version, and supported capabilities

Validation note: these schemas are internal evidence-readiness tools. They do **not** claim FedRAMP authorization, ATO, or certification.

Example documents:

| File | Description |
|------|-------------|
| `examples/valid-core-package.json` | Minimum valid core package (no x-sovereignty) |
| `examples/valid-with-sovereignty.json` | Full package with x-sovereignty and ML-DSA attestation reference |
| `examples/invalid-missing-required.json` | Expected-to-fail: missing required top-level fields |
| `examples/invalid-bad-format.json` | Expected-to-fail: invalid enum/format values |

### SBP v0.2 Protocol Contracts (`src/sbp/protocol.py`)

The Sovereignty Boundary Protocol (SBP) v0.2 offline contract layer was added. All contracts are transport-independent and offline-first.

Algorithm suite: `SBP-INTEROP-0.2/Ed25519-SHA3-512-AES-256-GCM`

| Primitive | Description |
|-----------|-------------|
| `CapabilityOffer` | Peer-to-peer capability advertisement and negotiation |
| `AuthorityExchange` | Binds peer identity to an Ed25519 public root key |
| `Delegation` | Root-signed, capability-scoped, subset-enforced grant with optional expiry |
| `ReplicationRecord` | Encrypted `ObjectEnvelope` synchronization record (backup/sync only, no authority transfer) |
| `negotiate_capabilities` | Fail-closed intersection of two `CapabilityOffer` sets |
| `verify_authority_exchange` | Verifies an `AuthorityExchange` against its root signature |
| `verify_delegation` | Verifies a `Delegation` against the issuing root signature, optional expiry, and required capability |
| `resolve_replication_conflict` | Deterministic conflict resolution for concurrent replication records |

### SBP v0.2 Conformance Vectors (`tests/sbp_protocol/`)

Executable vector conformance suite implementing RFC-SBP-0006:

- Normative JSON vectors in `tests/sbp_protocol/vectors/` (capability negotiation, authority exchange, delegation, branch creation, audit events, replication)
- Vectors contain no private keys and are fully reproducible offline
- Conformance RFC: `docs/rfc/RFC-SBP-0006-Protocol-Conformance.md`

### Schema Conformance Tests (`tests/conformance/test_fedramp_package_schema.py`)

pytest suite covering:

- Valid core and valid x-sovereignty documents
- All ML-DSA FIPS 204 parameter sets (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`)
- Both attestation discriminator kinds (`inline-signature`, `attestation-reference`)
- Missing required fields and invalid enum/format values
- Conditional validation (`authenticationRequired → authenticationMechanism`)
- Digest algorithm and pattern validation
- x-sovereignty field constraints

Run schema conformance tests:

```bash
python3 -m pytest tests/conformance/test_fedramp_package_schema.py -v
python3 -m pytest tests/sbp_protocol/ -v
```

### Repository map additions

| Location | What it contains |
|----------|-----------------|
| `docs/compliance/fedramp/` | FedRAMP Package Overview and x-sovereignty extension schemas, layering guide, and example documents |
| `docs/rfc/RFC-SBP-0006-Protocol-Conformance.md` | Normative SBP v0.2 protocol conformance RFC |
| `src/sbp/protocol.py` | SBP v0.2 transport-independent protocol contracts |
| `tests/sbp_protocol/` | SBP v0.2 vector conformance suite |
| `tests/conformance/test_fedramp_package_schema.py` | JSON schema validation tests for FedRAMP and x-sovereignty artifacts |
