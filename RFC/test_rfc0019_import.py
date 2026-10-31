"""
RFC-0019: Import bundle conformance tests.

Phase 1 extends the existing conformance suite with focused integrity tests.
The tests use the repository's real import validator, loader, hashing, and
SCAR Merkle implementation. They do not introduce a parallel import path.
"""
import json
from pathlib import Path

import pytest

from sia.imports.models import ImportBundle
from sia.imports.validator import validate_import
from sia.imports.loader import BundleLoader
from sia.errors import codes
from sia.errors.exceptions import ImportError as SIAImportError
from sia.utils.hashing import hash_object
from sovereignty_core.audit.merkle import (
    build_merkle_from_scarlog,
    generate_proof,
    verify_merkle_proof,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_valid_import_fixture():
    data = json.loads((FIXTURES / "valid_import.json").read_text())
    bundle = ImportBundle.from_dict(data)
    validate_import(bundle)  # must not raise


def test_import_duplicate_rejected():
    loader = BundleLoader()
    payload = {"boundaries": []}
    h = hash_object(payload)
    bundle = ImportBundle(
        bundle_id="imp-dup",
        created_by="user:bob",
        payload=payload,
        payload_hash=h,
        signature="c" * 128,
        created_at="2026-01-01T00:00:00+00:00",
    )
    loader.load(bundle)
    with pytest.raises(SIAImportError) as exc_info:
        loader.load(bundle)
    assert exc_info.value.code == codes.E_IMPORT_DUPLICATE


def test_import_hash_mismatch():
    bundle = ImportBundle(
        bundle_id="imp-bad",
        created_by="user:bob",
        payload={"data": "x"},
        payload_hash="wrong",
        signature="c" * 128,
        created_at="2026-01-01T00:00:00+00:00",
    )
    with pytest.raises(SIAImportError) as exc_info:
        validate_import(bundle)
    assert exc_info.value.code == codes.E_IMPORT_SCHEMA_INVALID


def test_import_unsupported_version():
    payload = {"data": "x"}
    h = hash_object(payload)
    bundle = ImportBundle(
        bundle_id="imp-v99",
        created_by="user:bob",
        payload=payload,
        payload_hash=h,
        signature="c" * 128,
        created_at="2026-01-01T00:00:00+00:00",
        schema_version="99.0",
    )
    with pytest.raises(SIAImportError) as exc_info:
        validate_import(bundle)
    assert exc_info.value.code == codes.E_IMPORT_VERSION_UNSUPPORTED


def test_import_roundtrip():
    payload = {"k": "v"}
    h = hash_object(payload)
    bundle = ImportBundle(
        bundle_id="imp-rt",
        created_by="user:bob",
        payload=payload,
        payload_hash=h,
        signature="d" * 128,
        created_at="2026-01-01T00:00:00+00:00",
    )
    restored = ImportBundle.from_dict(bundle.to_dict())
    assert restored.bundle_id == bundle.bundle_id


def test_import_loader_list():
    loader = BundleLoader()
    payload = {"x": 1}
    h = hash_object(payload)
    for i in range(3):
        bundle = ImportBundle(
            bundle_id=f"imp-list-{i}",
            created_by="user:bob",
            payload=payload,
            payload_hash=h,
            signature="e" * 128,
            created_at="2026-01-01T00:00:00+00:00",
        )
        loader.load(bundle)
    assert len(loader.list_bundles()) == 3


def _import_records() -> list[dict[str, object]]:
    """Return deterministic record fixtures for Merkle-only evidence tests."""
    return [
        {
            "sequence": 0,
            "event": "IDENTITY_CREATED",
            "payload_hash": "a" * 128,
        },
        {
            "sequence": 1,
            "event": "BOUNDARY_REGISTERED",
            "payload_hash": "b" * 128,
        },
        {
            "sequence": 2,
            "event": "DELEGATION_ISSUED",
            "payload_hash": "c" * 128,
        },
    ]


def test_import_records_have_verifiable_merkle_inclusion_proof():
    """Imported records can be independently checked as ordered evidence."""
    records = _import_records()
    tree = build_merkle_from_scarlog(records)
    proof = generate_proof(tree, 1)

    assert tree.root
    assert proof.leaf_hash == tree.leaves[1]
    assert verify_merkle_proof(proof) is True


def test_import_merkle_proof_rejects_tampered_leaf():
    records = _import_records()
    tree = build_merkle_from_scarlog(records)
    proof = generate_proof(tree, 1)
    tampered_proof = type(proof)(
        leaf_hash="f" * 128,
        siblings=proof.siblings,
        root=proof.root,
    )

    assert verify_merkle_proof(tampered_proof) is False


def test_import_record_order_is_bound_to_merkle_root():
    records = _import_records()
    reordered = [records[1], records[0], records[2]]

    original_root = build_merkle_from_scarlog(records).root
    reordered_root = build_merkle_from_scarlog(reordered).root

    assert original_root != reordered_root
