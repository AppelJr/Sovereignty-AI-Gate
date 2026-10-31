"""
RFC-0018: Export bundle conformance tests.
"""
import json
from pathlib import Path

import pytest

from sia.export.models import ExportBundle
from sia.export.validator import validate_bundle
from sia.errors import codes
from sia.errors.exceptions import ExportError
from sia.utils.hashing import hash_object

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_valid_export_fixture():
    data = json.loads((FIXTURES / "valid_export.json").read_text())
    bundle = ExportBundle.from_dict(data)
    validate_bundle(bundle)  # must not raise


def test_export_payload_hash_mismatch():
    payload = {"data": "x"}
    bundle = ExportBundle(
        bundle_id="e001",
        created_by="user:alice",
        payload=payload,
        payload_hash="badhash",
        signature="a" * 128,
    )
    with pytest.raises(ExportError) as exc_info:
        validate_bundle(bundle)
    assert exc_info.value.code == codes.E_EXPORT_SCHEMA_INVALID


def test_export_missing_bundle_id():
    payload = {"data": "x"}
    h = hash_object(payload)
    bundle = ExportBundle(
        bundle_id="",  # empty
        created_by="user:alice",
        payload=payload,
        payload_hash=h,
        signature="a" * 128,
    )
    with pytest.raises(ExportError) as exc_info:
        validate_bundle(bundle)
    assert exc_info.value.code == codes.E_EXPORT_SCHEMA_INVALID


def test_export_roundtrip():
    payload = {"boundaries": [], "version": "0.1.0"}
    h = hash_object(payload)
    bundle = ExportBundle(
        bundle_id="e002",
        created_by="user:alice",
        payload=payload,
        payload_hash=h,
        signature="b" * 128,
    )
    validate_bundle(bundle)
    restored = ExportBundle.from_dict(bundle.to_dict())
    assert restored.bundle_id == bundle.bundle_id
    assert restored.payload_hash == bundle.payload_hash
