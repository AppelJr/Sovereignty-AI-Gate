"""
RFC-0014: Memory conformance tests.

Tests memory schema validation, consent enforcement, and scoping rules.
"""
import json
from pathlib import Path

import pytest

from sia.memory.models import MemoryRecord
from sia.memory.validator import assert_read_access, validate_record
from sia.errors.exceptions import MemoryConsentDeniedError, MemorySchemaError

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_valid_memory_fixture():
    data = json.loads((FIXTURES / "valid_memory.json").read_text())
    record = MemoryRecord.from_dict(data)
    validate_record(record)  # must not raise


def test_memory_schema_missing_record_id():
    record = MemoryRecord(
        record_id="",
        model_id="model:gpt4",
        content={},
    )
    with pytest.raises(MemorySchemaError):
        validate_record(record)


def test_memory_schema_missing_model_id():
    record = MemoryRecord(
        record_id="mem-001",
        model_id="",
        content={},
    )
    with pytest.raises(MemorySchemaError):
        validate_record(record)


def test_memory_owner_can_read():
    record = MemoryRecord(
        record_id="mem-001",
        model_id="model:gpt4",
        content={"text": "hello"},
    )
    assert_read_access(record, "model:gpt4")  # must not raise


def test_memory_consent_denied():
    record = MemoryRecord(
        record_id="mem-001",
        model_id="model:gpt4",
        content={"text": "hello"},
        consent=[],
    )
    with pytest.raises(MemoryConsentDeniedError):
        assert_read_access(record, "model:claude")


def test_memory_consent_granted():
    record = MemoryRecord(
        record_id="mem-001",
        model_id="model:gpt4",
        content={"text": "hello"},
        consent=["model:claude"],
    )
    assert_read_access(record, "model:claude")  # must not raise


def test_memory_roundtrip():
    record = MemoryRecord(
        record_id="mem-rtx",
        model_id="model:gpt4",
        content={"key": "value"},
        consent=["model:claude"],
    )
    restored = MemoryRecord.from_dict(record.to_dict())
    assert restored.record_id == record.record_id
    assert restored.model_id == record.model_id
    assert restored.consent == record.consent
