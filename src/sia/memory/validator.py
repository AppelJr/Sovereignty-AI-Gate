"""
Memory: validator.

Validates ``MemoryRecord`` objects against the schema requirements
defined in RFC-0014.
"""
from __future__ import annotations

from sia.errors.exceptions import MemoryConsentDeniedError, MemorySchemaError
from sia.memory.models import MemoryRecord

REQUIRED_FIELDS = {"record_id", "model_id", "content", "schema_version"}


def validate_record(record: MemoryRecord) -> None:
    """
    Validate *record* against RFC-0014 memory schema requirements.

    Raises:
        MemorySchemaError: if the record is structurally invalid.
    """
    d = record.to_dict()
    missing = REQUIRED_FIELDS - d.keys()
    if missing:
        raise MemorySchemaError(f"Missing required fields: {missing}")
    if not isinstance(d["record_id"], str) or not d["record_id"]:
        raise MemorySchemaError("'record_id' must be a non-empty string.")
    if not isinstance(d["model_id"], str) or not d["model_id"]:
        raise MemorySchemaError("'model_id' must be a non-empty string.")
    if d["schema_version"] not in ("1.0",):
        raise MemorySchemaError(
            f"Unsupported schema_version '{d['schema_version']}'."
        )
    if not isinstance(d.get("consent", []), list):
        raise MemorySchemaError("'consent' must be a list.")


def assert_read_access(record: MemoryRecord, requesting_model_id: str) -> None:
    """
    Assert that *requesting_model_id* has read access to *record*.

    Raises:
        MemoryConsentDeniedError: if consent has not been granted.
    """
    if not record.has_consent(requesting_model_id):
        raise MemoryConsentDeniedError(
            f"Model '{requesting_model_id}' does not have consent to read "
            f"memory owned by '{record.model_id}'."
        )
