"""
Imports: validator.

Validate canonical RFC-0019 import payloads.
"""
from __future__ import annotations

from sia.errors import codes
from sia.errors.exceptions import ImportError as SIAImportError
from sia.imports.models import SUPPORTED_VERSIONS
from sia.utils.hashing import hash_object


REQUIRED_FIELDS = {"ledger_version", "ledger_hash", "records"}


def validate_import(bundle) -> None:
    """Validate an ImportBundle: version check and hash integrity."""
    if bundle.schema_version not in SUPPORTED_VERSIONS:
        raise SIAImportError(
            code=codes.E_IMPORT_VERSION_UNSUPPORTED,
            message=f"unsupported import schema version: {bundle.schema_version!r}",
        )
    expected = hash_object(bundle.payload)
    if bundle.payload_hash != expected:
        raise SIAImportError(
            code=codes.E_IMPORT_SCHEMA_INVALID,
            message="import payload hash mismatch",
        )


def validate_import_payload(payload: dict) -> None:
    missing = REQUIRED_FIELDS - payload.keys()
    if missing:
        raise SIAImportError(
            code=codes.E_IMPORT_SCHEMA_INVALID,
            message="required import fields missing",
        )
    if not isinstance(payload["records"], list):
        raise SIAImportError(
            code=codes.E_IMPORT_SCHEMA_INVALID,
            message="records must be ordered list",
        )
    for record in payload["records"]:
        if not isinstance(record, dict):
            raise SIAImportError(
                code=codes.E_IMPORT_SCHEMA_INVALID,
                message="record must be object",
            )
