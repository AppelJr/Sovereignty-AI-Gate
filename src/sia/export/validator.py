"""
Export: validator.

Validates ExportBundle objects before signing and before accepting
an inbound bundle from a remote operator.
"""
from __future__ import annotations

from sia.errors import codes
from sia.errors.exceptions import ExportError
from sia.export.models import ExportBundle, EXPORT_SCHEMA_VERSION
from sia.utils.hashing import hash_object

REQUIRED_FIELDS = {
    "bundle_id", "created_by", "payload", "payload_hash",
    "signature", "schema_version",
}


def validate_bundle(bundle: ExportBundle) -> None:
    """
    Validate an ExportBundle's structure and payload hash integrity.

    Does NOT verify the cryptographic signature (that requires the
    public key of the signer and is handled by the import layer).

    Raises:
        ExportError: if any validation check fails.
    """
    d = bundle.to_dict()

    # Required fields
    missing = REQUIRED_FIELDS - d.keys()
    if missing:
        raise ExportError(
            codes.E_EXPORT_BUNDLE_INCOMPLETE,
            f"Missing required export fields: {missing}",
        )

    # Schema version
    if d["schema_version"] != EXPORT_SCHEMA_VERSION:
        raise ExportError(
            codes.E_EXPORT_SCHEMA_INVALID,
            f"Unsupported export schema version '{d['schema_version']}'.",
        )

    # Non-empty required strings
    for field_name in ("bundle_id", "created_by", "payload_hash", "signature"):
        if not isinstance(d[field_name], str) or not d[field_name]:
            raise ExportError(
                codes.E_EXPORT_SCHEMA_INVALID,
                f"'{field_name}' must be a non-empty string.",
            )

    # Payload hash integrity
    expected_hash = hash_object(d["payload"])
    if d["payload_hash"] != expected_hash:
        raise ExportError(
            codes.E_EXPORT_SCHEMA_INVALID,
            f"payload_hash mismatch: expected {expected_hash}.",
        )
