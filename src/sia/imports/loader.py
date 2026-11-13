"""
Imports: loader.

RFC-0019 canonical import loader.
"""
from __future__ import annotations

import json
from typing import Any

from sia.errors import codes
from sia.errors.exceptions import ImportError as SIAImportError
from sia.export.models import ExportBundle
from sia.export.validator import validate_bundle
from sia.imports.models import ImportBundle, ImportedLedger
from sia.imports.validator import validate_import_payload


class BundleLoader:
    """Stateful loader that tracks imported bundles and rejects duplicates."""

    def __init__(self) -> None:
        self._seen: dict[str, ImportBundle] = {}

    def load(self, bundle: ImportBundle) -> None:
        """Load *bundle*, raising SIAImportError on duplicate bundle_id."""
        if bundle.bundle_id in self._seen:
            raise SIAImportError(
                code=codes.E_IMPORT_DUPLICATE,
                message=f"bundle already imported: {bundle.bundle_id!r}",
            )
        self._seen[bundle.bundle_id] = bundle

    def list_bundles(self) -> list[ImportBundle]:
        """Return all loaded bundles in insertion order."""
        return list(self._seen.values())


def import_ledger(envelope) -> ImportedLedger:
    if not isinstance(envelope, ExportBundle):
        raise SIAImportError(
            code=codes.E_IMPORT_LOAD_FAILED,
            message="canonical ExportBundle required",
        )

    validate_bundle(envelope)
    decoded = json.loads(json.dumps(envelope.payload))
    validate_import_payload(decoded)

    return ImportedLedger(
        ledger_version=decoded["ledger_version"],
        ledger_hash=decoded["ledger_hash"],
        records=tuple(decoded["records"]),
    )
