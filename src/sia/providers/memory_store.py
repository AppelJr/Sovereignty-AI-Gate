"""
Per-provider encrypted memory store.

One JSON file per canonical provider ID, stored at::

    ~/.sia/providers/<provider_id_underscored>.json

File layout::

    {
        "schema_version": "1.0",
        "provider_id": "<canonical_id>",
        "records": [ <MemoryRecord.to_dict()>, ... ]
    }

Encryption
----------
The entire JSON payload is encrypted at rest using Fernet (AES-128-CBC with
an authenticated encryption construction — part of the ``cryptography`` package already declared as a
project dependency).  The Fernet key is derived deterministically from the
device ``RootOfTrust`` so that the file is readable only on the device that
created it.

Consent
-------
``read_records()`` enforces ``MemoryRecord.has_consent(requesting_provider_id)``
on every record before returning it.  Records that fail the consent check are
silently omitted; the caller receives only records it is authorised to read.

Atomic writes
-------------
Writes go to ``<file>.tmp``, fsync, then os.replace() — the file is never
in a partially-written state.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Sequence

from cryptography.fernet import Fernet, InvalidToken

from sia.errors.exceptions import MemoryConsentDeniedError, MemoryDecryptError
from sia.memory.models import MemoryRecord
from sovereignty_core.identity.root_of_trust import RootOfTrust

_SCHEMA_VERSION = "1.0"
_KEY_CONTEXT_PREFIX = b"SAMA_PROVIDER_MEMORY:"


class ProviderMemoryStore:
    """
    Encrypted, consent-enforced, per-provider memory file store.

    Parameters
    ----------
    provider_id:
        Canonical provider ID (e.g. ``"xai.grok"``).
    root_of_trust:
        Device root-of-trust used to derive the AES key.  The same device
        must be used for both writes and reads.
    base_dir:
        Override the default ``~/.sia/providers/`` directory.  Useful for
        tests.
    """

    def __init__(
        self,
        provider_id: str,
        root_of_trust: RootOfTrust,
        base_dir: Path | None = None,
    ) -> None:
        self._provider_id = provider_id
        self._root_of_trust = root_of_trust
        safe_name = provider_id.replace(".", "_")
        dir_path = (base_dir or Path("~/.sia/providers")).expanduser()
        self._file_path = dir_path / f"{safe_name}.json"
        self._fernet = self._build_fernet()

    # ── Public interface ──────────────────────────────────────────────────────

    @property
    def file_path(self) -> Path:
        """Return the absolute path to the provider memory file."""
        return self._file_path

    def write_records(self, records: Sequence[MemoryRecord]) -> None:
        """
        Encrypt and atomically write *records* to the provider memory file.

        The file is created (including parent directories) if it does not
        exist.  Existing content is replaced.
        """
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "provider_id": self._provider_id,
            "records": [r.to_dict() for r in records],
        }
        plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        ciphertext = self._fernet.encrypt(plaintext)
        self._atomic_write(ciphertext)

    def append_record(self, record: MemoryRecord) -> None:
        """
        Append *record* to the provider memory file.

        If the file does not exist an empty list is assumed.
        """
        existing = self._load_raw_records()
        existing.append(record.to_dict())
        new_records = [MemoryRecord.from_dict(d) for d in existing]
        self.write_records(new_records)

    def read_records(
        self,
        requesting_provider_id: str,
    ) -> list[MemoryRecord]:
        """
        Decrypt and return records that *requesting_provider_id* is allowed to read.

        Consent is checked via ``MemoryRecord.has_consent()``.  Records that
        fail the consent check are omitted; the return value only contains
        authorised records.

        Raises ``MemoryDecryptError`` if the file cannot be decrypted.
        """
        raw = self._load_raw_records()
        result: list[MemoryRecord] = []
        for d in raw:
            rec = MemoryRecord.from_dict(d)
            if rec.has_consent(requesting_provider_id):
                result.append(rec)
        return result

    def read_record_strict(
        self,
        record_id: str,
        requesting_provider_id: str,
    ) -> MemoryRecord:
        """
        Return a single record by ID.

        Raises ``MemoryConsentDeniedError`` if consent is not granted.
        Raises ``KeyError`` if the record does not exist.
        """
        raw = self._load_raw_records()
        for d in raw:
            if d.get("record_id") == record_id:
                rec = MemoryRecord.from_dict(d)
                if not rec.has_consent(requesting_provider_id):
                    raise MemoryConsentDeniedError(
                        f"Provider '{requesting_provider_id}' does not have consent "
                        f"to read record '{record_id}' owned by '{rec.model_id}'"
                    )
                return rec
        raise KeyError(f"Record '{record_id}' not found in provider '{self._provider_id}' store")

    def file_exists(self) -> bool:
        """Return True if the encrypted memory file exists on disk."""
        return self._file_path.exists()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_fernet(self) -> Fernet:
        """Derive a Fernet key from the device root-of-trust backend."""
        context = _KEY_CONTEXT_PREFIX + self._provider_id.encode("utf-8")
        raw_key = self._root_of_trust.backend.derive_key(context, length=32)
        fernet_key = base64.urlsafe_b64encode(raw_key)
        return Fernet(fernet_key)

    def _load_raw_records(self) -> list[dict]:
        """
        Read, decrypt, and parse the memory file.

        Returns an empty list if the file does not exist.
        Raises ``MemoryDecryptError`` on decryption or parse failure.
        """
        if not self._file_path.exists():
            return []
        try:
            ciphertext = self._file_path.read_bytes()
            plaintext = self._fernet.decrypt(ciphertext)
            payload = json.loads(plaintext.decode("utf-8"))
        except InvalidToken as exc:
            raise MemoryDecryptError(
                f"Cannot decrypt memory file for provider '{self._provider_id}': "
                "wrong device or corrupted file"
            ) from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MemoryDecryptError(
                f"Memory file for provider '{self._provider_id}' is not valid JSON after decryption"
            ) from exc
        return payload.get("records", [])

    def _atomic_write(self, ciphertext: bytes) -> None:
        """Write *ciphertext* atomically: tmp → fsync → rename."""
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = str(self._file_path) + ".tmp"
        with open(tmp_path, "wb") as fh:
            fh.write(ciphertext)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, self._file_path)
