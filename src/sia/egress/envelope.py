"""Versioned, portable authenticated-encryption envelopes for cloud egress.

This module performs no network I/O. A caller must explicitly seal data before
sending it to storage or a recipient that can decrypt this format.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from sia.utils.canonical import canonical_bytes, canonical_json

_SCHEMA = "sia.cloud-egress.v1"
_SUITE = "SIA-E1"
_KDF = "argon2id"
_KDF_PARAMS = {"iterations": 3, "lanes": 4, "memory_cost": 65536, "length": 32}
_SALT_BYTES = 16
_NONCE_BYTES = 12
_KEY_BYTES = 32
_RECIPIENT_NAMESPACES = frozenset({"provider", "vault", "device", "storage", "peer"})
_AAD_FIELDS = (
    "schema",
    "suite",
    "kdf",
    "kdf_params",
    "recipient_id",
    "content_type",
    "created",
    "expires",
)


class EgressEnvelopeError(ValueError):
    """Raised for malformed, tampered, expired, or undecryptable envelopes."""


@dataclass(frozen=True)
class CloudEgressEnvelope:
    """A JSON-serializable envelope shared across language implementations.

    Recipient routing metadata is visible but authenticated as AES-GCM
    additional authenticated data. Payload bytes and the passphrase never
    appear in the envelope.
    """

    schema: str
    suite: str
    kdf: str
    kdf_params: dict[str, int]
    recipient_id: str
    content_type: str
    created: str
    expires: str | None
    salt: str
    nonce: str
    ciphertext: str
    envelope_id: str

    @classmethod
    def seal(
        cls,
        plaintext: bytes,
        *,
        passphrase: str,
        recipient_id: str,
        content_type: str = "application/octet-stream",
        created: str | None = None,
        expires: str | None = None,
    ) -> "CloudEgressEnvelope":
        """Encrypt bytes for explicit egress with a user-supplied shared secret."""
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not isinstance(passphrase, str) or not passphrase:
            raise ValueError("passphrase must be a non-empty string")
        _validate_recipient_id(recipient_id)
        if not isinstance(content_type, str) or not content_type:
            raise ValueError("content_type is required")

        created = created or _utc_now()
        _validate_timestamp(created, "created")
        if expires is not None:
            _validate_timestamp(expires, "expires")
            if _parse_timestamp(expires) <= _parse_timestamp(created):
                raise ValueError("expires must be after created")

        salt = secrets.token_bytes(_SALT_BYTES)
        nonce = secrets.token_bytes(_NONCE_BYTES)
        header = {
            "schema": _SCHEMA,
            "suite": _SUITE,
            "kdf": _KDF,
            "kdf_params": _KDF_PARAMS.copy(),
            "recipient_id": recipient_id,
            "content_type": content_type,
            "created": created,
            "expires": expires,
        }
        ciphertext = AESGCM(cls._derive_key(passphrase, salt)).encrypt(
            nonce, plaintext, canonical_bytes(header)
        )
        value = {
            **header,
            "salt": _b64encode(salt),
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
        }
        return cls(envelope_id=_envelope_id(value), **value)

    def open(self, *, passphrase: str, recipient_id: str) -> bytes:
        """Authenticate metadata and decrypt the payload for its recipient."""
        self._validate()
        if self.expires is not None and _parse_timestamp(self.expires) <= datetime.now(UTC):
            raise EgressEnvelopeError("Envelope has expired")
        if recipient_id != self.recipient_id:
            raise EgressEnvelopeError("Envelope recipient does not match")
        try:
            salt = _b64decode(self.salt, "salt")
            nonce = _b64decode(self.nonce, "nonce")
            ciphertext = _b64decode(self.ciphertext, "ciphertext")
        except ValueError as exc:
            raise EgressEnvelopeError("Envelope encoding is invalid") from exc
        if len(salt) != _SALT_BYTES or len(nonce) != _NONCE_BYTES or not ciphertext:
            raise EgressEnvelopeError("Envelope parameters are invalid")
        try:
            return AESGCM(self._derive_key(passphrase, salt)).decrypt(
                nonce, ciphertext, canonical_bytes(self._authenticated_header())
            )
        except (InvalidTag, ValueError) as exc:
            raise EgressEnvelopeError(
                "Envelope authentication failed or passphrase is incorrect"
            ) from exc

    def to_dict(self) -> dict[str, Any]:
        """Return the portable JSON envelope object."""
        return {
            "schema": self.schema,
            "suite": self.suite,
            "kdf": self.kdf,
            "kdf_params": self.kdf_params,
            "recipient_id": self.recipient_id,
            "content_type": self.content_type,
            "created": self.created,
            "expires": self.expires,
            "salt": self.salt,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
            "envelope_id": self.envelope_id,
        }

    def to_json(self) -> str:
        """Return canonical JSON suitable for storage or transmission."""
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CloudEgressEnvelope":
        """Validate and construct a portable envelope from decoded JSON."""
        expected = {
            "schema", "suite", "kdf", "kdf_params", "recipient_id", "content_type",
            "created", "expires", "salt", "nonce", "ciphertext", "envelope_id",
        }
        if set(value) != expected:
            raise EgressEnvelopeError("Envelope schema is invalid")
        string_fields = expected - {"kdf_params", "expires"}
        if any(not isinstance(value[key], str) for key in string_fields):
            raise EgressEnvelopeError("Envelope schema is invalid")
        if value["expires"] is not None and not isinstance(value["expires"], str):
            raise EgressEnvelopeError("Envelope schema is invalid")
        if value["kdf_params"] != _KDF_PARAMS:
            raise EgressEnvelopeError("Envelope KDF parameters are not supported")
        envelope = cls(**{key: value[key] for key in expected})
        envelope._validate()
        return envelope

    def _validate(self) -> None:
        if self.schema != _SCHEMA or self.suite != _SUITE or self.kdf != _KDF:
            raise EgressEnvelopeError("Envelope algorithm suite is not supported")
        if self.kdf_params != _KDF_PARAMS:
            raise EgressEnvelopeError("Envelope KDF parameters are not supported")
        try:
            _validate_recipient_id(self.recipient_id)
            _validate_timestamp(self.created, "created")
            if self.expires is not None:
                _validate_timestamp(self.expires, "expires")
                if _parse_timestamp(self.expires) <= _parse_timestamp(self.created):
                    raise ValueError("expires must be after created")
        except ValueError as exc:
            raise EgressEnvelopeError("Envelope metadata is invalid") from exc
        if self.envelope_id != _envelope_id(self._without_envelope_id()):
            raise EgressEnvelopeError("Envelope identifier is invalid")

    def _without_envelope_id(self) -> dict[str, Any]:
        value = self.to_dict()
        del value["envelope_id"]
        return value

    def _authenticated_header(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in _AAD_FIELDS}

    @staticmethod
    def _derive_key(passphrase: str, salt: bytes) -> bytes:
        if not isinstance(passphrase, str) or not passphrase:
            raise ValueError("passphrase must be a non-empty string")
        return Argon2id(salt=salt, **_KDF_PARAMS).derive(passphrase.encode("utf-8"))


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_timestamp(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{name} must be an ISO-8601 UTC timestamp")
    parsed = _parse_timestamp(value)
    if parsed.tzinfo != UTC:
        raise ValueError(f"{name} must be an ISO-8601 UTC timestamp")


def _validate_recipient_id(value: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        raise ValueError("recipient_id must use a registered namespace")
    namespace, name = value.split(":", 1)
    if namespace not in _RECIPIENT_NAMESPACES or not name:
        raise ValueError("recipient_id must use a registered namespace")


def _envelope_id(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: str, name: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError(f"{name} is not URL-safe base64") from exc
