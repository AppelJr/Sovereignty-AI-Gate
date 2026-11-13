"""
Root-of-trust abstractions for the Sovereign AI Memory Architecture.

The root layer defines the stable contract that higher SAMA layers depend
on. SoftwareTrustBackend performs real Ed25519 signatures but cannot claim
hardware-backed key protection. Production deployments should supply
platform-backed adapters that keep root material inside a secure device
boundary.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import secrets
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


class RootTrustError(RuntimeError):
    """Raised when a root-of-trust operation cannot be completed."""


class TrustBackend(ABC):
    """
    Stable backend contract for device-rooted trust material.

    Higher layers depend on this interface rather than platform-specific
    hardware APIs.
    """

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Return a stable identifier for the backend implementation."""

    @property
    @abstractmethod
    def hardware_backed(self) -> bool:
        """Return whether the backend is backed by secure hardware."""

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """
        Return the signing algorithm identifier for this backend.

        Return a standard identifier such as ``"Ed25519"`` or
        ``"ML-DSA-87"``.
        """

    @abstractmethod
    def public_key_bytes(self) -> bytes:
        """Return public root material that is safe to expose."""

    @abstractmethod
    def sign(self, payload: bytes) -> str:
        """Sign payload bytes without exposing root material."""

    @abstractmethod
    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify a signature produced by this backend."""

    @abstractmethod
    def derive_key(self, context: bytes, *, length: int = 32) -> bytes:
        """Derive deterministic key material for a scoped local purpose."""

    @abstractmethod
    def best_effort_destroy(self) -> None:
        """
        Best-effort cleanup of in-memory authority material.

        Python cannot guarantee secure erasure; hardware adapters may offer
        stronger deletion semantics.
        """


class SoftwareTrustBackend(TrustBackend):
    """
    Software Ed25519 backend that stores root material in process memory.

    This backend uses real asymmetric signatures, but it must not be treated
    as a hardware root because its private material is process-resident.
    """

    _ALGORITHM = "Ed25519"

    def __init__(self, root_secret: bytes | None = None) -> None:
        self._root_secret = root_secret or secrets.token_bytes(32)
        private_bytes = hashlib.sha3_512(
            b"SAMA_ED25519_PRIVATE:" + self._root_secret
        ).digest()[:32]
        self._private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        self._public_key = self._private_key.public_key()

    @property
    def backend_name(self) -> str:
        return "software-ed25519"

    @property
    def hardware_backed(self) -> bool:
        return False

    @property
    def algorithm(self) -> str:
        return self._ALGORITHM

    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, payload: bytes) -> str:
        return self._private_key.sign(payload).hex()

    def verify(self, payload: bytes, signature: str) -> bool:
        try:
            self._public_key.verify(bytes.fromhex(signature), payload)
        except (ValueError, TypeError):
            return False
        except Exception:
            return False
        return True

    def derive_key(self, context: bytes, *, length: int = 32) -> bytes:
        if length <= 0:
            raise RootTrustError("Derived key length must be positive")

        output = bytearray()
        counter = 0
        while len(output) < length:
            block = hashlib.sha3_512(
                b"SAMA_DERIVE:" + counter.to_bytes(4, "big") + context + self._root_secret
            ).digest()
            output.extend(block)
            counter += 1
        return bytes(output[:length])

    def best_effort_destroy(self) -> None:
        self._root_secret = b""
        self._private_key = None


@dataclass(frozen=True)
class DeviceIdentity:
    """Public device identity derived deterministically from root authority."""

    identity_id: str
    public_key: str
    backend_name: str
    hardware_backed: bool
    created_at: int
    version: int = 1


@dataclass(frozen=True)
class SignedObject:
    """Signature envelope for sovereignty objects."""

    payload_hash: str
    signature: str
    signer: str
    timestamp: int
    algorithm: str = "Ed25519"


class RootOfTrust:
    """
    Stable SAMA contract for device-rooted authority.

    Responsibilities:
    - expose public device identity
    - derive deterministic local-only authority material
    - sign sovereignty objects without exposing private root material
    """

    def __init__(self, backend: TrustBackend | None = None) -> None:
        self._backend = backend or SoftwareTrustBackend()
        self._identity = self._create_identity()

    @property
    def backend(self) -> TrustBackend:
        """Return the configured root backend."""

        return self._backend

    @property
    def identity(self) -> DeviceIdentity:
        """Return the public device identity."""

        return self._identity

    def _create_identity(self) -> DeviceIdentity:
        public_material = self._backend.public_key_bytes()
        identity_id = hashlib.sha3_512(b"SAMA_IDENTITY:" + public_material).hexdigest()
        return DeviceIdentity(
            identity_id=identity_id,
            public_key=public_material.hex(),
            backend_name=self._backend.backend_name,
            hardware_backed=self._backend.hardware_backed,
            created_at=int(time.time()),
        )

    def derive_identity_key(self) -> bytes:
        """Derive local identity-scoped key material."""

        return self._backend.derive_key(b"SAMA_IDENTITY_KEY", length=32)

    def derive_vault_key(self) -> bytes:
        """
        Derive local vault key material.

        Vault key material remains separate from identity key material and
        must never be exposed to providers.
        """

        return self._backend.derive_key(b"SAMA_VAULT_KEY", length=32)

    def sign(self, payload: bytes) -> SignedObject:
        """Sign payload bytes using the configured backend."""

        payload_hash = hashlib.sha3_512(payload).hexdigest()
        signature = self._backend.sign(payload)
        return SignedObject(
            payload_hash=payload_hash,
            signature=signature,
            signer=self.identity.identity_id,
            timestamp=int(time.time()),
            algorithm=self._backend.algorithm,
        )

    def verify(self, payload: bytes, signed: SignedObject) -> bool:
        """Verify payload integrity and backend signature."""

        expected_hash = hashlib.sha3_512(payload).hexdigest()
        if expected_hash != signed.payload_hash:
            return False
        return self._backend.verify(payload, signed.signature)

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verification hook for higher-layer signed objects."""

        return self._backend.verify(payload, signature)

    def export_public_identity(self) -> dict[str, object]:
        """Return a serializable public-only identity document."""

        return {
            "identity_id": self.identity.identity_id,
            "public_key": self.identity.public_key,
            "backend_name": self.identity.backend_name,
            "hardware_backed": self.identity.hardware_backed,
            "created_at": self.identity.created_at,
            "version": self.identity.version,
        }

    def best_effort_destroy(self) -> None:
        """Best-effort cleanup of local authority material."""

        self._backend.best_effort_destroy()
