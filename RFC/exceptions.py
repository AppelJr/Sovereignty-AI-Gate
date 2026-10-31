"""
Exceptions for the Sovereignty AI Gate.

All SIA exceptions carry an error code from `sia.errors.codes` and a
human-readable message. Callers should catch `SIAError` for broad
handling or specific subclasses for targeted handling.
"""
from __future__ import annotations

from sia.errors import codes


class SIAError(Exception):
    """Base exception for all Sovereignty AI Gate errors."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        self.message = message or codes.describe(code)
        super().__init__(f"[{self.code}] {self.message}")

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


class AuthorityFailure(SIAError):
    """General-purpose authority-level failure."""

    def __init__(
        self,
        code: str,
        message: str | None = None,
        rfc: str | None = None,
    ) -> None:
        self.rfc = rfc
        super().__init__(code, message)


# ── Authority ──────────────────────────────────────────────────────────────────

class NotInitializedError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_NOT_INITIALIZED, message)


class InvalidIdentityError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_INVALID_IDENTITY, message)


class BoundaryViolationError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_BOUNDARY_VIOLATION, message)


class PolicyDeniedError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_POLICY_DENIED, message)


class SignatureInvalidError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_SIGNATURE_INVALID, message)


class HashMismatchError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_HASH_MISMATCH, message)


# ── Memory ─────────────────────────────────────────────────────────────────────

class MemoryDecryptError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_MEMORY_DECRYPT_FAILED, message)


class MemoryConsentDeniedError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_MEMORY_CONSENT_DENIED, message)


class MemorySchemaError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_MEMORY_SCHEMA_INVALID, message)


# ── Delegation ─────────────────────────────────────────────────────────────────

class DelegationExpiredError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_DELEGATION_EXPIRED, message)


class DelegationScopeError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_DELEGATION_SCOPE_EXCEEDED, message)


class DelegationRevokedError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_DELEGATION_REVOKED, message)


class DelegationInvalidError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_DELEGATION_INVALID, message)


# ── Export ─────────────────────────────────────────────────────────────────────

class ExportError(SIAError):
    def __init__(self, code: str = codes.E_EXPORT_SIGNING_FAILED,
                 message: str | None = None) -> None:
        super().__init__(code, message)


# ── Import ─────────────────────────────────────────────────────────────────────

class ImportError(SIAError):  # noqa: A001
    def __init__(self, code: str = codes.E_IMPORT_LOAD_FAILED,
                 message: str | None = None) -> None:
        super().__init__(code, message)


# ── Audit ──────────────────────────────────────────────────────────────────────

class AuditChainError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_AUDIT_CHAIN_BROKEN, message)


class AuditTamperedError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_AUDIT_TAMPERED, message)


# ── Conformance ────────────────────────────────────────────────────────────────

class ConformanceAssertionError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_CONFORMANCE_ASSERTION_FAILED, message)


# ── Registry ───────────────────────────────────────────────────────────────────

class RegistryNotFoundError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_REGISTRY_NOT_FOUND, message)


class RegistryDuplicateError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_REGISTRY_DUPLICATE, message)


class CreatorLockedError(SIAError):
    def __init__(self, message: str | None = None) -> None:
        super().__init__(codes.E_REGISTRY_CREATOR_LOCKED, message)


# ── Provider ───────────────────────────────────────────────────────────────────

class BannedProviderError(SIAError):
    """Raised when a banned provider is referenced."""

    def __init__(self, provider_id: str, message: str | None = None) -> None:
        self.provider_id = provider_id
        super().__init__(
            codes.E_BANNED_PROVIDER,
            message or f"Provider '{provider_id}' is banned and cannot be used",
        )


class ProviderConfigError(SIAError):
    """Raised when a provider API key or configuration is missing or invalid."""

    def __init__(self, provider_id: str, message: str | None = None) -> None:
        self.provider_id = provider_id
        super().__init__(
            codes.E_PROVIDER_CONFIG,
            message or f"Provider '{provider_id}': API key not found in local vault",
        )


class ProviderCallError(SIAError):
    """Raised when a provider HTTP call fails."""

    def __init__(
        self, provider_id: str, status: int | None = None, message: str | None = None
    ) -> None:
        self.provider_id = provider_id
        self.status = status
        detail = f" (HTTP {status})" if status is not None else ""
        super().__init__(
            codes.E_PROVIDER_CALL_FAILED,
            message or f"Provider '{provider_id}' call failed{detail}",
        )
