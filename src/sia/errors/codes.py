"""
Error codes for the Sovereignty AI Gate.

Each code is a four-character string prefixed with 'E' for errors and
'W' for warnings, followed by a four-digit number.
"""

# Core / authority errors
E_UNKNOWN = "E0000"
E_NOT_INITIALIZED = "E0001"
E_INVALID_IDENTITY = "E0002"
E_BOUNDARY_VIOLATION = "E0003"
E_POLICY_DENIED = "E0004"
E_SIGNATURE_INVALID = "E0005"
E_HASH_MISMATCH = "E0006"

# Memory errors
E_MEMORY_DECRYPT_FAILED = "E1000"
E_MEMORY_CONSENT_DENIED = "E1001"
E_MEMORY_SCOPE_MISMATCH = "E1002"
E_MEMORY_SCHEMA_INVALID = "E1003"
E_MEMORY_STORE_FAILED = "E1004"

# Delegation errors
E_DELEGATION_EXPIRED = "E2000"
E_DELEGATION_SCOPE_EXCEEDED = "E2001"
E_DELEGATION_CHAIN_TOO_DEEP = "E2002"
E_DELEGATION_REVOKED = "E2003"
E_DELEGATION_INVALID = "E2004"

# Export errors
E_EXPORT_SIGNING_FAILED = "E3000"
E_EXPORT_SCHEMA_INVALID = "E3001"
E_EXPORT_BUNDLE_INCOMPLETE = "E3002"

# Import errors
E_IMPORT_SCHEMA_INVALID = "E4000"
E_IMPORT_SIGNATURE_INVALID = "E4001"
E_IMPORT_VERSION_UNSUPPORTED = "E4002"
E_IMPORT_DUPLICATE = "E4003"
E_IMPORT_LOAD_FAILED = "E4004"

# Audit errors
E_AUDIT_CHAIN_BROKEN = "E5000"
E_AUDIT_TAMPERED = "E5001"
E_AUDIT_WRITE_FAILED = "E5002"

# Conformance errors
E_CONFORMANCE_ASSERTION_FAILED = "E6000"
E_CONFORMANCE_EVIDENCE_INVALID = "E6001"
E_CONFORMANCE_RFC_MISSING = "E6002"

# Boundary / registry errors
E_REGISTRY_NOT_FOUND = "E7000"
E_REGISTRY_DUPLICATE = "E7001"
E_REGISTRY_CONVERSION_DENIED = "E7002"
E_REGISTRY_CREATOR_LOCKED = "E7003"

# Provider errors
E_BANNED_PROVIDER = "E8000"
E_PROVIDER_CONFIG = "E8001"
E_PROVIDER_CALL_FAILED = "E8002"

# Code descriptions
DESCRIPTIONS: dict[str, str] = {
    E_UNKNOWN: "Unknown error",
    E_NOT_INITIALIZED: "Authority not initialized",
    E_INVALID_IDENTITY: "Invalid identity material",
    E_BOUNDARY_VIOLATION: "Boundary policy violation",
    E_POLICY_DENIED: "Action denied by authority policy",
    E_SIGNATURE_INVALID: "Cryptographic signature is invalid",
    E_HASH_MISMATCH: "Hash does not match expected value",
    E_MEMORY_DECRYPT_FAILED: "Memory decryption failed",
    E_MEMORY_CONSENT_DENIED: "Cross-model memory access denied — no user consent",
    E_MEMORY_SCOPE_MISMATCH: "Memory scope does not match requesting model",
    E_MEMORY_SCHEMA_INVALID: "Memory record schema is invalid",
    E_MEMORY_STORE_FAILED: "Failed to persist memory record",
    E_DELEGATION_EXPIRED: "Delegation token has expired",
    E_DELEGATION_SCOPE_EXCEEDED: "Delegation would exceed granted scope",
    E_DELEGATION_CHAIN_TOO_DEEP: "Delegation chain depth limit exceeded",
    E_DELEGATION_REVOKED: "Delegation has been revoked",
    E_DELEGATION_INVALID: "Delegation token is structurally invalid",
    E_EXPORT_SIGNING_FAILED: "Failed to sign export bundle",
    E_EXPORT_SCHEMA_INVALID: "Export bundle schema is invalid",
    E_EXPORT_BUNDLE_INCOMPLETE: "Export bundle is missing required fields",
    E_IMPORT_SCHEMA_INVALID: "Imported bundle schema is invalid",
    E_IMPORT_SIGNATURE_INVALID: "Imported bundle signature verification failed",
    E_IMPORT_VERSION_UNSUPPORTED: "Imported bundle version is not supported",
    E_IMPORT_DUPLICATE: "Bundle with this ID already imported",
    E_IMPORT_LOAD_FAILED: "Failed to load import bundle",
    E_AUDIT_CHAIN_BROKEN: "Audit ledger chain integrity check failed",
    E_AUDIT_TAMPERED: "Audit ledger entry has been tampered with",
    E_AUDIT_WRITE_FAILED: "Failed to write audit ledger entry",
    E_CONFORMANCE_ASSERTION_FAILED: "Conformance assertion failed",
    E_CONFORMANCE_EVIDENCE_INVALID: "Conformance evidence record is invalid",
    E_CONFORMANCE_RFC_MISSING: "Referenced RFC is not registered",
    E_REGISTRY_NOT_FOUND: "Boundary not found in registry",
    E_REGISTRY_DUPLICATE: "Boundary already registered",
    E_REGISTRY_CONVERSION_DENIED: "Boundary type conversion is not permitted",
    E_REGISTRY_CREATOR_LOCKED: "Creator boundary is locked and cannot be modified",
    E_BANNED_PROVIDER: "Provider is on the banned list and cannot be used",
    E_PROVIDER_CONFIG: "Provider configuration is missing or invalid (API key not found)",
    E_PROVIDER_CALL_FAILED: "Provider HTTP call failed",
}


def describe(code: str) -> str:
    """Return a human-readable description for an error code."""
    return DESCRIPTIONS.get(code, f"Unknown code: {code}")
