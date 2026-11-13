"""
Provider Registry — canonical allowed provider set.

Allowed providers are enumerated in ``ProviderID``. Any provider whose
canonical ID starts with a banned prefix is rejected at lookup time with a
``BannedProviderError``; unknown IDs raise ``RegistryNotFoundError``.

Registry entries carry:
- ``display_name``        — human-readable label
- ``model_family``        — supported model names (tuple, for visibility)
- ``roles``               — frozenset of roles this provider may fill
- ``never_use_as_primary``— True for Heavy Judge / council-only providers
- ``dedicated_memory_file``— path to the per-provider encrypted memory file
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from sia.errors.exceptions import BannedProviderError, RegistryNotFoundError


# ---------------------------------------------------------------------------
# Canonical provider IDs
# ---------------------------------------------------------------------------

class ProviderID(StrEnum):
    """Frozen set of allowed provider canonical IDs."""

    XAI_GROK = "xai.grok"
    OPENAI_GPT = "openai.gpt"
    ANTHROPIC_CLAUDE = "anthropic.claude"
    GITHUB_COPILOT = "github.copilot"


# ---------------------------------------------------------------------------
# Banned provider prefixes (rejected explicitly — not silently skipped)
# ---------------------------------------------------------------------------

BANNED_PROVIDER_PREFIXES: frozenset[str] = frozenset(
    {
        "google.",
        "meta.",
        "firebase.",
        "vertex.",
    }
)

# Convenience set of example banned IDs for documentation / test assertions
KNOWN_BANNED_PROVIDERS: frozenset[str] = frozenset(
    {
        "google.gemini",
        "google.palm",
        "meta.llama",
        "meta.codellama",
        "firebase.genai",
        "vertex.ai",
    }
)


# ---------------------------------------------------------------------------
# Registry entry schema
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProviderEntry:
    """Metadata record for a single allowed provider."""

    canonical_id: str
    display_name: str
    model_family: tuple[str, ...]
    roles: frozenset[str]
    never_use_as_primary: bool
    dedicated_memory_file: Path


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def _memory_path(provider_id: str) -> Path:
    """Return the canonical per-provider memory file path."""
    safe_name = provider_id.replace(".", "_")
    return Path("~/.sia/providers") / f"{safe_name}.json"


PROVIDER_REGISTRY: dict[ProviderID, ProviderEntry] = {
    ProviderID.XAI_GROK: ProviderEntry(
        canonical_id=ProviderID.XAI_GROK,
        display_name="xAI / Grok",
        model_family=("grok-4.5", "SuperGrok"),
        roles=frozenset({"judge", "council", "daily", "code", "medical"}),
        never_use_as_primary=False,
        dedicated_memory_file=_memory_path(ProviderID.XAI_GROK),
    ),
    ProviderID.OPENAI_GPT: ProviderEntry(
        canonical_id=ProviderID.OPENAI_GPT,
        display_name="OpenAI / GPT",
        model_family=("gpt-5.6", "gpt-5.5-codex", "gpt-5.5-mini"),
        roles=frozenset({"daily", "code", "council"}),
        never_use_as_primary=False,
        dedicated_memory_file=_memory_path(ProviderID.OPENAI_GPT),
    ),
    ProviderID.ANTHROPIC_CLAUDE: ProviderEntry(
        canonical_id=ProviderID.ANTHROPIC_CLAUDE,
        display_name="Anthropic / Claude",
        model_family=("claude-fable-5", "claude-sonnet-5"),
        roles=frozenset({"daily", "code", "medical", "council"}),
        never_use_as_primary=False,
        dedicated_memory_file=_memory_path(ProviderID.ANTHROPIC_CLAUDE),
    ),
    ProviderID.GITHUB_COPILOT: ProviderEntry(
        canonical_id=ProviderID.GITHUB_COPILOT,
        display_name="GitHub Copilot",
        model_family=("copilot-hybrid",),
        roles=frozenset({"code", "judge"}),
        # Heavy Judge: never dispatched as the primary provider — council/review only
        never_use_as_primary=True,
        dedicated_memory_file=_memory_path(ProviderID.GITHUB_COPILOT),
    ),
}


# ---------------------------------------------------------------------------
# Lookup helper
# ---------------------------------------------------------------------------

def _is_banned(provider_id: str) -> bool:
    """Return True if *provider_id* starts with any banned prefix."""
    lower = provider_id.lower()
    return any(lower.startswith(prefix) for prefix in BANNED_PROVIDER_PREFIXES)


def lookup_provider(provider_id: str) -> ProviderEntry:
    """
    Return the registry entry for *provider_id*.

    Raises
    ------
    BannedProviderError
        If the ID starts with a banned prefix (``google.*``, ``meta.*``,
        ``firebase.*``, ``vertex.*``).
    RegistryNotFoundError
        If the ID is not in the allowed registry.
    """
    if _is_banned(provider_id):
        raise BannedProviderError(provider_id)
    try:
        pid = ProviderID(provider_id)
    except ValueError:
        raise RegistryNotFoundError(
            f"Provider '{provider_id}' is not a recognized canonical ID"
        )
    return PROVIDER_REGISTRY[pid]
