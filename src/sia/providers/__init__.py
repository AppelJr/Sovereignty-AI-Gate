"""
Provider routing layer for the Sovereignty AI Gate.

Allowed providers: xAI/Grok, OpenAI/GPT, Anthropic/Claude, GitHub Copilot.
Banned providers: Google/Gemini, Meta, Firebase, Vertex — rejected with
``BannedProviderError`` on any lookup attempt.
"""
from sia.providers.registry import (
    PROVIDER_REGISTRY,
    ProviderEntry,
    ProviderID,
    lookup_provider,
)
from sia.providers.router import ProviderRouter

__all__ = [
    "PROVIDER_REGISTRY",
    "ProviderEntry",
    "ProviderID",
    "lookup_provider",
    "ProviderRouter",
]
