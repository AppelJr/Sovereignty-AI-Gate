"""
Anthropic / Claude provider driver.

REAL HTTP DRIVER — requires a valid API key stored at::

    ~/.sia/vault/keys/anthropic.claude.key

and network connectivity to ``api.anthropic.com``.

If the key file is absent or the network is unavailable the call raises
``ProviderConfigError`` or ``ProviderCallError`` respectively.  No silent
fallback or mock behaviour.

The Anthropic Messages API differs from the OpenAI chat-completions schema:
- ``system`` content is a top-level field, not a message role.
- ``messages`` must alternate user/assistant turns.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from sia.authority_gate import AIProvider, AuthorizedContextPacket
from sia.errors.exceptions import ProviderCallError, ProviderConfigError

_PROVIDER_ID = "anthropic.claude"
_API_URL = "https://api.anthropic.com/v1/messages"
_KEY_FILE = Path("~/.sia/vault/keys/anthropic.claude.key")
_DEFAULT_MODEL = "claude-sonnet-5"
_ANTHROPIC_VERSION = "2023-06-01"
_TIMEOUT_SECONDS = 60
_MAX_TOKENS = 4096


def _load_api_key(key_file: Path) -> str:
    resolved = key_file.expanduser()
    if not resolved.exists():
        raise ProviderConfigError(
            _PROVIDER_ID,
            f"[REAL DRIVER — Anthropic/Claude] API key not found at '{resolved}'. "
            "Store your Anthropic API key there to enable this provider.",
        )
    key = resolved.read_text(encoding="utf-8").strip()
    if not key:
        raise ProviderConfigError(
            _PROVIDER_ID,
            f"[REAL DRIVER — Anthropic/Claude] API key file '{resolved}' is empty.",
        )
    return key


def _build_payload(
    packet: AuthorizedContextPacket, model: str
) -> dict[str, Any]:
    """Convert an authorized context packet into an Anthropic Messages payload."""
    system_parts: list[str] = []
    for rec in packet.memory_context:
        content = rec.get("content")
        if isinstance(content, str) and content:
            system_parts.append(content)

    prompt = packet.metadata.get("prompt") or packet.metadata.get("query") or ""
    user_text = str(prompt) if prompt else f"operation:{packet.operation}"

    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": _MAX_TOKENS,
        "messages": [{"role": "user", "content": user_text}],
    }
    if system_parts:
        payload["system"] = "\n\n".join(system_parts)
    return payload


class AnthropicProvider(AIProvider):
    """
    REAL HTTP DRIVER — Anthropic / Claude

    Dispatches authorized context packets to the Anthropic Messages API.
    API key must exist at ``~/.sia/vault/keys/anthropic.claude.key``.
    Network connectivity to ``api.anthropic.com`` is required at call time.
    """

    def __init__(
        self,
        *,
        model: str = _DEFAULT_MODEL,
        key_file: Path = _KEY_FILE,
        timeout: int = _TIMEOUT_SECONDS,
        max_tokens: int = _MAX_TOKENS,
    ) -> None:
        self._model = model
        self._key_file = key_file
        self._timeout = timeout
        self._max_tokens = max_tokens

    @property
    def provider_id(self) -> str:
        return _PROVIDER_ID

    def execute(self, packet: AuthorizedContextPacket) -> dict[str, Any]:
        if not isinstance(packet, AuthorizedContextPacket) or not packet.authorized:
            raise ValueError(f"[{_PROVIDER_ID}] requires an authorized context packet")

        api_key = _load_api_key(self._key_file)
        payload = _build_payload(packet, self._model)
        payload["max_tokens"] = self._max_tokens
        request_body = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            _API_URL,
            data=request_body,
            headers={
                "x-api-key": api_key,
                "anthropic-version": _ANTHROPIC_VERSION,
                "Content-Type": "application/json",
                "X-SIA-Packet-ID": packet.packet_id,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
                data = json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ProviderCallError(
                _PROVIDER_ID,
                status=exc.code,
                message=f"[REAL DRIVER — Anthropic/Claude] HTTP {exc.code}: {exc.reason}",
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ProviderCallError(
                _PROVIDER_ID,
                message=f"[REAL DRIVER — Anthropic/Claude] Network error: {exc}",
            ) from exc

        return {
            "provider_id": self.provider_id,
            "packet_id": packet.packet_id,
            "model": data.get("model", self._model),
            "content": data.get("content", []),
            "usage": data.get("usage", {}),
            "stop_reason": data.get("stop_reason"),
            "authorized": True,
        }
