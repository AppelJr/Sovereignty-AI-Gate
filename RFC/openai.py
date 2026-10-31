"""
OpenAI / GPT provider driver.

REAL HTTP DRIVER — requires a valid API key stored at::

    ~/.sia/vault/keys/openai.gpt.key

and network connectivity to ``api.openai.com``.

If the key file is absent or the network is unavailable the call raises
``ProviderConfigError`` or ``ProviderCallError`` respectively.  No silent
fallback or mock behaviour.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from sia.authority_gate import AIProvider, AuthorizedContextPacket
from sia.errors.exceptions import ProviderCallError, ProviderConfigError

_PROVIDER_ID = "openai.gpt"
_API_URL = "https://api.openai.com/v1/chat/completions"
_KEY_FILE = Path("~/.sia/vault/keys/openai.gpt.key")
_DEFAULT_MODEL = "gpt-5.6"
_TIMEOUT_SECONDS = 60


def _load_api_key(key_file: Path) -> str:
    resolved = key_file.expanduser()
    if not resolved.exists():
        raise ProviderConfigError(
            _PROVIDER_ID,
            f"[REAL DRIVER — OpenAI/GPT] API key not found at '{resolved}'. "
            "Store your OpenAI API key there to enable this provider.",
        )
    key = resolved.read_text(encoding="utf-8").strip()
    if not key:
        raise ProviderConfigError(
            _PROVIDER_ID,
            f"[REAL DRIVER — OpenAI/GPT] API key file '{resolved}' is empty.",
        )
    return key


def _build_messages(packet: AuthorizedContextPacket) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = []
    for rec in packet.memory_context:
        content = rec.get("content")
        if isinstance(content, str) and content:
            messages.append({"role": "system", "content": content})
    prompt = packet.metadata.get("prompt") or packet.metadata.get("query") or ""
    if prompt:
        messages.append({"role": "user", "content": str(prompt)})
    if not messages:
        messages.append({"role": "user", "content": f"operation:{packet.operation}"})
    return messages


class OpenAIProvider(AIProvider):
    """
    REAL HTTP DRIVER — OpenAI / GPT

    Dispatches authorized context packets to the OpenAI Chat Completions API.
    API key must exist at ``~/.sia/vault/keys/openai.gpt.key``.
    Network connectivity to ``api.openai.com`` is required at call time.
    """

    def __init__(
        self,
        *,
        model: str = _DEFAULT_MODEL,
        key_file: Path = _KEY_FILE,
        timeout: int = _TIMEOUT_SECONDS,
    ) -> None:
        self._model = model
        self._key_file = key_file
        self._timeout = timeout

    @property
    def provider_id(self) -> str:
        return _PROVIDER_ID

    def execute(self, packet: AuthorizedContextPacket) -> dict[str, Any]:
        if not isinstance(packet, AuthorizedContextPacket) or not packet.authorized:
            raise ValueError(f"[{_PROVIDER_ID}] requires an authorized context packet")

        api_key = _load_api_key(self._key_file)
        messages = _build_messages(packet)
        request_body = json.dumps(
            {
                "model": self._model,
                "messages": messages,
                "stream": False,
            }
        ).encode("utf-8")

        req = urllib.request.Request(
            _API_URL,
            data=request_body,
            headers={
                "Authorization": "Bearer " + api_key,
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
                message=f"[REAL DRIVER — OpenAI/GPT] HTTP {exc.code}: {exc.reason}",
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ProviderCallError(
                _PROVIDER_ID,
                message=f"[REAL DRIVER — OpenAI/GPT] Network error: {exc}",
            ) from exc

        return {
            "provider_id": self.provider_id,
            "packet_id": packet.packet_id,
            "model": data.get("model", self._model),
            "choices": data.get("choices", []),
            "usage": data.get("usage", {}),
            "authorized": True,
        }
