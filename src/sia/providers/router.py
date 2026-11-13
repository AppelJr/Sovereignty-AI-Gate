"""Provider selection without execution."""
from __future__ import annotations

from collections.abc import Mapping

from sia.authority_gate import AIProvider, OperationRequest
from sia.context.request_context import RequestContext
from sia.errors.exceptions import RegistryNotFoundError


class ProviderRouter:
    """Select a registered provider; execution remains with the authority."""

    def __init__(self, providers: Mapping[str, AIProvider]) -> None:
        self._providers = dict(providers)

    def select(self, request: OperationRequest, context: RequestContext) -> AIProvider:
        """Select the requested provider without invoking it."""
        del context
        if not request.provider_id:
            raise RegistryNotFoundError("Provider calls require a provider_id")
        try:
            return self._providers[request.provider_id]
        except KeyError as exc:
            raise RegistryNotFoundError(
                f"Provider '{request.provider_id}' is not available for this request"
            ) from exc
