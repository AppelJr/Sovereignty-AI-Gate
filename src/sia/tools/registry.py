from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


class DuplicateToolRegistrationError(ValueError):
    pass


@dataclass(frozen=True)
class RegisteredTool:
    name: str
    executable: str


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, RegisteredTool] = {}

    def register(self, name: str, executable: str) -> None:
        if not name:
            raise ValueError("Tool name cannot be empty")
        if not executable:
            raise ValueError("Executable path cannot be empty")
        if name in self._tools:
            raise DuplicateToolRegistrationError(f"Tool already registered: {name}")
        self._tools[name] = RegisteredTool(name=name, executable=executable)

    def resolve(self, name: str) -> str:
        try:
            return self._tools[name].executable
        except KeyError as exc:
            raise PermissionError("Tool not registered") from exc

    def is_registered(self, name: str) -> bool:
        return name in self._tools
