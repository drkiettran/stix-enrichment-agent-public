"""Thin wrapper over the Ollama Python client.

Centralizes model-selection, host config, and the chat call signature so the
agent doesn't reach into ollama internals directly.
"""
from __future__ import annotations

from typing import Any

from ollama import Client


class LLMClient:
    """Wraps an Ollama chat client with tool-calling enabled."""

    def __init__(self, host: str, model: str) -> None:
        self._client = Client(host=host)
        self._model = model

    @property
    def model(self) -> str:
        return self._model

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Single chat turn. Returns the raw Ollama response.

        The response shape we care about:
          response["message"]["content"] -> str (assistant text, may be empty)
          response["message"]["tool_calls"] -> optional list of tool calls
        """
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = tools

        response = self._client.chat(**kwargs)
        return response

    def health_check(self) -> bool:
        """Verify Ollama is reachable and the configured model is available."""
        try:
            models = self._client.list()
            available = {m.get("name") or m.get("model") for m in models.get("models", [])}
            return any(self._model in name for name in available if name)
        except Exception:
            return False
