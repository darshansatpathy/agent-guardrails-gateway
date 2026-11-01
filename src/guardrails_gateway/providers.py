"""Model providers behind one small interface.

The gateway never depends on a model vendor. An agent loop asks a provider for the next
turn, and the provider answers with text and/or tool calls. Two implementations ship:

- `ScriptedProvider`: deterministic, offline, for tests, demos and evals.
- `OpenAICompatibleProvider`: any Chat Completions-compatible endpoint. That covers
  OpenAI, Azure OpenAI, and self-hosted servers such as vLLM, Ollama or LiteLLM, which
  is also how Bedrock, Vertex and other hosted models are commonly fronted.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

Message = dict[str, Any]


@dataclass(frozen=True)
class ToolRequest:
    """One tool call the model wants to make."""

    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ModelTurn:
    """What the model said on one step: optional text and zero or more tool calls."""

    content: str | None = None
    tool_calls: tuple[ToolRequest, ...] = ()


class ModelProvider(Protocol):
    def complete(self, messages: Sequence[Message], tools: Sequence[dict[str, Any]]) -> ModelTurn:
        """Return the model's next turn given the conversation and available tools."""
        ...


class ProviderError(Exception):
    pass


@dataclass
class ScriptedProvider:
    """Replays a fixed list of turns. Records what it was shown, for assertions."""

    turns: list[ModelTurn]
    seen: list[tuple[list[Message], list[str]]] = field(default_factory=list)

    def complete(self, messages: Sequence[Message], tools: Sequence[dict[str, Any]]) -> ModelTurn:
        self.seen.append(([dict(m) for m in messages], [t["function"]["name"] for t in tools]))
        if not self.turns:
            return ModelTurn(content="(script finished)")
        return self.turns.pop(0)


@dataclass
class OpenAICompatibleProvider:
    """Chat Completions over HTTP with tool calling.

    For Azure OpenAI pass the deployment URL as `base_url` and set `azure_api_version`;
    the provider then sends the `api-key` header and the `api-version` query parameter.
    """

    base_url: str
    model: str
    api_key: str = ""
    azure_api_version: str | None = None
    timeout_seconds: float = 60.0
    transport: Any = None  # an httpx transport, injectable for tests
    temperature: float = 0.0

    @classmethod
    def from_env(cls) -> OpenAICompatibleProvider:
        """Read AGGW_LLM_BASE_URL, AGGW_LLM_MODEL, AGGW_LLM_API_KEY, AGGW_AZURE_API_VERSION."""
        return cls(
            base_url=os.environ.get("AGGW_LLM_BASE_URL", "https://api.openai.com/v1"),
            model=os.environ.get("AGGW_LLM_MODEL", "gpt-4o-mini"),
            api_key=os.environ.get("AGGW_LLM_API_KEY", ""),
            azure_api_version=os.environ.get("AGGW_AZURE_API_VERSION") or None,
        )

    def complete(self, messages: Sequence[Message], tools: Sequence[dict[str, Any]]) -> ModelTurn:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ProviderError(
                "install the 'llm' extra: pip install 'agent-guardrails-gateway[llm]'"
            ) from exc

        headers = {"Content-Type": "application/json"}
        params: dict[str, str] = {}
        if self.azure_api_version:
            headers["api-key"] = self.api_key
            params["api-version"] = self.azure_api_version
        elif self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body: dict[str, Any] = {
            "model": self.model,
            "messages": list(messages),
            "temperature": self.temperature,
        }
        if tools:
            body["tools"] = list(tools)
            body["tool_choice"] = "auto"

        with httpx.Client(timeout=self.timeout_seconds, transport=self.transport) as client:
            resp = client.post(
                self.base_url.rstrip("/") + "/chat/completions",
                headers=headers,
                params=params,
                json=body,
            )
        if resp.status_code >= 400:
            raise ProviderError(f"model endpoint returned {resp.status_code}: {resp.text[:300]}")
        return parse_chat_completion(resp.json())


def parse_chat_completion(payload: dict[str, Any]) -> ModelTurn:
    """Turn a Chat Completions response into a ModelTurn, tolerating malformed arguments."""
    try:
        message = payload["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ProviderError("response has no choices[0].message") from exc
    calls: list[ToolRequest] = []
    for raw in message.get("tool_calls") or []:
        fn = raw.get("function") or {}
        args_text = fn.get("arguments") or "{}"
        try:
            args = json.loads(args_text) if isinstance(args_text, str) else dict(args_text)
        except json.JSONDecodeError:
            # Keep the call so the gateway can deny it visibly instead of dropping it.
            args = {"__unparseable_arguments__": str(args_text)[:500]}
        if not isinstance(args, dict):
            args = {"__non_object_arguments__": args}
        calls.append(
            ToolRequest(
                call_id=str(raw.get("id", "")), name=str(fn.get("name", "")), arguments=args
            )
        )
    return ModelTurn(content=message.get("content"), tool_calls=tuple(calls))
