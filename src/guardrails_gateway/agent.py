"""A minimal agent loop whose every action goes through the gateway.

This is the integration pattern the gateway is designed for: the model proposes tool
calls, the loop hands each one to `Gateway.invoke`, and whatever the gateway decides
(the tool's result, a denial with its reason, or "waiting for approval") goes back to
the model as the tool's answer. The model never touches a tool directly.

Tool schemas shown to the model are generated from the policy, so the model only ever
learns about tools its agent may use, with the argument limits already described.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from guardrails_gateway.gateway import Gateway
from guardrails_gateway.models import Decision, ToolCall
from guardrails_gateway.policy import ArgConstraint
from guardrails_gateway.providers import Message, ModelProvider

DEFAULT_SYSTEM_PROMPT = (
    "You are a customer-support agent. Use the tools provided. If a tool call is denied "
    "or awaiting approval, explain that to the user instead of retrying with different "
    "arguments to get around the rule."
)


def tool_schemas(gateway: Gateway, agent_id: str, tools: list[str]) -> list[dict[str, Any]]:
    """OpenAI-style function specs for the tools this agent may use, from the policy."""
    specs: list[dict[str, Any]] = []
    for name in tools:
        tool = gateway.policy.tool(name)
        agent_tool = gateway.policy.agent_tool(agent_id, name)
        if tool is None or agent_tool is None:
            continue
        properties = {
            arg: _json_schema(constraint) for arg, constraint in agent_tool.constraints.items()
        }
        required = sorted(arg for arg, c in agent_tool.constraints.items() if c.required)
        params: dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            params["required"] = required
        if agent_tool.strict_args:
            params["additionalProperties"] = False
        specs.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": tool.description or name,
                    "parameters": params,
                },
            }
        )
    return specs


def _json_schema(c: ArgConstraint) -> dict[str, Any]:
    schema: dict[str, Any] = {}
    if c.one_of is not None:
        schema["enum"] = list(c.one_of)
    elif c.min is not None or c.max is not None:
        schema["type"] = "number"
        if c.min is not None:
            schema["minimum"] = c.min
        if c.max is not None:
            schema["maximum"] = c.max
    else:
        schema["type"] = "string"
        if c.pattern is not None:
            schema["pattern"] = f"^(?:{c.pattern})$"
        if c.max_length is not None:
            schema["maxLength"] = c.max_length
    return schema


@dataclass
class Step:
    tool: str
    arguments: dict[str, Any]
    decision: Decision
    result: Any = None
    error: str | None = None


@dataclass
class AgentRun:
    final_answer: str | None
    steps: list[Step] = field(default_factory=list)
    stopped_reason: str = "answered"


@dataclass
class GuardedAgent:
    gateway: Gateway
    provider: ModelProvider
    agent_id: str
    task_id: str
    grant_token: str
    system_prompt: str = DEFAULT_SYSTEM_PROMPT
    max_steps: int = 8
    session_id: str = field(default_factory=lambda: "sess_" + uuid.uuid4().hex[:12])

    def run(self, user_message: str) -> AgentRun:
        grant = self.gateway.grants.verify(self.grant_token)
        tools = tool_schemas(self.gateway, self.agent_id, sorted(grant.tools))
        messages: list[Message] = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_message},
        ]
        run = AgentRun(final_answer=None)
        for _ in range(self.max_steps):
            turn = self.provider.complete(messages, tools)
            if not turn.tool_calls:
                run.final_answer = turn.content
                return run
            messages.append(
                {
                    "role": "assistant",
                    "content": turn.content,
                    "tool_calls": [
                        {
                            "id": tc.call_id,
                            "type": "function",
                            "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                        }
                        for tc in turn.tool_calls
                    ],
                }
            )
            for tc in turn.tool_calls:
                call = ToolCall(
                    agent_id=self.agent_id,
                    task_id=self.task_id,
                    session_id=self.session_id,
                    tool=tc.name or "<missing>",
                    arguments=tc.arguments,
                )
                outcome = self.gateway.invoke(call, self.grant_token)
                step = Step(tc.name, tc.arguments, outcome.decision, outcome.result, outcome.error)
                run.steps.append(step)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.call_id,
                        "content": json.dumps(_tool_message(step), default=str),
                    }
                )
        run.stopped_reason = "max_steps"
        return run


def _tool_message(step: Step) -> dict[str, Any]:
    d = step.decision
    if d.allowed and step.error is None:
        return {"status": "ok", "result": step.result}
    if d.allowed:
        return {"status": "error", "error": step.error}
    if d.approval_id:
        return {
            "status": "awaiting_human_approval",
            "approval_id": d.approval_id,
            "reason": d.reason,
            "instruction": "Tell the user a reviewer must approve this. Do not retry.",
        }
    return {"status": "denied", "rule": d.rule, "reason": d.reason}
