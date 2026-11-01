"""Declarative policy: which agent may call which tool, with which arguments.

Policies are YAML so security and platform teams can review them in a pull request,
the same way they review infrastructure code. Anything not listed is denied.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from guardrails_gateway.models import Risk


class ArgConstraint(BaseModel):
    """Limits on a single tool argument."""

    model_config = ConfigDict(extra="forbid")

    required: bool = False
    pattern: str | None = None
    one_of: list[Any] | None = None
    min: float | None = None
    max: float | None = None
    max_length: int | None = None

    @field_validator("pattern")
    @classmethod
    def _pattern_compiles(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid regex {value!r}: {exc}") from exc
        return value

    def violation(self, name: str, value: Any) -> str | None:
        """Return a human-readable violation, or None if the value is acceptable."""
        if self.one_of is not None and value not in self.one_of:
            return f"argument '{name}' must be one of {self.one_of}"
        if self.pattern is not None and (
            not isinstance(value, str) or re.fullmatch(self.pattern, value) is None
        ):
            return f"argument '{name}' does not match the allowed pattern"
        if self.min is not None or self.max is not None:
            if isinstance(value, bool) or not isinstance(value, int | float):
                return f"argument '{name}' must be a number"
            if self.min is not None and value < self.min:
                return f"argument '{name}' is below the minimum of {self.min}"
            if self.max is not None and value > self.max:
                return f"argument '{name}' exceeds the maximum of {self.max}"
        if (
            self.max_length is not None
            and isinstance(value, str | list | dict)
            and len(value) > self.max_length
        ):
            return f"argument '{name}' is longer than {self.max_length}"
        return None


class RateLimit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_calls: int = Field(gt=0)
    per_seconds: int = Field(gt=0)


class ToolDefinition(BaseModel):
    """Properties of a tool that hold no matter which agent calls it."""

    model_config = ConfigDict(extra="forbid")

    risk: Risk = Risk.LOW
    description: str = ""
    requires_approval: bool = False
    irreversible: bool = False
    egress: bool = False
    untrusted_output: bool = False

    @property
    def needs_human(self) -> bool:
        return self.requires_approval or self.irreversible or self.risk is Risk.HIGH


class AgentToolPolicy(BaseModel):
    """What one agent may do with one tool."""

    model_config = ConfigDict(extra="forbid")

    constraints: dict[str, ArgConstraint] = Field(default_factory=dict)
    strict_args: bool = False
    rate_limit: RateLimit | None = None

    def violation(self, arguments: dict[str, Any]) -> str | None:
        for name, constraint in self.constraints.items():
            if name not in arguments:
                if constraint.required:
                    return f"required argument '{name}' is missing"
                continue
            problem = constraint.violation(name, arguments[name])
            if problem:
                return problem
        if self.strict_args:
            unknown = sorted(set(arguments) - set(self.constraints))
            if unknown:
                return f"arguments not permitted by policy: {', '.join(unknown)}"
        return None


class AgentPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = ""
    tools: dict[str, AgentToolPolicy] = Field(default_factory=dict)


class Defaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_ttl_seconds: int = Field(default=900, gt=0)
    max_grant_ttl_seconds: int = Field(default=3600, gt=0)


class Policy(BaseModel):
    """The full policy document."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    defaults: Defaults = Field(default_factory=Defaults)
    tools: dict[str, ToolDefinition] = Field(default_factory=dict)
    agents: dict[str, AgentPolicy] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _agents_reference_known_tools(self) -> Policy:
        for agent_id, agent in self.agents.items():
            unknown = sorted(set(agent.tools) - set(self.tools))
            if unknown:
                raise ValueError(
                    f"agent '{agent_id}' references undefined tools: {', '.join(unknown)}"
                )
        return self

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)

    def tool(self, name: str) -> ToolDefinition | None:
        return self.tools.get(name)

    def agent_tool(self, agent_id: str, tool: str) -> AgentToolPolicy | None:
        agent = self.agents.get(agent_id)
        if agent is None:
            return None
        return agent.tools.get(tool)

    def tools_for(self, agent_id: str) -> list[str]:
        agent = self.agents.get(agent_id)
        return sorted(agent.tools) if agent else []
