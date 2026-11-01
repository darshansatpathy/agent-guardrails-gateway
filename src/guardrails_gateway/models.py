"""Core data types shared across the gateway."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Outcome(StrEnum):
    """The three things the gateway can decide about a tool call."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Risk(StrEnum):
    """How much damage a tool can do if it is misused."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ToolCall(BaseModel):
    """A single request from an agent to use a tool."""

    agent_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable hash of who is calling what with which arguments.

        Approvals are bound to this fingerprint, so approving one call can never be
        replayed to authorise a different call (different amount, recipient, etc.).
        """
        payload = {
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "tool": self.tool,
            "arguments": self.arguments,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


class Decision(BaseModel):
    """The gateway's verdict on a tool call, with the rule that produced it."""

    outcome: Outcome
    rule: str
    reason: str
    approval_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW

    @classmethod
    def allow(cls, rule: str = "allow", reason: str = "all checks passed") -> Decision:
        return cls(outcome=Outcome.ALLOW, rule=rule, reason=reason)

    @classmethod
    def deny(cls, rule: str, reason: str) -> Decision:
        return cls(outcome=Outcome.DENY, rule=rule, reason=reason)
