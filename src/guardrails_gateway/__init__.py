"""Agent Guardrails Gateway.

A policy enforcement point that sits between AI agents and the tools they call.
The agent can reason freely; it can only act through calls this gateway allows.
"""

from guardrails_gateway.gateway import Gateway
from guardrails_gateway.models import Decision, Outcome, ToolCall

__all__ = ["Decision", "Gateway", "Outcome", "ToolCall"]
__version__ = "0.1.0"
