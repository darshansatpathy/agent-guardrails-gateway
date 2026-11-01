# ADR-0007: Provider-agnostic agent loop with tool schemas from policy

**Status:** accepted

## Context

Enterprises rarely standardise on one model vendor. The same agent may run on Azure
OpenAI in one region, a self-hosted open model in another, and a mock in CI. Tool
definitions are also commonly duplicated: once for the model, once for authorisation.

## Decision

- Model access goes through a one-method `ModelProvider` protocol. Ship an
  OpenAI-compatible provider (covering OpenAI, Azure OpenAI and self-hosted servers such
  as vLLM, Ollama and LiteLLM) and a deterministic scripted provider for tests and evals.
- The agent loop routes every proposed tool call through `Gateway.invoke` and returns the
  verdict to the model as the tool result, including denials and pending approvals, so
  the model can explain rather than retry around a rule.
- Tool schemas shown to the model are generated from the policy: only tools the agent may
  use, with argument limits expressed as JSON Schema. One source of truth.
- Malformed tool arguments from the model are kept and passed to the gateway, which
  denies them visibly, instead of being silently dropped.

## Alternatives considered

- **Depend on one framework's agent abstraction** (LangGraph, Semantic Kernel). Fine
  for applications; for a gateway reference it couples the security boundary to a
  framework's release cycle. The loop is one short module and easy to port into any framework.
- **Native SDKs per vendor.** More features, more surface. The OpenAI-compatible
  interface is the common denominator most platforms expose.

## Consequences

- Swapping models is configuration, not code.
- Vendor-specific features (parallel tool calls with special semantics, reasoning
  traces) are not used; add a provider if you need them.
