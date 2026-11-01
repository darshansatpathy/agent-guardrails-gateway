# ADR-0002: Stateless HMAC grants scoped to a task

**Status:** accepted

## Context

Agents need credentials to call the gateway. Long-lived API keys per agent create standing
access: a leaked key, or a task that drifts, retains every permission the agent has.

## Decision

The orchestrator requests a **grant** per task: an HMAC-SHA256 signed token naming the
agent, the task, the subset of tools that task needs, and an expiry no longer than the
policy ceiling. The gateway verifies grants without a database lookup. A revocation set
supports killing one grant or every grant for a task.

A grant can never exceed policy: the gateway refuses to issue one that names a tool the
agent is not allowed to use.

## Alternatives considered

- **JWT with a library.** Equivalent security properties; adds a dependency and the usual
  JWT pitfalls (`alg` confusion). The token format here is a few lines and fully tested.
  Swapping to JWT, or to tokens from an existing STS, is straightforward.
- **Opaque tokens in a database.** Easy revocation, but every call becomes a lookup.

## Consequences

- Least privilege per task, by default.
- Revocation state is in memory; with several replicas it must move to a shared store.
- The grant secret is critical. Load it from a secret manager and rotate it.
