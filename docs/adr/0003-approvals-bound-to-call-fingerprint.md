# ADR-0003: Approvals bound to the exact call, single use

**Status:** accepted

## Context

A naive approval ("allow refunds for task T-42") lets an agent obtain approval for one
action and use it for another: approve $120, execute $12,000; approve one email, send fifty.

## Decision

An approval is bound to the **fingerprint** of the call: SHA-256 over agent, task, tool and
canonicalised arguments. When the agent retries, the gateway consumes an approved,
unexpired approval only if the fingerprint matches exactly. Approvals are single use and
expire if not acted on. The approver must not be the requesting agent.

## Alternatives considered

- **Approve a tool for a task.** Simpler UX, open to laundering as above.
- **Approve and execute inside the approval endpoint.** Removes the retry, but means the
  gateway executes actions on a reviewer's request outside the agent's flow, and the agent
  loses track of what happened.

## Consequences

- Reviewers see exactly what will run, and only that runs.
- Any change to arguments needs a fresh approval, by design.
- The agent must retry the identical call after approval; the denial reason says so.
