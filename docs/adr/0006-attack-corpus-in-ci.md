# ADR-0006: Test guardrails against an attack corpus in CI

**Status:** accepted

## Context

Unit tests prove each check works in isolation. They do not prove that the policy as
shipped, combined with the code as shipped, stops the attacks we care about. A one-line
policy change (a higher refund limit, a looser regex) can quietly reopen a hole while
every unit test stays green.

## Decision

Keep a corpus of attack and benign scenarios in `evals/scenarios.yaml`, written as short
step sequences against the real gateway with demo tools and a controllable clock. `aggw
eval` runs them and exits non-zero on any failure; CI runs it on every push and publishes
the table to the run summary.

- An **attack** passes only if every step yields the expected non-executing outcome.
- A **benign** scenario passes only if legitimate work is allowed, so over-blocking is
  caught as a failure rather than celebrated as safety.

The eval itself is tested: tests weaken the policy in specific ways and assert the eval
reports the matching scenario as failed.

## Alternatives considered

- **Unit tests only.** Necessary, not sufficient; they do not exercise the shipped policy.
- **Red-teaming with a live model.** Valuable for discovering new attacks, but slow,
  costly and non-deterministic. New findings from red-teaming become scenarios here.

## Consequences

- Policy changes are reviewed with evidence: the PR shows whether any scenario changed.
- The corpus must grow with the threat model; CONTRIBUTING requires a scenario for any
  security-relevant change.
