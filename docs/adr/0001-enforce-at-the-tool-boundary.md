# ADR-0001: Enforce at the tool boundary, not in the prompt

**Status:** accepted

## Context

Agent platforms commonly express rules as system-prompt instructions ("never refund more
than $500", "only email customers"). Models follow these most of the time. They are
trained to complete tasks, and their behaviour can be steered by content they read, so
"most of the time" is not a control an auditor will accept.

## Decision

Rules that limit what an agent can *do* are enforced in code at the tool-call boundary.
The model may still be told the rules (it helps it plan), but the gateway is the source of
truth and denies anything outside them.

## Alternatives considered

- **Prompt instructions only.** Cheap; not enforceable; no audit trail.
- **Guard model reviewing each action.** Useful as an extra signal, but it is another
  probabilistic component that can itself be manipulated. Not a substitute for
  deterministic limits.
- **Per-tool checks inside each integration.** Enforceable, but scattered across teams and
  codebases, with no single audit trail or policy view.

## Consequences

- One place to review, test and audit agent permissions.
- Framework- and model-agnostic.
- Policy authors must anticipate harmful argument patterns; the gateway cannot infer intent.
