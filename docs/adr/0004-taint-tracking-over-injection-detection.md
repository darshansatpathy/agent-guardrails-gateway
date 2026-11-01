# ADR-0004: Contain prompt injection with taint tracking instead of detecting it

**Status:** accepted

## Context

Indirect prompt injection (instructions hidden in a web page, email or document the agent
reads) is the most practical attack on tool-using agents. Classifiers that try to detect
it reduce the rate but cannot be relied on, and attackers adapt to them.

## Decision

Do not try to detect injection at the gateway. Track **provenance** instead. Tools whose
output comes from outside the organisation are marked `untrusted_output`. When a session
receives such output, it is tainted. In a tainted session, any tool marked `egress`
requires human approval, even if it would otherwise be allowed.

This is the same idea as taint tracking in secure language runtimes: you cannot know if
input is malicious, but you can know where it came from and refuse to let it reach a
dangerous sink unchecked.

## Alternatives considered

- **Injection classifier on tool output.** Worth adding as a signal; not a boundary.
- **Block all egress after any untrusted read.** Safe but breaks legitimate workflows.
  A human gate keeps them possible.

## Consequences

- Exfiltration via injected instructions needs a human to click approve.
- Correct `egress` and `untrusted_output` classification of tools is essential.
- Taint is per session; orchestrators should start fresh sessions for unrelated work.
