# ADR-0005: Keyed hash chain for the audit log

**Status:** accepted

## Context

After an incident, the first question is "what did the agent do, and who approved it?"
The answer is only useful if the log could not have been edited afterwards.

## Decision

Every decision, approval, grant event and tool result is appended as one JSON line. Each
record includes the hash of the previous record. With `AGGW_AUDIT_KEY` set, links are
HMAC-SHA256, so someone who can write the file but does not hold the key cannot rebuild a
valid chain. `aggw verify-audit` replays the chain and reports the first bad record.

Operators should periodically export the head hash to a separate system (ticket, SIEM,
object-lock bucket) so the whole file cannot be swapped for a forged one.

## Alternatives considered

- **Database table.** Easy to query; easy to `UPDATE` silently.
- **Managed ledger / WORM storage.** Stronger, and the recommended production sink. The
  local chain keeps the guarantee portable and verifiable offline.

## Consequences

- Tampering is detectable, not preventable. Pair it with restricted write access.
- The log contains call arguments (redacted by key name). Treat it as sensitive data.
