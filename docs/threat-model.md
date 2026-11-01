# Threat model

## Assets

- The systems tools can act on: payments, customer records, outbound email, files.
- The data those systems hold.
- The integrity of the record of what agents did.

## Trust boundaries

| Component | Trusted? | Notes |
|---|---|---|
| Model / agent | **No** | Treated as an insider that may be confused, manipulated or wrong. |
| Content the agent reads | **No** | Web pages, inbound email, documents, tool output. |
| Orchestrator | Yes | Holds the admin token; decides which tools a task needs. |
| Reviewers | Yes | Identified by the admin channel (OIDC in production). |
| Gateway host and keys | Yes | Compromise of the grant secret or audit key is out of scope. |

## Threats and mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | Agent calls a tool it was never meant to use | Default-deny policy; grant names exact tools | Policy authoring mistakes. Mitigated by `validate-policy` in CI and PR review. |
| T2 | Allowed tool, harmful arguments (huge refund, outside recipient) | Per-agent argument constraints with full-match regex, bounds, allow-lists, strict args | Constraints the policy author did not think of. |
| T3 | Indirect prompt injection drives data exfiltration | Taint tracking: egress after untrusted reads needs a human; recipient constraints | Exfiltration through a tool not marked `egress`. Classify tools carefully. |
| T4 | Stolen or replayed grant | HMAC signature, short TTL with a policy ceiling, task binding, revocation | Use within the TTL by whoever holds it. Keep TTLs short. |
| T5 | Approval laundering: approve a small refund, execute a large one | Approval bound to the call fingerprint (agent, task, tool, all arguments) | None known within the model. |
| T6 | Approval replay | Approvals are single use and expire | None known within the model. |
| T7 | Agent approves its own request | Approver identity must differ from the requesting agent | A compromised reviewer account. |
| T8 | Runaway loop or denial of wallet | Per-agent, per-tool sliding-window rate limits | Limits must be set per tool. |
| T9 | Covering tracks by editing the audit log | HMAC-chained records; verification names the first bad record | An attacker holding the audit key. Anchor the head hash externally. |
| T10 | Secrets leaking into logs | Argument redaction by key name before logging | Secrets in unexpected argument names or in free text. |

## Out of scope (deliberately)

- **Detecting prompt injection.** Reliable detection is an open problem. The gateway
  assumes injection will sometimes succeed and limits what a manipulated agent can do.
- **Content safety of model output** (toxicity, hallucination). That belongs in the
  application layer and in evals, not at the tool boundary.
- **Compromise of the gateway host or its keys.** Use your platform's secret manager,
  key rotation and host hardening.
- **Authorisation inside the downstream system.** The gateway is an additional layer;
  tools should still enforce their own access control.
