# Agent Guardrails Gateway

[![CI](https://github.com/darshansatpathy/agent-guardrails-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/darshansatpathy/agent-guardrails-gateway/actions/workflows/ci.yml)
[![CodeQL](https://github.com/darshansatpathy/agent-guardrails-gateway/actions/workflows/codeql.yml/badge.svg)](https://github.com/darshansatpathy/agent-guardrails-gateway/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![Typed](https://img.shields.io/badge/mypy-strict-informational)
![Attacks contained](https://img.shields.io/badge/attack%20scenarios-23%2F23%20contained-success)
![License](https://img.shields.io/badge/license-MIT-green)

**A policy enforcement point between AI agents and the tools they call.**
The agent can reason freely. It can only *act* through calls this gateway allows.

Guardrails written into a prompt are suggestions. A model can be talked out of them by a
crafted email or web page, and it is trained to finish the task, not to follow your
company's rules. This gateway moves the rules out of the prompt and into code, at the one
place every action has to pass through: the tool call.

```
agent  ──tool call──▶  GATEWAY  ──allowed calls only──▶  CRM · payments · email · MCP servers
                          │
                 grant → policy → arguments → rate limit → human gate
                          │
                 tamper-evident audit log of every decision
```

> Reference implementation built on synthetic data. It distils patterns from production
> agent platforms into a codebase you can run, read and extend in an afternoon.

---

## What it enforces

| Control | What it stops | How |
|---|---|---|
| **Task-scoped, expiring grants** | Standing access; a leaked token living forever | HMAC-signed grant per task naming the agent, the task, the exact tools, and a TTL capped by policy. Revoke one grant or a whole task instantly. |
| **Default-deny policy** | Agents using tools nobody approved | YAML policy reviewed in a PR. Tools not listed for an agent do not exist for it. |
| **Argument constraints** | "Allowed tool, dangerous arguments" (refund $50,000, email an outside address) | Per-agent regex (full match), allow-lists, numeric bounds, length caps, required/unknown-argument rules. |
| **Rate limits** | A looping or hijacked agent hammering an API | Sliding window per agent and tool. |
| **Human approval** | Irreversible or high-risk actions happening unattended | Approval bound to the exact call fingerprint, single use, expiring, and **the requesting agent can never approve itself**. |
| **Taint tracking** | Indirect prompt injection exfiltrating data | Once a session reads untrusted content (web, inbound email), every egress tool in that session needs a human. |
| **Tamper-evident audit** | Quietly editing history after an incident | Append-only JSONL, each record HMAC-chained to the previous one. `verify` names the first altered record. |
| **MCP proxy** | Agents seeing or calling MCP tools outside their remit | Drop-in stdio proxy: filters `tools/list`, enforces every `tools/call`. |

Mapped to the [OWASP Top 10 for LLM Applications](docs/threat-model.md#owasp-top-10-for-llm-applications-2025):
prompt injection (LLM01), sensitive information disclosure (LLM02), excessive agency
(LLM06) and unbounded consumption (LLM10).

## Architecture

```mermaid
flowchart TB
    O[Orchestrator] -- "1. grant: task, tools, TTL" --> G
    A[LLM agent] -- "tool call + grant" --> G
    M[MCP client] -- stdio --> P[aggw mcp-proxy] --> G

    subgraph G[Agent Guardrails Gateway]
        direction TB
        V1[Verify grant] --> V2[Policy: may this agent use this tool?]
        V2 --> V3[Argument constraints]
        V3 --> V4[Rate limit]
        V4 --> V5{Human gate}
    end

    V5 -- allow --> T[(Tools / MCP server)]
    V5 -- needs approval --> Q[Approval queue]
    R[Reviewer] -- approve or deny --> Q
    G -.-> L[(Hash-chained audit log)]
    T -. untrusted output .-> TT[Taint tracker] -.-> V5
```

The first failing check decides the outcome, and the outcome is always written to the
audit log, including denials. See [docs/architecture.md](docs/architecture.md) for the
full request lifecycle.

## See it work in 60 seconds (no API keys, no network)

```bash
git clone https://github.com/darshansatpathy/agent-guardrails-gateway
cd agent-guardrails-gateway
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,llm]"
aggw demo        # scripted walkthrough of every guardrail
aggw eval        # 23 attack scenarios + benign controls
```

The demo runs a support agent through every guardrail. Abridged output:

```text
 3. Refund above the agent's limit is denied
    result  DENY              rule=policy.argument_violation
    why     argument 'amount' exceeds the maximum of 500.0

 4. Refund within limit still needs a human (high risk)
    result  REQUIRE_APPROVAL  rule=human_gate

 5. The agent tries to approve its own refund
    result  REJECTED  an agent cannot approve its own request

 6. Identical call after approval is allowed and runs
    result  ALLOW             rule=approval.granted
    why     approved by finance-lead@example.com

10. Injected exfiltration to an outside address is denied
    result  DENY              rule=policy.argument_violation

11. Even a legit email now needs a human: the session is tainted
    result  REQUIRE_APPROVAL  rule=human_gate
    why     session read untrusted content (web_fetch) and this tool sends data out

13. Audit trail integrity
    someone edits the logged refund amount from 120 to 12...
    verify  ok=False first_bad_seq=7 reason=record contents were modified
```

## Evaluation

Guardrails are only as good as the attacks they have been tested against, so the repo
ships an attack corpus ([evals/scenarios.yaml](evals/scenarios.yaml)) and runs it on
every push. An attack passes only if the harmful action never executes. Benign scenarios
pass only if legitimate work is allowed, because a guardrail that blocks everything gets
switched off.

**Attacks contained: 23/23** · **Legitimate actions allowed: 6/6**

| Category | Kind | Passed |
|---|---|---|
| Approval abuse | attack | 4/4 |
| Argument abuse | attack | 6/6 |
| Audit integrity | attack | 1/1 |
| Credential abuse | attack | 4/4 |
| Excessive agency | attack | 3/3 |
| Prompt injection | attack | 4/4 |
| Resource abuse | attack | 1/1 |
| Legitimate work | benign | 6/6 |

The eval is tested too: the suite includes tests that weaken the policy (raise the refund
limit, loosen the recipient pattern, drop taint marking, over-block a safe tool) and
assert the eval catches each regression. CI publishes the table to the run summary and
fails if any scenario fails.

## Use it

### With an LLM agent

The agent loop hands every tool call the model proposes to the gateway and feeds the
verdict back as the tool's result. Tool schemas shown to the model are generated from the
policy, so the model only learns about tools it may use, with their limits described.

```bash
export AGGW_LLM_BASE_URL=https://api.openai.com/v1   # or Azure, vLLM, Ollama, LiteLLM
export AGGW_LLM_MODEL=gpt-4o-mini
export AGGW_LLM_API_KEY=...
aggw agent "Customer acme@example.com was double charged on INV-1001. Sort it out."
```

Illustrative output. The model's wording and the order of its calls will vary; the
gateway's verdicts for a given call will not.

```text
ALLOW             read_invoice    rule=allow  all checks passed
REQUIRE_APPROVAL  refund_payment  rule=human_gate  'refund_payment' is high risk
ALLOW             send_email      rule=allow  all checks passed

I've confirmed the duplicate charge and requested a $120 refund, which is waiting for
finance approval. I've emailed the customer to let them know.
```

For Azure OpenAI, set `AGGW_LLM_BASE_URL` to the deployment URL and
`AGGW_AZURE_API_VERSION`. Anything with a Chat Completions-compatible endpoint works,
which is how Bedrock, Vertex and other hosted models are commonly fronted.

```python
from guardrails_gateway.agent import GuardedAgent
from guardrails_gateway.config import Settings, build_gateway
from guardrails_gateway.providers import OpenAICompatibleProvider

gateway = build_gateway(Settings.from_env())
grant = gateway.issue_grant(
    "support-agent",
    "T-42",
    ["read_invoice", "send_email"],
    ttl_seconds=900,
    issued_by="orchestrator",
)
run = GuardedAgent(
    gateway, OpenAICompatibleProvider.from_env(), "support-agent", "T-42", grant
).run("Has INV-1001 been paid?")
```

### As an HTTP service

```bash
cp .env.example .env    # set real secrets: openssl rand -hex 32
docker compose up --build
# or: aggw serve --port 8080    (OpenAPI docs at http://localhost:8080/docs)
```

```bash
# Orchestrator: grant the agent two tools for one task, for 15 minutes
GRANT=$(curl -s localhost:8080/v1/grants -H "Authorization: Bearer $AGGW_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"agent_id":"support-agent","task_id":"T-42","tools":["search_docs","refund_payment"],
       "ttl_seconds":900,"issued_by":"orchestrator"}' | jq -r .grant)

# Agent: request a refund. High risk, so it waits for a human.
curl -s localhost:8080/v1/tool-calls -H "X-Agent-Grant: $GRANT" \
  -H 'content-type: application/json' \
  -d '{"agent_id":"support-agent","task_id":"T-42","session_id":"s1","tool":"refund_payment",
       "arguments":{"invoice_id":"INV-1001","amount":120,"currency":"USD"}}'
# {"decision":{"outcome":"require_approval","rule":"human_gate","approval_id":"apr_..."}}

# Reviewer approves; the agent retries the identical call and it runs once.
curl -s -X POST localhost:8080/v1/approvals/apr_.../approve \
  -H "Authorization: Bearer $AGGW_ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"decided_by":"finance-lead@example.com","note":"duplicate charge"}'
```

| Endpoint | Who | Purpose |
|---|---|---|
| `POST /v1/tool-calls` | agent (`X-Agent-Grant`) | evaluate and, if allowed, execute |
| `POST /v1/grants` | orchestrator (admin) | issue a task grant |
| `POST /v1/tasks/{id}/revoke` | on-call (admin) | kill switch for a task |
| `GET /v1/approvals` · `POST …/approve` · `POST …/deny` | reviewers (admin) | human-in-the-loop |
| `GET /v1/audit/verify` | auditors (admin) | check the chain |
| `GET /metrics` | monitoring | Prometheus counters by outcome and rule |

The container runs as a non-root user with a read-only filesystem, no Linux
capabilities and `no-new-privileges` in the compose file.

### In front of any MCP server

```bash
export AGGW_GRANT="<grant for this agent and task>"
aggw mcp-proxy --agent support-agent --task T-42 -- npx -y @modelcontextprotocol/server-filesystem ./docs
```

Point your MCP client at the proxy command instead of the server. The agent only sees the
tools its policy and grant allow, and blocked calls come back as MCP tool errors the model
can read. A client config example is in [examples/mcp-client-config.json](examples/mcp-client-config.json).

## Policy

Policies are plain YAML, meant to be reviewed like infrastructure code. Abridged from
[policies/support-agent.yaml](policies/support-agent.yaml):

```yaml
tools:
  web_fetch:      { risk: low, untrusted_output: true }   # may carry injected instructions
  send_email:     { risk: medium, egress: true }          # data leaves the organisation
  refund_payment: { risk: high }                          # always needs a human
  delete_record:  { risk: high, irreversible: true }

agents:
  support-agent:
    tools:
      send_email:
        constraints:
          to: { required: true, pattern: "[^@\\s]+@example\\.com" }   # customers only
        strict_args: true
        rate_limit: { max_calls: 5, per_seconds: 60 }
      refund_payment:
        constraints:
          amount:   { required: true, min: 0.01, max: 500 }
          currency: { required: true, one_of: [USD, EUR, GBP, AED, SAR, INR] }
      # delete_record is absent: this agent can never delete anything.
```

`aggw validate-policy <file>` lints a policy in CI before it ships, and `aggw eval
--policy <file>` runs the attack corpus against it. Typos in keys, undefined tools and
invalid regexes fail validation instead of failing open at runtime.

## Observability

- **Decision logs:** one JSON line per decision on the `aggw.decision` logger, with agent,
  tool, outcome, rule, redacted arguments, latency and the request ID.
- **Request IDs:** `X-Request-ID` is accepted from your edge or generated, and returned on
  every response.
- **Traces:** with `pip install "agent-guardrails-gateway[otel]"` and an OpenTelemetry
  SDK configured, each evaluation is an `aggw.evaluate` span nested under the agent's own
  span, so a trace shows exactly which step a guardrail stopped.
- **Metrics:** `/metrics` exposes Prometheus counters by outcome and by rule.

## Design decisions

Each is recorded as an ADR with the alternatives considered:

- [ADR-0001](docs/adr/0001-enforce-at-the-tool-boundary.md) Enforce at the tool boundary, not in the prompt
- [ADR-0002](docs/adr/0002-stateless-signed-grants.md) Stateless HMAC grants scoped to a task
- [ADR-0003](docs/adr/0003-approvals-bound-to-call-fingerprint.md) Approvals bound to the exact call, single use
- [ADR-0004](docs/adr/0004-taint-tracking-over-injection-detection.md) Contain prompt injection with taint tracking instead of detecting it
- [ADR-0005](docs/adr/0005-hash-chained-audit-log.md) Keyed hash chain for the audit log
- [ADR-0006](docs/adr/0006-attack-corpus-in-ci.md) Test guardrails against an attack corpus in CI
- [ADR-0007](docs/adr/0007-provider-agnostic-agent-loop.md) Provider-agnostic agent loop with schemas from policy

The threat model, including what this gateway deliberately does *not* defend against, is
in [docs/threat-model.md](docs/threat-model.md).

## Quality bar

| Check | Where it runs |
|---|---|
| 111 tests (unit, API, agent loop, eval regressions, end-to-end MCP proxy over stdio), 92% coverage, 85% gate | CI, Python 3.11 to 3.13 |
| `mypy --strict`, ruff lint and format | CI |
| Attack-scenario evaluation, published to the run summary | CI |
| Dependency audit (`pip-audit`) | CI |
| CodeQL security analysis (`security-extended`) | CI, weekly |
| Container build, health check and a live deny decision | CI |
| Dependabot for Python, Actions and the base image | Weekly |

## Taking it to production

This is a reference implementation, built to be read and extended. The seams for an
enterprise deployment are deliberate:

| Here | In production |
|---|---|
| Admin bearer token | OIDC/SAML via your identity provider; reviewer identity from the token |
| SQLite approvals | Postgres, with approvals surfaced in Slack/Teams/ServiceNow |
| In-memory taint and rate state | Redis, so multiple gateway replicas share state |
| YAML policy engine | Same model compiled to OPA/Rego or Cedar if you already run one |
| Local audit file | Ship to your SIEM; anchor the chain head in WORM storage daily |
| Env-var secrets | Secret manager with rotation (Key Vault, Secrets Manager, Secret Manager) |

## Project layout

```
src/guardrails_gateway/
  gateway.py        the five-step decision pipeline and tool execution
  policy.py         YAML policy model and argument constraints
  grants.py         task-scoped signed grants, revocation
  approvals.py      human approval queue (SQLite)
  audit.py          hash-chained audit log and verification
  taint.py          untrusted-content tracking per session
  ratelimit.py      sliding-window limits
  agent.py          agent loop that routes every tool call through the gateway
  providers.py      model providers: OpenAI-compatible, Azure OpenAI, scripted mock
  evals.py          attack-scenario evaluation
  observability.py  JSON logs, request IDs, OpenTelemetry spans
  mcp_proxy.py      stdio proxy for MCP servers
  api.py            FastAPI service
  cli.py            aggw serve | demo | eval | agent | verify-audit | validate-policy | mcp-proxy
policies/           example policies
evals/              attack and benign scenarios
docs/               architecture, threat model, ADRs
tests/              unit, API, eval and end-to-end tests
```

## About

Built by **Darshan Kumar Satpathy**, Solutions Architect for Data & AI.
[Portfolio](https://darshansatpathy.github.io) · [LinkedIn](https://www.linkedin.com/in/darshansatpathy/)

MIT licensed. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
