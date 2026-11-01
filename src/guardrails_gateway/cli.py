"""Command-line interface: `aggw serve | demo | verify-audit | validate-policy | mcp-proxy`."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from guardrails_gateway.audit import AuditLog
from guardrails_gateway.policy import Policy


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "guardrails_gateway.api:app_from_env",
        factory=True,
        host=args.host,
        port=args.port,
        log_level="info",
    )
    return 0


def _cmd_demo(_: argparse.Namespace) -> int:
    from guardrails_gateway import demo

    demo.main()
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    key = os.environ.get("AGGW_AUDIT_KEY")
    result = AuditLog(args.path, key=key.encode() if key else None).verify()
    if result.ok:
        print(f"OK  {result.records} records  head={result.head}")
        return 0
    print(f"TAMPERED  first bad record: seq {result.first_bad_seq} ({result.reason})")
    return 1


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        policy = Policy.from_yaml(args.path)
    except Exception as exc:
        print(f"INVALID  {exc}")
        return 1
    print(f"OK  {len(policy.tools)} tools, {len(policy.agents)} agents")
    for agent_id in sorted(policy.agents):
        print(f"  {agent_id}: {', '.join(policy.tools_for(agent_id)) or '(no tools)'}")
    return 0


def _cmd_mcp_proxy(args: argparse.Namespace) -> int:
    from guardrails_gateway.config import Settings, build_gateway
    from guardrails_gateway.mcp_proxy import McpInterceptor, run_proxy

    grant = os.environ.get("AGGW_GRANT")
    if not grant:
        print("AGGW_GRANT must hold the task grant for this agent", file=sys.stderr)
        return 2
    if not args.server:
        print("give the MCP server command after --", file=sys.stderr)
        return 2
    gateway = build_gateway(Settings.from_env())
    interceptor = McpInterceptor(
        gateway=gateway,
        grant_token=grant,
        agent_id=args.agent,
        task_id=args.task,
        session_id=args.session or args.task,
    )
    return asyncio.run(run_proxy(interceptor, args.server))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aggw", description="Agent Guardrails Gateway")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the HTTP API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.set_defaults(func=_cmd_serve)

    sub.add_parser("demo", help="run the offline walkthrough").set_defaults(func=_cmd_demo)

    verify = sub.add_parser("verify-audit", help="check an audit log for tampering")
    verify.add_argument("path", type=Path)
    verify.set_defaults(func=_cmd_verify)

    validate = sub.add_parser("validate-policy", help="lint a policy file")
    validate.add_argument("path", type=Path)
    validate.set_defaults(func=_cmd_validate)

    proxy = sub.add_parser("mcp-proxy", help="guard an MCP server over stdio")
    proxy.add_argument("--agent", required=True)
    proxy.add_argument("--task", required=True)
    proxy.add_argument("--session")
    proxy.add_argument("server", nargs=argparse.REMAINDER, help="-- <server command>")
    proxy.set_defaults(func=_cmd_mcp_proxy)

    args = parser.parse_args(argv)
    if getattr(args, "server", None) and args.server[:1] == ["--"]:
        args.server = args.server[1:]
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
