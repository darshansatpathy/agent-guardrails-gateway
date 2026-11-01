"""MCP stdio proxy: put the gateway in front of any Model Context Protocol server.

    agent / MCP client  <-- stdio -->  aggw mcp-proxy  <-- stdio -->  MCP server

The proxy speaks newline-delimited JSON-RPC 2.0, the MCP stdio transport. It passes
everything through except two methods:

- `tools/list` responses are filtered, so the agent only sees tools that both the
  policy and its task grant allow. A tool it cannot see is a tool it cannot try.
- `tools/call` requests are evaluated by the gateway first. Denied calls and calls
  awaiting approval never reach the server; the client gets an MCP tool error
  explaining why, which the model can read and act on.
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, field
from typing import Any

from guardrails_gateway.gateway import Gateway
from guardrails_gateway.models import Outcome, ToolCall

JsonRpc = dict[str, Any]


@dataclass
class McpInterceptor:
    """Pure message-level logic, kept free of I/O so it is easy to test."""

    gateway: Gateway
    grant_token: str
    agent_id: str
    task_id: str
    session_id: str
    _pending_lists: set[Any] = field(default_factory=set)
    _pending_calls: dict[Any, ToolCall] = field(default_factory=dict)

    def on_client_message(self, msg: JsonRpc) -> tuple[JsonRpc | None, JsonRpc | None]:
        """Return (message to forward to the server, reply to send back to the client)."""
        method = msg.get("method")
        if method == "tools/list" and "id" in msg:
            self._pending_lists.add(msg["id"])
            return msg, None
        if method != "tools/call":
            return msg, None

        params = msg.get("params") or {}
        call = ToolCall(
            agent_id=self.agent_id,
            task_id=self.task_id,
            session_id=self.session_id,
            tool=str(params.get("name", "")) or "<missing>",
            arguments=params.get("arguments") or {},
        )
        decision = self.gateway.evaluate(call, self.grant_token)
        if decision.outcome is Outcome.ALLOW:
            if "id" in msg:
                self._pending_calls[msg["id"]] = call
            return msg, None

        if decision.outcome is Outcome.REQUIRE_APPROVAL:
            text = (
                f"Blocked pending human approval ({decision.approval_id}): {decision.reason}. "
                "Retry the identical call after a reviewer approves it."
            )
        else:
            text = f"Denied by policy [{decision.rule}]: {decision.reason}"
        reply = {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "result": {"content": [{"type": "text", "text": text}], "isError": True},
        }
        return None, reply

    def on_server_message(self, msg: JsonRpc) -> JsonRpc:
        msg_id = msg.get("id")
        if msg_id in self._pending_lists and "result" in msg:
            self._pending_lists.discard(msg_id)
            visible = self._visible_tools()
            tools = msg["result"].get("tools", [])
            msg["result"]["tools"] = [t for t in tools if t.get("name") in visible]
        elif msg_id in self._pending_calls:
            call = self._pending_calls.pop(msg_id)
            if "result" in msg and not msg["result"].get("isError"):
                self.gateway.record_tool_output(call)
        return msg

    def _visible_tools(self) -> set[str]:
        allowed = set(self.gateway.policy.tools_for(self.agent_id))
        try:
            grant = self.gateway.grants.verify(self.grant_token)
        except Exception:
            return set()
        return allowed & set(grant.tools)


async def run_proxy(interceptor: McpInterceptor, server_cmd: list[str]) -> int:
    """Wire the interceptor between this process's stdio and a server subprocess."""
    server = await asyncio.create_subprocess_exec(
        *server_cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE
    )
    assert server.stdin is not None and server.stdout is not None
    loop = asyncio.get_running_loop()
    client_in = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(client_in), sys.stdin)

    def to_client(msg: JsonRpc) -> None:
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    async def pump_client() -> None:
        assert server.stdin is not None
        while line := await client_in.readline():
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            forward, reply = interceptor.on_client_message(msg)
            if reply is not None:
                to_client(reply)
            if forward is not None:
                server.stdin.write((json.dumps(forward) + "\n").encode())
                await server.stdin.drain()
        server.stdin.close()

    async def pump_server() -> None:
        assert server.stdout is not None
        while line := await server.stdout.readline():
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            to_client(interceptor.on_server_message(msg))

    await asyncio.gather(pump_client(), pump_server())
    return await server.wait()
