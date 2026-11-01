from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from guardrails_gateway.gateway import Gateway
from guardrails_gateway.mcp_proxy import McpInterceptor
from tests.conftest import POLICY_PATH

FAKE_SERVER = Path(__file__).parent / "fake_mcp_server.py"


@pytest.fixture
def interceptor(gateway: Gateway) -> McpInterceptor:
    token = gateway.issue_grant(
        "support-agent", "T-1", ["search_docs", "web_fetch", "send_email"], 600, "tests"
    )
    return McpInterceptor(gateway, token, "support-agent", "T-1", "mcp-session")


def _call(msg_id: int, name: str, **arguments: object) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def test_tools_list_is_filtered_to_policy_and_grant(interceptor: McpInterceptor) -> None:
    forward, reply = interceptor.on_client_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    )
    assert forward is not None and reply is None
    server_reply = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {"name": n} for n in ["search_docs", "delete_record", "refund_payment", "web_fetch"]
            ]
        },
    }
    visible = [t["name"] for t in interceptor.on_server_message(server_reply)["result"]["tools"]]
    assert visible == ["search_docs", "web_fetch"]


def test_denied_call_never_reaches_the_server(interceptor: McpInterceptor) -> None:
    forward, reply = interceptor.on_client_message(_call(2, "delete_record", record_id="x"))
    assert forward is None
    assert reply is not None
    assert reply["id"] == 2
    assert reply["result"]["isError"] is True
    assert "grant.tool_out_of_scope" in reply["result"]["content"][0]["text"]


def test_allowed_call_is_forwarded(interceptor: McpInterceptor) -> None:
    msg = _call(3, "search_docs", query="refunds")
    forward, reply = interceptor.on_client_message(msg)
    assert forward == msg and reply is None


def test_untrusted_output_taints_session_and_gates_egress(interceptor: McpInterceptor) -> None:
    interceptor.on_client_message(_call(4, "web_fetch", url="https://example.org"))
    interceptor.on_server_message(
        {"jsonrpc": "2.0", "id": 4, "result": {"content": [{"type": "text", "text": "page"}]}}
    )
    forward, reply = interceptor.on_client_message(
        _call(5, "send_email", to="a@example.com", subject="hi")
    )
    assert forward is None and reply is not None
    assert "pending human approval" in reply["result"]["content"][0]["text"]


def test_other_messages_pass_through(interceptor: McpInterceptor) -> None:
    msg = {"jsonrpc": "2.0", "id": 9, "method": "initialize", "params": {}}
    assert interceptor.on_client_message(msg) == (msg, None)


def test_end_to_end_over_stdio(tmp_path: Path, gateway: Gateway) -> None:
    """Run the real `aggw mcp-proxy` process in front of a fake MCP server."""
    secret = "e2e-secret-e2e-secret-e2e-secret-!!"
    from guardrails_gateway.grants import GrantIssuer

    token = GrantIssuer(secret.encode()).issue("support-agent", "T-7", ["search_docs"], 300)
    env = {
        **os.environ,
        "AGGW_GRANT_SECRET": secret,
        "AGGW_GRANT": token,
        "AGGW_POLICY": str(POLICY_PATH),
        "AGGW_DATA_DIR": str(tmp_path),
        "AGGW_ADMIN_TOKEN": "x",
    }
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        _call(2, "search_docs", query="refunds"),
        _call(3, "delete_record", record_id="x"),
    ]
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "guardrails_gateway.cli",
            "mcp-proxy",
            "--agent",
            "support-agent",
            "--task",
            "T-7",
            "--",
            sys.executable,
            str(FAKE_SERVER),
        ],
        input="\n".join(json.dumps(m) for m in messages) + "\n",
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )
    replies = {r["id"]: r for r in map(json.loads, proc.stdout.splitlines())}
    assert [t["name"] for t in replies[1]["result"]["tools"]] == ["search_docs"]
    assert replies[2]["result"]["isError"] is False
    assert "Denied by policy" in replies[3]["result"]["content"][0]["text"]
    audit = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert any('"tool": "delete_record"' in line for line in audit)
