"""A minimal MCP-style stdio server used by the end-to-end proxy test."""

from __future__ import annotations

import json
import sys

TOOLS = ["search_docs", "delete_record", "refund_payment", "web_fetch"]


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        if msg.get("method") == "tools/list":
            result = {"tools": [{"name": n, "inputSchema": {"type": "object"}} for n in TOOLS]}
        elif msg.get("method") == "tools/call":
            name = msg["params"]["name"]
            result = {"content": [{"type": "text", "text": f"ran {name}"}], "isError": False}
        else:
            result = {}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}))
        sys.stdout.write("\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
