"""Task-scoped, expiring capability grants.

An agent never holds standing access. For each task, the orchestrator asks for a grant
that names the agent, the task, the subset of tools the task needs, and a short expiry.
The grant is an HMAC-signed token, so the gateway can verify it without a database
lookup, and a leaked token is useless after it expires or once its task is revoked.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field


class GrantError(Exception):
    """Raised when a grant is malformed, forged, expired, revoked or out of scope."""


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class Grant:
    grant_id: str
    agent_id: str
    task_id: str
    tools: frozenset[str]
    issued_at: int
    expires_at: int

    def covers(self, tool: str) -> bool:
        return tool in self.tools


@dataclass
class GrantIssuer:
    """Issues and verifies grants with a shared HMAC key."""

    secret: bytes
    max_ttl_seconds: int = 3600
    clock: Callable[[], float] = time.time
    _revoked: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if len(self.secret) < 32:
            raise ValueError("grant secret must be at least 32 bytes")

    def issue(self, agent_id: str, task_id: str, tools: list[str], ttl_seconds: int) -> str:
        if ttl_seconds <= 0:
            raise GrantError("ttl must be positive")
        if ttl_seconds > self.max_ttl_seconds:
            raise GrantError(f"ttl exceeds the maximum of {self.max_ttl_seconds} seconds")
        if not tools:
            raise GrantError("a grant must name at least one tool")
        now = int(self.clock())
        payload = {
            "gid": secrets.token_hex(8),
            "agt": agent_id,
            "tsk": task_id,
            "tls": sorted(set(tools)),
            "iat": now,
            "exp": now + ttl_seconds,
        }
        body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{body}.{self._sign(body)}"

    def verify(self, token: str) -> Grant:
        try:
            body, signature = token.split(".", 1)
        except ValueError as exc:
            raise GrantError("malformed grant") from exc
        if not hmac.compare_digest(signature, self._sign(body)):
            raise GrantError("grant signature is invalid")
        try:
            payload = json.loads(_b64decode(body))
            grant = Grant(
                grant_id=str(payload["gid"]),
                agent_id=str(payload["agt"]),
                task_id=str(payload["tsk"]),
                tools=frozenset(str(t) for t in payload["tls"]),
                issued_at=int(payload["iat"]),
                expires_at=int(payload["exp"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GrantError("grant payload is invalid") from exc
        if grant.expires_at <= int(self.clock()):
            raise GrantError("grant has expired")
        if grant.grant_id in self._revoked or f"task:{grant.task_id}" in self._revoked:
            raise GrantError("grant has been revoked")
        return grant

    def revoke(self, grant_id: str) -> None:
        self._revoked.add(grant_id)

    def revoke_task(self, task_id: str) -> None:
        """Kill switch: invalidate every grant issued for a task."""
        self._revoked.add(f"task:{task_id}")

    def _sign(self, body: str) -> str:
        digest = hmac.new(self.secret, body.encode(), hashlib.sha256).digest()
        return _b64encode(digest)
