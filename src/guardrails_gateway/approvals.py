"""Human-in-the-loop approvals, stored in SQLite.

Rules this module enforces:
- An approval is bound to the exact call fingerprint (agent, task, tool, arguments).
- An approval is single use: it is consumed by the call it authorises.
- Approvals expire if nobody acts on them.
- The agent that asked can never approve its own request (separation of duties).
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from guardrails_gateway.models import ToolCall


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class ApprovalError(Exception):
    pass


@dataclass(frozen=True)
class Approval:
    approval_id: str
    fingerprint: str
    call: dict[str, Any]
    reason: str
    status: ApprovalStatus
    created_at: float
    expires_at: float
    decided_by: str | None
    note: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "fingerprint": self.fingerprint,
            "call": self.call,
            "reason": self.reason,
            "status": self.status.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "decided_by": self.decided_by,
            "note": self.note,
        }


_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    call_json   TEXT NOT NULL,
    reason      TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    decided_by  TEXT,
    note        TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_fp ON approvals (fingerprint, status);
"""


class ApprovalStore:
    def __init__(self, path: str | Path = ":memory:", clock: Callable[[], float] = time.time):
        self._clock = clock
        self._lock = threading.Lock()
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)

    def request(self, call: ToolCall, reason: str, ttl_seconds: int) -> Approval:
        """Open an approval request, or return the pending one for the same call."""
        fingerprint = call.fingerprint()
        with self._lock:
            self._expire_stale()
            row = self._db.execute(
                "SELECT * FROM approvals WHERE fingerprint = ? AND status = ?",
                (fingerprint, ApprovalStatus.PENDING.value),
            ).fetchone()
            if row is not None:
                return self._row(row)
            now = self._clock()
            approval_id = "apr_" + secrets.token_hex(8)
            self._db.execute(
                "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (
                    approval_id,
                    fingerprint,
                    json.dumps(call.model_dump(), sort_keys=True),
                    reason,
                    ApprovalStatus.PENDING.value,
                    now,
                    now + ttl_seconds,
                ),
            )
            self._db.commit()
        return self.get(approval_id)

    def decide(self, approval_id: str, approve: bool, decided_by: str, note: str = "") -> Approval:
        approval = self.get(approval_id)
        if approval.status is not ApprovalStatus.PENDING:
            raise ApprovalError(f"approval is {approval.status.value}, not pending")
        if approval.expires_at <= self._clock():
            self._set_status(approval_id, ApprovalStatus.EXPIRED)
            raise ApprovalError("approval request has expired")
        if decided_by == approval.call.get("agent_id"):
            raise ApprovalError("an agent cannot approve its own request")
        status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
        with self._lock:
            self._db.execute(
                "UPDATE approvals SET status = ?, decided_by = ?, note = ? WHERE approval_id = ?",
                (status.value, decided_by, note or None, approval_id),
            )
            self._db.commit()
        return self.get(approval_id)

    def consume(self, call: ToolCall) -> Approval | None:
        """Use up an approved, unexpired approval for exactly this call, if one exists."""
        with self._lock:
            self._expire_stale()
            row = self._db.execute(
                "SELECT * FROM approvals WHERE fingerprint = ? AND status = ? "
                "ORDER BY created_at LIMIT 1",
                (call.fingerprint(), ApprovalStatus.APPROVED.value),
            ).fetchone()
            if row is None:
                return None
            self._db.execute(
                "UPDATE approvals SET status = ? WHERE approval_id = ?",
                (ApprovalStatus.CONSUMED.value, row["approval_id"]),
            )
            self._db.commit()
        return self.get(row["approval_id"])

    def get(self, approval_id: str) -> Approval:
        row = self._db.execute(
            "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
        ).fetchone()
        if row is None:
            raise ApprovalError(f"unknown approval '{approval_id}'")
        return self._row(row)

    def list(self, status: ApprovalStatus | None = None) -> list[Approval]:
        with self._lock:
            self._expire_stale()
        if status is None:
            rows = self._db.execute("SELECT * FROM approvals ORDER BY created_at").fetchall()
        else:
            rows = self._db.execute(
                "SELECT * FROM approvals WHERE status = ? ORDER BY created_at", (status.value,)
            ).fetchall()
        return [self._row(r) for r in rows]

    def close(self) -> None:
        self._db.close()

    def _expire_stale(self) -> None:
        self._db.execute(
            "UPDATE approvals SET status = ? WHERE status IN (?, ?) AND expires_at <= ?",
            (
                ApprovalStatus.EXPIRED.value,
                ApprovalStatus.PENDING.value,
                ApprovalStatus.APPROVED.value,
                self._clock(),
            ),
        )
        self._db.commit()

    def _set_status(self, approval_id: str, status: ApprovalStatus) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE approvals SET status = ? WHERE approval_id = ?",
                (status.value, approval_id),
            )
            self._db.commit()

    @staticmethod
    def _row(row: sqlite3.Row) -> Approval:
        return Approval(
            approval_id=row["approval_id"],
            fingerprint=row["fingerprint"],
            call=json.loads(row["call_json"]),
            reason=row["reason"],
            status=ApprovalStatus(row["status"]),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            decided_by=row["decided_by"],
            note=row["note"],
        )
