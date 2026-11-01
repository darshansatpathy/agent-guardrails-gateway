"""Append-only, hash-chained audit log.

Every decision, approval and tool result is written as one JSON line. Each line carries
the hash of the line before it, so editing, deleting or reordering any past entry breaks
the chain from that point on, and `verify()` reports exactly where.

With a key configured, links are HMAC-SHA256 rather than plain SHA-256. An attacker
who can write to the file but does not hold the key cannot rebuild a valid chain.
Exporting the latest head hash to a separate system (a ticket, a SIEM, object-lock
storage) anchors the chain against wholesale replacement too.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    head: str
    first_bad_seq: int | None = None
    reason: str | None = None


class AuditLog:
    def __init__(self, path: str | Path, key: bytes | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key = key
        self._lock = threading.Lock()
        self._seq, self._head = self._load_tail()

    @property
    def head(self) -> str:
        return self._head

    def append(self, event: str, data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            record: dict[str, Any] = {
                "seq": self._seq + 1,
                "ts": round(time.time(), 6),
                "event": event,
                "data": data,
                "prev": self._head,
            }
            record["hash"] = self._link(record)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True, default=str) + "\n")
            self._seq = record["seq"]
            self._head = record["hash"]
            return record

    def records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def verify(self) -> VerifyResult:
        prev = GENESIS
        count = 0
        if not self.path.exists():
            return VerifyResult(ok=True, records=0, head=GENESIS)
        with self.path.open(encoding="utf-8") as fh:
            for expected_seq, line in enumerate((ln for ln in fh if ln.strip()), start=1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return VerifyResult(False, count, prev, expected_seq, "line is not valid JSON")
                if record.get("seq") != expected_seq:
                    return VerifyResult(
                        False, count, prev, expected_seq, "sequence gap or reordering"
                    )
                if record.get("prev") != prev:
                    return VerifyResult(
                        False, count, prev, expected_seq, "previous-hash link is broken"
                    )
                if not hmac.compare_digest(str(record.get("hash")), self._link(record)):
                    return VerifyResult(
                        False, count, prev, expected_seq, "record contents were modified"
                    )
                prev = record["hash"]
                count += 1
        return VerifyResult(ok=True, records=count, head=prev)

    def _link(self, record: dict[str, Any]) -> str:
        body = {k: record[k] for k in ("seq", "ts", "event", "data", "prev")}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
        material = canonical.encode()
        if self._key:
            return hmac.new(self._key, material, hashlib.sha256).hexdigest()
        return hashlib.sha256(material).hexdigest()

    def _load_tail(self) -> tuple[int, str]:
        records = self.records()
        if not records:
            return 0, GENESIS
        last = records[-1]
        return int(last["seq"]), str(last["hash"])
