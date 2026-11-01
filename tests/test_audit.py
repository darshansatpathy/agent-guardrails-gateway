from __future__ import annotations

import json
from pathlib import Path

from guardrails_gateway.audit import GENESIS, AuditLog


def _write(log: AuditLog, n: int = 5) -> None:
    for i in range(n):
        log.append("decision", {"i": i, "tool": "refund_payment", "amount": 100 + i})


def _lines(path: Path) -> list[str]:
    return path.read_text().splitlines()


def test_empty_log_verifies(tmp_path: Path) -> None:
    result = AuditLog(tmp_path / "a.jsonl").verify()
    assert result.ok and result.records == 0 and result.head == GENESIS


def test_chain_verifies_and_head_advances(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "a.jsonl", key=b"k")
    _write(log)
    result = log.verify()
    assert result.ok and result.records == 5 and result.head == log.head


def test_modified_record_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path, key=b"k")
    _write(log)
    lines = _lines(path)
    record = json.loads(lines[2])
    record["data"]["amount"] = 1
    lines[2] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")
    result = log.verify()
    assert not result.ok
    assert result.first_bad_seq == 3
    assert result.reason == "record contents were modified"


def test_deleted_record_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    _write(log)
    lines = _lines(path)
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    result = log.verify()
    assert not result.ok and result.first_bad_seq == 2


def test_reordered_records_are_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    _write(log)
    lines = _lines(path)
    lines[1], lines[2] = lines[2], lines[1]
    path.write_text("\n".join(lines) + "\n")
    assert not log.verify().ok


def test_rebuilt_chain_without_the_key_fails(tmp_path: Path) -> None:
    """An attacker who rewrites and re-hashes the file with plain SHA-256 is caught."""
    path = tmp_path / "a.jsonl"
    _write(AuditLog(path, key=b"real-key"))
    forged = tmp_path / "forged.jsonl"
    _write(AuditLog(forged))  # same content, no key
    path.write_text(forged.read_text())
    assert not AuditLog(path, key=b"real-key").verify().ok


def test_reopening_continues_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    _write(AuditLog(path, key=b"k"), 3)
    reopened = AuditLog(path, key=b"k")
    _write(reopened, 2)
    result = reopened.verify()
    assert result.ok and result.records == 5


def test_garbage_line_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    _write(log, 2)
    with path.open("a") as fh:
        fh.write("not json\n")
    result = log.verify()
    assert not result.ok and result.first_bad_seq == 3
