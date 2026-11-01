"""Structured logging, request IDs and optional OpenTelemetry tracing.

- Every decision is logged once as a JSON line on the `aggw.decision` logger, with the
  request ID of the HTTP call that caused it, so logs join cleanly with your gateway or
  agent logs in any log platform.
- If `opentelemetry-api` is installed, each evaluation is a span (`aggw.evaluate`) with
  the agent, tool, outcome and rule as attributes; it nests under whatever span the
  calling agent already has open. Without it, tracing is a no-op.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import sys
import time
from collections.abc import Iterator
from typing import Any

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "aggw_request_id", default=None
)

decision_log = logging.getLogger("aggw.decision")

try:  # optional dependency
    from opentelemetry import trace as _otel_trace

    _tracer: Any = _otel_trace.get_tracer("agent-guardrails-gateway")
except ImportError:  # pragma: no cover - exercised only without the extra
    _tracer = None


class JsonFormatter(logging.Formatter):
    """One JSON object per line: time, level, logger, message, request_id and extras."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": round(record.created, 3),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None) or request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    """Route the gateway's loggers to stdout as JSON lines."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    for name in ("aggw", "guardrails_gateway"):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.setLevel(level.upper())
        logger.propagate = False


def log_decision(fields: dict[str, Any]) -> None:
    # Capture the request ID now: handlers may format the record later, off the request.
    decision_log.info("decision", extra={"fields": fields, "request_id": request_id_var.get()})


@contextlib.contextmanager
def span(name: str, attributes: dict[str, Any]) -> Iterator[Any]:
    """Open an OpenTelemetry span if tracing is available; otherwise do nothing."""
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as current:
        for key, value in attributes.items():
            if value is not None:
                current.set_attribute(key, value)
        yield current


def set_span_attributes(current: Any, attributes: dict[str, Any]) -> None:
    if current is None:
        return
    for key, value in attributes.items():
        if value is not None:
            current.set_attribute(key, value)


class Timer:
    def __init__(self) -> None:
        self.started = time.perf_counter()

    @property
    def ms(self) -> float:
        return round((time.perf_counter() - self.started) * 1000, 3)
