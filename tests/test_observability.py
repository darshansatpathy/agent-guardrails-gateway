from __future__ import annotations

import json
import logging

import pytest
from fastapi.testclient import TestClient
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from guardrails_gateway import observability
from guardrails_gateway.api import create_app
from guardrails_gateway.gateway import Gateway
from guardrails_gateway.observability import JsonFormatter, request_id_var
from tests.conftest import make_call

_EXPORTER = InMemorySpanExporter()
_PROVIDER = TracerProvider()
_PROVIDER.add_span_processor(SimpleSpanProcessor(_EXPORTER))


@pytest.fixture
def spans(monkeypatch: pytest.MonkeyPatch) -> InMemorySpanExporter:
    _EXPORTER.clear()
    monkeypatch.setattr(observability, "_tracer", _PROVIDER.get_tracer("test"))
    return _EXPORTER


def test_each_decision_is_a_span(gateway: Gateway, grant: str, spans: InMemorySpanExporter) -> None:
    gateway.evaluate(make_call("delete_record", record_id="x"), grant)
    [s] = [s for s in spans.get_finished_spans() if s.name == "aggw.evaluate"]
    assert s.attributes is not None
    assert s.attributes["aggw.tool"] == "delete_record"
    assert s.attributes["aggw.outcome"] == "deny"
    assert s.attributes["aggw.rule"] == "grant.tool_out_of_scope"


def test_decision_spans_nest_under_the_agents_span(
    gateway: Gateway, grant: str, spans: InMemorySpanExporter
) -> None:
    tracer = _PROVIDER.get_tracer("agent")
    with tracer.start_as_current_span("agent.step") as parent:
        gateway.evaluate(make_call("search_docs", query="q"), grant)
    child = next(s for s in spans.get_finished_spans() if s.name == "aggw.evaluate")
    assert child.parent is not None
    assert child.parent.span_id == parent.get_span_context().span_id


def test_decisions_are_logged_as_json_with_request_id(
    gateway: Gateway, grant: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="aggw.decision")
    token = request_id_var.set("req-123")
    try:
        gateway.evaluate(make_call("search_docs", query="q", api_key="sk-secret"), grant)
    finally:
        request_id_var.reset(token)
    line = JsonFormatter().format(caplog.records[-1])
    payload = json.loads(line)
    assert payload["request_id"] == "req-123"
    assert payload["tool"] == "search_docs" and payload["outcome"] == "allow"
    assert payload["arguments"]["api_key"] == "***"
    assert "sk-secret" not in line


def test_api_echoes_or_assigns_request_ids(gateway: Gateway) -> None:
    client = TestClient(create_app(gateway, "t"))
    assert (
        client.get("/healthz", headers={"X-Request-ID": "abc-1"}).headers["x-request-id"] == "abc-1"
    )
    generated = client.get("/healthz", headers={"X-Request-ID": "bad id\n"}).headers["x-request-id"]
    assert generated != "bad id\n" and len(generated) == 32


def test_tracing_is_optional(gateway: Gateway, grant: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(observability, "_tracer", None)
    assert gateway.evaluate(make_call("search_docs", query="q"), grant).allowed


def test_configure_logging_emits_json(capsys: pytest.CaptureFixture[str]) -> None:
    observability.configure_logging("info")
    try:
        logging.getLogger("aggw.decision").info("decision", extra={"fields": {"tool": "t"}})
        out = capsys.readouterr().out.strip().splitlines()[-1]
        assert json.loads(out)["tool"] == "t"
    finally:
        for name in ("aggw", "guardrails_gateway"):
            logger = logging.getLogger(name)
            logger.handlers = []
            logger.propagate = True
