"""Builds a Gateway from settings (environment variables or explicit arguments)."""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from guardrails_gateway.approvals import ApprovalStore
from guardrails_gateway.audit import AuditLog
from guardrails_gateway.gateway import Gateway
from guardrails_gateway.grants import GrantIssuer
from guardrails_gateway.policy import Policy
from guardrails_gateway.tools import ToolRegistry, demo_registry

log = logging.getLogger(__name__)

_PACKAGED = Path(__file__).resolve().parent / "policies" / "support-agent.yaml"
_REPO = Path(__file__).resolve().parents[2] / "policies" / "support-agent.yaml"
DEFAULT_POLICY = _PACKAGED if _PACKAGED.exists() else _REPO


@dataclass(frozen=True)
class Settings:
    policy_path: Path
    data_dir: Path
    grant_secret: bytes
    audit_key: bytes | None
    admin_token: str
    demo_tools: bool

    @classmethod
    def from_env(cls) -> Settings:
        secret = os.environ.get("AGGW_GRANT_SECRET")
        if not secret:
            log.warning("AGGW_GRANT_SECRET not set; using an ephemeral key (dev only)")
            secret = secrets.token_hex(32)
        admin = os.environ.get("AGGW_ADMIN_TOKEN")
        if not admin:
            admin = secrets.token_urlsafe(24)
            log.warning("AGGW_ADMIN_TOKEN not set; generated one for this process: %s", admin)
        audit_key = os.environ.get("AGGW_AUDIT_KEY")
        return cls(
            policy_path=Path(os.environ.get("AGGW_POLICY", str(DEFAULT_POLICY))),
            data_dir=Path(os.environ.get("AGGW_DATA_DIR", "./data")),
            grant_secret=secret.encode(),
            audit_key=audit_key.encode() if audit_key else None,
            admin_token=admin,
            demo_tools=os.environ.get("AGGW_DEMO_TOOLS", "true").lower() == "true",
        )


def build_gateway(settings: Settings, registry: ToolRegistry | None = None) -> Gateway:
    policy = Policy.from_yaml(settings.policy_path)
    if registry is None and settings.demo_tools:
        registry = demo_registry()
    return Gateway(
        policy=policy,
        grants=GrantIssuer(settings.grant_secret, policy.defaults.max_grant_ttl_seconds),
        audit=AuditLog(settings.data_dir / "audit.jsonl", key=settings.audit_key),
        approvals=ApprovalStore(settings.data_dir / "approvals.db"),
        registry=registry,
    )
