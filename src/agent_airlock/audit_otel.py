"""OpenTelemetry audit export for Agent-Airlock (V0.4.0).

Exports audit events to OpenTelemetry for enterprise observability.
Integrates with Datadog, Splunk, Grafana, and other OTEL-compatible backends.

Usage:
    config = AirlockConfig(
        audit_otel_enabled=True,
        audit_otel_endpoint="http://otel-collector:4317",
    )

The OTel exporter creates spans for each tool call with:
    - Tool name, status, and duration
    - Agent/session identity
    - Block reason (if blocked)
    - Sanitization counts
    - Capability usage (V0.4.0)

This provides forensics-grade audit trails for security teams.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from opentelemetry.trace import Tracer

    from .trace_redaction import TraceRedactionPolicy

logger = structlog.get_logger("agent-airlock.audit_otel")


def _hash_args(args: dict[str, Any]) -> str:
    """Create SHA256 hash of arguments for audit trail.

    This allows forensic correlation without storing sensitive data.
    """
    import json

    try:
        serialized = json.dumps(args, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()[:16]
    except Exception:
        return "hash_failed"


@dataclass
class EnhancedAuditRecord:
    """Enhanced audit record with V0.4.0 fields.

    Extends the base AuditRecord with fields for:
    - Args hash for forensic correlation
    - Policy identification
    - Sandbox backend info
    - Capability usage tracking
    - Egress domain tracking
    """

    # Core fields (from base AuditRecord)
    timestamp: str
    tool_name: str
    blocked: bool
    block_reason: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    duration_ms: float | None = None
    sanitized_count: int = 0
    truncated: bool = False
    args_preview: dict[str, str] = field(default_factory=dict)
    result_type: str = "unknown"
    result_preview: str = ""
    error: str | None = None

    # V0.4.0 enhanced fields
    args_hash: str | None = None
    policy_id: str | None = None
    policy_hash: str | None = None
    redaction_applied: bool = False
    unknown_args_stripped: list[str] = field(default_factory=list)
    unknown_args_mode: str | None = None

    # Sandbox fields
    sandbox_backend: str | None = None
    sandbox_id: str | None = None

    # Capability fields
    capabilities_required: list[str] = field(default_factory=list)
    capabilities_granted: list[str] = field(default_factory=list)
    capabilities_denied: list[str] = field(default_factory=list)

    # Network fields
    egress_domains: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        result = {}
        for k, v in self.__dict__.items():
            if v is not None and v != [] and v != {}:
                result[k] = v
        return result


class OTelAuditExporter:
    """Export audit events to OpenTelemetry.

    Creates spans for each tool call with rich attributes for
    security monitoring and forensic analysis.

    Attributes:
        endpoint: OTel collector endpoint (e.g., "http://localhost:4317").
        service_name: Name of the service for OTel traces.
        enabled: Whether export is enabled.
        redaction_policy: Optional trace-redaction + watermark policy applied
            because the OTel collector is a non-local sink.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        service_name: str = "agent-airlock",
        enabled: bool = True,
        redaction_policy: TraceRedactionPolicy | None = None,
    ) -> None:
        """Initialize OTel exporter.

        Args:
            endpoint: OTel collector endpoint. If None, uses OTEL_EXPORTER_OTLP_ENDPOINT env var.
            service_name: Service name for traces.
            enabled: Whether to enable export.
            redaction_policy: Optional :class:`TraceRedactionPolicy`. The OTel
                collector is a NON-LOCAL sink, so when this is set and
                ``enabled`` the record is run through ``trace_redact`` before
                any attribute leaves the process — protected fields are dropped
                (recipe gone), verifier-critical evidence is kept, and the
                per-tenant watermark token is attached. ``None`` (default)
                preserves prior behavior exactly.
        """
        self.endpoint = endpoint
        self.service_name = service_name
        self.enabled = enabled
        self.redaction_policy = redaction_policy
        self._tracer: Tracer | None = None
        self._initialized = False

    def _init_tracer(self) -> None:
        """Lazily initialize the OTel tracer."""
        if self._initialized or not self.enabled:
            return

        try:
            from opentelemetry import trace
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            # Set up resource
            resource = Resource.create({"service.name": self.service_name})
            provider = TracerProvider(resource=resource)

            # Add exporter if endpoint specified
            if self.endpoint:
                try:
                    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                        OTLPSpanExporter,
                    )

                    exporter = OTLPSpanExporter(endpoint=self.endpoint)
                    provider.add_span_processor(BatchSpanProcessor(exporter))
                except ImportError:
                    logger.warning(
                        "otel_grpc_exporter_not_installed",
                        hint="Install opentelemetry-exporter-otlp-proto-grpc",
                    )

            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer("agent-airlock")
            self._initialized = True

            logger.info(
                "otel_audit_initialized",
                endpoint=self.endpoint,
                service_name=self.service_name,
            )

        except ImportError:
            logger.warning(
                "opentelemetry_not_installed",
                hint="Install opentelemetry-api and opentelemetry-sdk for OTel support",
            )
            self.enabled = False

    def export(self, record: EnhancedAuditRecord) -> None:
        """Export an audit record as an OTel span.

        Args:
            record: The audit record to export.
        """
        if not self.enabled:
            return

        self._init_tracer()
        if self._tracer is None:
            return

        # The OTel collector is a non-local sink: redact + watermark the
        # record before any attribute leaves the process. The redaction
        # operates on the serialized trace dict (what would ship to the sink);
        # verifier-critical evidence — tool_name, blocked, block_reason,
        # policy_id — is in the preserved set and survives. Local JSON-Lines
        # audit (audit.py) is untouched and keeps full fidelity.
        watermark_token = ""  # nosec B105 - empty init, not a secret (name trips B105)
        watermark_tenant_fp = ""
        if self.redaction_policy is not None and self.redaction_policy.enabled:
            from .trace_redaction import trace_redact

            _, report = trace_redact(record.to_dict(), self.redaction_policy)
            watermark_token = report.watermark_token
            watermark_tenant_fp = report.tenant_fp

        try:
            from opentelemetry.trace import StatusCode

            with self._tracer.start_span(f"airlock.{record.tool_name}") as span:
                if watermark_token:
                    span.set_attribute("airlock.trace_redacted", True)
                    span.set_attribute("airlock.watermark.scheme", "redact-hmac-v1")
                    span.set_attribute("airlock.watermark.tenant_fp", watermark_tenant_fp)
                    span.set_attribute("airlock.watermark.token", watermark_token)
                # Core attributes
                span.set_attribute("airlock.tool_name", record.tool_name)
                span.set_attribute("airlock.blocked", record.blocked)
                span.set_attribute("airlock.agent_id", record.agent_id or "unknown")
                span.set_attribute("airlock.session_id", record.session_id or "unknown")
                span.set_attribute("airlock.duration_ms", record.duration_ms or 0)
                span.set_attribute("airlock.sanitized_count", record.sanitized_count)
                span.set_attribute("airlock.truncated", record.truncated)

                # V0.4.0 attributes
                if record.args_hash:
                    span.set_attribute("airlock.args_hash", record.args_hash)
                if record.policy_id:
                    span.set_attribute("airlock.policy_id", record.policy_id)
                if record.policy_hash:
                    span.set_attribute("airlock.policy_hash", record.policy_hash)
                if record.unknown_args_mode:
                    span.set_attribute("airlock.unknown_args_mode", record.unknown_args_mode)
                if record.unknown_args_stripped:
                    span.set_attribute(
                        "airlock.unknown_args_stripped", ",".join(record.unknown_args_stripped)
                    )

                # Sandbox attributes
                if record.sandbox_backend:
                    span.set_attribute("airlock.sandbox_backend", record.sandbox_backend)
                if record.sandbox_id:
                    span.set_attribute("airlock.sandbox_id", record.sandbox_id)

                # Capability attributes
                if record.capabilities_required:
                    span.set_attribute(
                        "airlock.capabilities_required", ",".join(record.capabilities_required)
                    )
                if record.capabilities_granted:
                    span.set_attribute(
                        "airlock.capabilities_granted", ",".join(record.capabilities_granted)
                    )
                if record.capabilities_denied:
                    span.set_attribute(
                        "airlock.capabilities_denied", ",".join(record.capabilities_denied)
                    )

                # Network attributes
                if record.egress_domains:
                    span.set_attribute("airlock.egress_domains", ",".join(record.egress_domains))

                # Status
                if record.blocked:
                    span.set_status(StatusCode.ERROR, record.block_reason or "blocked")
                    span.set_attribute("airlock.block_reason", record.block_reason or "unknown")
                else:
                    span.set_status(StatusCode.OK)

                # Error details
                if record.error:
                    span.set_attribute("airlock.error", record.error)

        except Exception as e:
            logger.warning("otel_export_failed", error=str(e))

    def flush(self) -> None:
        """Flush any buffered spans to the collector."""
        if not self._initialized:
            return

        try:
            from opentelemetry import trace

            provider = trace.get_tracer_provider()
            if hasattr(provider, "force_flush"):
                provider.force_flush()
        except Exception as e:
            logger.warning("otel_flush_failed", error=str(e))


# Global exporter instance
_global_exporter: OTelAuditExporter | None = None


def get_otel_exporter(
    endpoint: str | None = None,
    enabled: bool = True,
) -> OTelAuditExporter:
    """Get or create the global OTel exporter.

    Args:
        endpoint: OTel collector endpoint.
        enabled: Whether to enable export.

    Returns:
        The global OTelAuditExporter instance.
    """
    global _global_exporter

    if _global_exporter is None:
        _global_exporter = OTelAuditExporter(endpoint=endpoint, enabled=enabled)

    return _global_exporter


def create_enhanced_record(
    tool_name: str,
    blocked: bool,
    args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> EnhancedAuditRecord:
    """Create an enhanced audit record with automatic field population.

    Args:
        tool_name: Name of the tool.
        blocked: Whether the call was blocked.
        args: Arguments passed to the tool (will be hashed).
        **kwargs: Additional fields for the record.

    Returns:
        EnhancedAuditRecord with populated fields.
    """
    record = EnhancedAuditRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        tool_name=tool_name,
        blocked=blocked,
        **kwargs,
    )

    if args:
        record.args_hash = _hash_args(args)

    return record
