"""Observability hooks for Agent-Airlock.

Provides integration with OpenTelemetry for distributed tracing and metrics.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.observability")


@dataclass
class SpanContext:
    """Context for an observability span."""

    name: str
    tool_name: str
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    status: str = "ok"
    error: str | None = None

    def set_attribute(self, key: str, value: Any) -> None:
        """Set a span attribute."""
        self.attributes[key] = value

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        """Add an event to the span."""
        self.events.append(
            {
                "name": name,
                "timestamp": time.time(),
                "attributes": attributes or {},
            }
        )

    def set_error(self, error: Exception) -> None:
        """Set error status on span."""
        self.status = "error"
        self.error = str(error)

    def finish(self) -> None:
        """Mark span as finished."""
        self.end_time = time.time()

    @property
    def duration_ms(self) -> float:
        """Get span duration in milliseconds."""
        end = self.end_time or time.time()
        return (end - self.start_time) * 1000


class ObservabilityProvider(ABC):
    """Abstract base class for observability providers."""

    @abstractmethod
    def start_span(self, name: str, tool_name: str) -> SpanContext:
        """Start a new span."""
        ...

    @abstractmethod
    def end_span(self, span: SpanContext) -> None:
        """End a span and export it."""
        ...

    @abstractmethod
    def record_metric(
        self,
        name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a metric value."""
        ...

    @abstractmethod
    def track_event(
        self,
        event_name: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Track an analytics event."""
        ...


class NoOpProvider(ObservabilityProvider):
    """No-op provider when no observability is configured."""

    def start_span(self, name: str, tool_name: str) -> SpanContext:
        return SpanContext(name=name, tool_name=tool_name)

    def end_span(self, span: SpanContext) -> None:
        span.finish()

    def record_metric(
        self,
        name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        pass

    def track_event(
        self,
        event_name: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        pass


class OpenTelemetryProvider(ObservabilityProvider):
    """OpenTelemetry integration for distributed tracing.

    Usage:
        from agent_airlock.observability import configure, OpenTelemetryProvider

        # Configure with OTEL
        configure(OpenTelemetryProvider(service_name="my-service"))

        # Use observability
        with observe("my_operation", tool_name="my_tool") as span:
            span.set_attribute("key", "value")
            do_work()
    """

    def __init__(
        self,
        service_name: str = "agent-airlock",
        endpoint: str | None = None,
    ) -> None:
        """Initialize OpenTelemetry provider.

        Args:
            service_name: Name of the service for tracing.
            endpoint: OTLP endpoint (uses OTEL_EXPORTER_OTLP_ENDPOINT env var if not set).
        """
        self.service_name = service_name
        self.endpoint = endpoint
        self._tracer: Any = None
        self._meter: Any = None
        self._initialized = False

    def _ensure_initialized(self) -> None:
        """Lazy initialization of OpenTelemetry."""
        if self._initialized:
            return

        try:
            from opentelemetry import metrics, trace
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.trace import TracerProvider

            # Set up tracer
            if not trace.get_tracer_provider():
                trace.set_tracer_provider(TracerProvider())

            self._tracer = trace.get_tracer(self.service_name)

            # Set up meter
            if not metrics.get_meter_provider():
                metrics.set_meter_provider(MeterProvider())

            self._meter = metrics.get_meter(self.service_name)
            self._initialized = True

            logger.info("otel_initialized", service=self.service_name)

        except ImportError:
            logger.warning(
                "opentelemetry_not_installed",
                hint="Install with: pip install opentelemetry-api opentelemetry-sdk",
            )
            self._tracer = None
            self._meter = None
            self._initialized = True

    def start_span(self, name: str, tool_name: str) -> SpanContext:
        self._ensure_initialized()
        span = SpanContext(name=name, tool_name=tool_name)

        if self._tracer:
            try:
                otel_span = self._tracer.start_span(name)
                otel_span.set_attribute("tool.name", tool_name)
                otel_span.set_attribute("airlock.version", "0.4.0")
                span.attributes["_otel_span"] = otel_span
            except Exception:
                logger.exception("otel_start_span_error")

        return span

    def end_span(self, span: SpanContext) -> None:
        span.finish()

        otel_span = span.attributes.pop("_otel_span", None)
        if otel_span:
            try:
                from opentelemetry.trace import StatusCode

                for key, value in span.attributes.items():
                    if not key.startswith("_"):
                        otel_span.set_attribute(key, value)

                for event in span.events:
                    otel_span.add_event(event["name"], event.get("attributes", {}))

                if span.status == "error":
                    otel_span.set_status(StatusCode.ERROR, span.error)
                else:
                    otel_span.set_status(StatusCode.OK)

                otel_span.end()
            except Exception:
                logger.exception("otel_end_span_error")

    def record_metric(
        self,
        name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        self._ensure_initialized()

        if self._meter:
            try:
                # Create a gauge for the metric
                gauge = self._meter.create_gauge(
                    name,
                    description=f"Airlock metric: {name}",
                )
                gauge.set(value, tags or {})
            except Exception:
                logger.exception("otel_metric_error", metric=name)

    def track_event(
        self,
        event_name: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Track event as a log entry with OTEL."""
        logger.info(
            "otel_event",
            event=event_name,
            properties=properties,
        )


# Global observability instance
_provider: ObservabilityProvider = NoOpProvider()


def configure(provider: ObservabilityProvider) -> None:
    """Configure the global observability provider.

    Args:
        provider: The provider to use globally.

    Example:
        from agent_airlock.observability import configure, OpenTelemetryProvider

        configure(OpenTelemetryProvider(service_name="my-agent"))
    """
    global _provider
    _provider = provider
    logger.info("observability_configured", provider=type(provider).__name__)


def get_provider() -> ObservabilityProvider:
    """Get the current observability provider."""
    return _provider


def start_span(name: str, tool_name: str) -> SpanContext:
    """Start a new span using the global provider."""
    return _provider.start_span(name, tool_name)


def end_span(span: SpanContext) -> None:
    """End a span using the global provider."""
    _provider.end_span(span)


def record_metric(
    name: str,
    value: float,
    tags: dict[str, str] | None = None,
) -> None:
    """Record a metric using the global provider."""
    _provider.record_metric(name, value, tags)


def track_event(
    event_name: str,
    properties: dict[str, Any] | None = None,
) -> None:
    """Track an event using the global provider."""
    _provider.track_event(event_name, properties)


def _reset_provider() -> None:
    """Reset the global observability provider for testing.

    This function should only be used in tests to ensure isolation
    between test cases. Resets to no-op provider.
    """
    global _provider
    _provider = NoOpProvider()


class observe:
    """Context manager and decorator for observability.

    Usage:
        # As decorator
        @observe("my_operation")
        def my_tool():
            ...

        # As context manager
        with observe("my_operation", tool_name="my_tool") as span:
            span.set_attribute("key", "value")
            ...
    """

    def __init__(
        self,
        name: str,
        tool_name: str = "unknown",
        record_args: bool = False,
    ) -> None:
        self.name = name
        self.tool_name = tool_name
        self.record_args = record_args
        self._span: SpanContext | None = None

    def __enter__(self) -> SpanContext:
        self._span = start_span(self.name, self.tool_name)
        return self._span

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> bool:
        if self._span:
            if exc_val is not None and isinstance(exc_val, Exception):
                self._span.set_error(exc_val)
            end_span(self._span)
        return False

    def __call__(self, func: Callable[..., Any]) -> Callable[..., Any]:
        import functools

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with observe(
                self.name or func.__name__,
                tool_name=func.__name__,
            ) as span:
                if self.record_args:
                    span.set_attribute("args_count", len(args))
                    span.set_attribute("kwargs_keys", list(kwargs.keys()))
                return func(*args, **kwargs)

        return wrapper
