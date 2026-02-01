"""Tests for audit_otel module (V0.4.0)."""

from __future__ import annotations

from datetime import datetime, timezone


from agent_airlock.audit_otel import (
    EnhancedAuditRecord,
    OTelAuditExporter,
    create_enhanced_record,
    get_otel_exporter,
)


class TestEnhancedAuditRecord:
    """Test the EnhancedAuditRecord dataclass."""

    def test_basic_creation(self) -> None:
        """Test creating a basic enhanced record."""
        record = EnhancedAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool_name="test_tool",
            blocked=False,
        )
        assert record.tool_name == "test_tool"
        assert record.blocked is False

    def test_with_args_hash(self) -> None:
        """Test record with args hash."""
        record = EnhancedAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool_name="test_tool",
            blocked=False,
            args_hash="abc123",
        )
        assert record.args_hash == "abc123"

    def test_with_capabilities(self) -> None:
        """Test record with capabilities."""
        record = EnhancedAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool_name="test_tool",
            blocked=False,
            capabilities_required=["FILESYSTEM_READ", "NETWORK_HTTPS"],
        )
        assert "FILESYSTEM_READ" in record.capabilities_required
        assert "NETWORK_HTTPS" in record.capabilities_required

    def test_with_egress_domains(self) -> None:
        """Test record with egress domains."""
        record = EnhancedAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool_name="test_tool",
            blocked=False,
            egress_domains=["api.example.com", "cdn.example.com"],
        )
        assert "api.example.com" in record.egress_domains

    def test_with_policy_id(self) -> None:
        """Test record with policy ID."""
        record = EnhancedAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool_name="test_tool",
            blocked=False,
            policy_id="strict-v1",
        )
        assert record.policy_id == "strict-v1"

    def test_with_session_id(self) -> None:
        """Test record with session ID."""
        record = EnhancedAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool_name="test_tool",
            blocked=False,
            session_id="sess-12345",
        )
        assert record.session_id == "sess-12345"

    def test_with_agent_id(self) -> None:
        """Test record with agent ID."""
        record = EnhancedAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool_name="test_tool",
            blocked=False,
            agent_id="agent-001",
        )
        assert record.agent_id == "agent-001"

    def test_blocked_record(self) -> None:
        """Test record with blocked status."""
        record = EnhancedAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool_name="test_tool",
            blocked=True,
            block_reason="POLICY_VIOLATION",
        )
        assert record.blocked is True
        assert record.block_reason == "POLICY_VIOLATION"

    def test_to_dict(self) -> None:
        """Test converting record to dictionary."""
        record = EnhancedAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool_name="test_tool",
            blocked=False,
            args_hash="sha256:abc",
        )
        data = record.to_dict()
        assert data["tool_name"] == "test_tool"
        assert data["blocked"] is False
        assert data["args_hash"] == "sha256:abc"


class TestOTelAuditExporter:
    """Test the OTelAuditExporter class."""

    def test_disabled_exporter(self) -> None:
        """Test exporter when disabled."""
        exporter = OTelAuditExporter(enabled=False)
        assert exporter.enabled is False

    def test_enabled_with_endpoint(self) -> None:
        """Test exporter can be enabled with endpoint."""
        exporter = OTelAuditExporter(enabled=True, endpoint="http://localhost:4317")
        assert exporter.enabled is True
        assert exporter.endpoint == "http://localhost:4317"

    def test_export_when_disabled(self) -> None:
        """Test export does nothing when disabled."""
        exporter = OTelAuditExporter(enabled=False)
        record = EnhancedAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool_name="test_tool",
            blocked=False,
        )
        # Should not raise
        exporter.export(record)

    def test_service_name_configuration(self) -> None:
        """Test service name can be configured."""
        exporter = OTelAuditExporter(enabled=True, service_name="my-agent-service")
        assert exporter.service_name == "my-agent-service"

    def test_default_service_name(self) -> None:
        """Test default service name."""
        exporter = OTelAuditExporter(enabled=True)
        assert exporter.service_name == "agent-airlock"


class TestCreateEnhancedRecord:
    """Test the create_enhanced_record factory function."""

    def test_basic_creation(self) -> None:
        """Test basic record creation."""
        record = create_enhanced_record(
            tool_name="my_tool",
            blocked=False,
        )
        assert record.tool_name == "my_tool"
        assert record.blocked is False
        assert record.timestamp is not None

    def test_with_args_for_hashing(self) -> None:
        """Test record creation with args for hashing."""
        record = create_enhanced_record(
            tool_name="my_tool",
            blocked=False,
            args={"key": "value"},
        )
        assert record.args_hash is not None

    def test_blocked_record(self) -> None:
        """Test creating a blocked record."""
        record = create_enhanced_record(
            tool_name="my_tool",
            blocked=True,
            block_reason="POLICY_VIOLATION",
        )
        assert record.blocked is True
        assert record.block_reason == "POLICY_VIOLATION"

    def test_with_capabilities(self) -> None:
        """Test record with capabilities list."""
        record = create_enhanced_record(
            tool_name="my_tool",
            blocked=False,
            capabilities_required=["FILESYSTEM_READ"],
        )
        assert "FILESYSTEM_READ" in record.capabilities_required

    def test_with_context(self) -> None:
        """Test record with context information."""
        record = create_enhanced_record(
            tool_name="my_tool",
            blocked=False,
            session_id="sess-123",
            agent_id="agent-456",
            policy_id="strict",
        )
        assert record.session_id == "sess-123"
        assert record.agent_id == "agent-456"
        assert record.policy_id == "strict"


class TestGetOTelExporter:
    """Test the get_otel_exporter function."""

    def test_returns_exporter(self) -> None:
        """Test that function returns an exporter."""
        # Reset global first
        import agent_airlock.audit_otel as module

        module._global_exporter = None

        exporter = get_otel_exporter()
        assert isinstance(exporter, OTelAuditExporter)

        # Reset for other tests
        module._global_exporter = None

    def test_returns_singleton(self) -> None:
        """Test that function returns singleton exporter."""
        import agent_airlock.audit_otel as module

        module._global_exporter = None

        exporter1 = get_otel_exporter()
        exporter2 = get_otel_exporter()
        assert exporter1 is exporter2

        module._global_exporter = None


class TestArgsHashing:
    """Test argument hashing functionality."""

    def test_same_args_same_hash(self) -> None:
        """Test that same args produce same hash."""
        args = {"key": "value", "num": 42}

        record1 = create_enhanced_record(
            tool_name="tool",
            blocked=False,
            args=args,
        )
        record2 = create_enhanced_record(
            tool_name="tool",
            blocked=False,
            args=args,
        )
        assert record1.args_hash == record2.args_hash

    def test_different_args_different_hash(self) -> None:
        """Test that different args produce different hash."""
        record1 = create_enhanced_record(
            tool_name="tool",
            blocked=False,
            args={"key": "value1"},
        )
        record2 = create_enhanced_record(
            tool_name="tool",
            blocked=False,
            args={"key": "value2"},
        )
        assert record1.args_hash != record2.args_hash


class TestOTelIntegration:
    """Test OTel integration scenarios."""

    def test_blocked_record_with_full_context(self) -> None:
        """Test blocked record with all context fields."""
        record = create_enhanced_record(
            tool_name="dangerous_tool",
            blocked=True,
            block_reason="CAPABILITY_DENIED",
            capabilities_required=["PROCESS_SHELL"],
            session_id="sess-blocked",
            agent_id="agent-test",
            policy_id="strict-v1",
        )
        assert record.blocked is True
        assert record.block_reason == "CAPABILITY_DENIED"
        assert "PROCESS_SHELL" in record.capabilities_required

    def test_success_record_with_egress(self) -> None:
        """Test success record with egress domains."""
        record = EnhancedAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            tool_name="fetch_data",
            blocked=False,
            egress_domains=["api.example.com"],
            capabilities_required=["NETWORK_HTTPS"],
        )
        assert "api.example.com" in record.egress_domains
