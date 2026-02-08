"""
Comprehensive API Route Tests for AI Security Auditor.

Tests all 17 REST API endpoints plus WebSocket functionality.
Uses FastAPI TestClient for synchronous testing.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock
import asyncio

from fastapi.testclient import TestClient
from fastapi.websockets import WebSocket

# Import the FastAPI app and models
from api.routes import (
    app,
    audits,
    agents_state,
    findings_store,
    evidence_store,
    compliance_store,
    AuditStatus,
    AgentStatus,
    AgentType,
    Severity,
    AssessmentState,
    manager,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_state():
    """Reset in-memory state before each test."""
    audits.clear()
    agents_state.clear()
    findings_store.clear()
    evidence_store.clear()
    compliance_store.clear()
    yield
    # Cleanup after test
    audits.clear()
    agents_state.clear()
    findings_store.clear()
    evidence_store.clear()
    compliance_store.clear()


@pytest.fixture
def sample_audit_request():
    """Sample audit creation request."""
    return {
        "target": "https://example.com",
        "frameworks": ["SOC2", "HIPAA"],
        "agents": ["vulnerability_scanner", "code_analyzer"],
        "config": {"scan_depth": "full"}
    }


@pytest.fixture
def created_audit(client, sample_audit_request):
    """Create and return an audit for testing."""
    # Patch the background task to not actually run
    with patch('api.routes.run_audit_background', new_callable=AsyncMock):
        response = client.post("/api/audits", json=sample_audit_request)
        return response.json()


@pytest.fixture
def audit_with_findings(client, sample_audit_request):
    """Create an audit with pre-populated findings."""
    with patch('api.routes.run_audit_background', new_callable=AsyncMock):
        response = client.post("/api/audits", json=sample_audit_request)
        audit_data = response.json()
        audit_id = audit_data["audit_id"]
        
        # Add sample findings
        findings_store[audit_id] = [
            {
                "finding_id": "FND-001",
                "agent_type": "vulnerability_scanner",
                "severity": "critical",
                "title": "SQL Injection",
                "description": "SQL injection vulnerability detected",
                "evidence_ids": ["EVD-001"],
                "control_ids": ["CC6.1"],
                "remediation": "Use parameterized queries",
                "discovered_at": datetime.now(timezone.utc)
            },
            {
                "finding_id": "FND-002",
                "agent_type": "code_analyzer",
                "severity": "high",
                "title": "Hardcoded Credentials",
                "description": "Hardcoded password in config file",
                "evidence_ids": ["EVD-002"],
                "control_ids": ["CC6.2"],
                "remediation": "Use environment variables",
                "discovered_at": datetime.now(timezone.utc)
            },
            {
                "finding_id": "FND-003",
                "agent_type": "log_analyzer",
                "severity": "medium",
                "title": "Brute Force Attempt",
                "description": "Multiple failed login attempts detected",
                "evidence_ids": ["EVD-003"],
                "control_ids": ["CC6.8"],
                "remediation": "Implement rate limiting",
                "discovered_at": datetime.now(timezone.utc)
            }
        ]
        
        # Add sample evidence
        evidence_store[audit_id] = [
            {
                "evidence_id": "EVD-001",
                "evidence_type": "scan_result",
                "source": "OWASP ZAP",
                "summary": "Vulnerability scan output",
                "collected_at": datetime.now(timezone.utc),
                "content_hash": "sha256:abc123",
                "related_findings": ["FND-001"],
                "related_controls": ["CC6.1"]
            },
            {
                "evidence_id": "EVD-002",
                "evidence_type": "code_analysis",
                "source": "Static Analysis",
                "summary": "Code review output",
                "collected_at": datetime.now(timezone.utc),
                "content_hash": "sha256:def456",
                "related_findings": ["FND-002"],
                "related_controls": ["CC6.2"]
            },
            {
                "evidence_id": "EVD-003",
                "evidence_type": "log_analysis",
                "source": "Log Analyzer",
                "summary": "Authentication event analysis",
                "collected_at": datetime.now(timezone.utc),
                "content_hash": "sha256:ghi789",
                "related_findings": ["FND-003"],
                "related_controls": ["CC6.8"]
            }
        ]
        
        return audit_data


# =============================================================================
# Health & Status Endpoint Tests
# =============================================================================

class TestHealthEndpoints:
    """Tests for health and status endpoints."""
    
    def test_get_health_returns_healthy(self, client):
        """GET /api/health returns healthy status."""
        response = client.get("/api/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "components" in data
        assert "api" in data["components"]
        assert "database" in data["components"]
        assert "agents" in data["components"]
    
    def test_get_health_components_have_status(self, client):
        """Health endpoint includes component statuses."""
        response = client.get("/api/health")
        data = response.json()
        
        for component_name, component_data in data["components"].items():
            assert "status" in component_data, f"{component_name} missing status"
    
    def test_get_system_status(self, client):
        """GET /api/status returns system status."""
        response = client.get("/api/status")
        
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert "uptime_seconds" in data
        assert "active_audits" in data
        assert "total_audits" in data
        assert "timestamp" in data
    
    def test_system_status_counts_audits(self, client, sample_audit_request):
        """System status accurately counts audits."""
        # Create some audits
        with patch('api.routes.run_audit_background', new_callable=AsyncMock):
            client.post("/api/audits", json=sample_audit_request)
            client.post("/api/audits", json=sample_audit_request)
        
        response = client.get("/api/status")
        data = response.json()
        
        assert data["total_audits"] == 2


# =============================================================================
# Audit Management Endpoint Tests
# =============================================================================

class TestAuditEndpoints:
    """Tests for audit management endpoints."""
    
    def test_create_audit_success(self, client, sample_audit_request):
        """POST /api/audits creates a new audit."""
        with patch('api.routes.run_audit_background', new_callable=AsyncMock):
            response = client.post("/api/audits", json=sample_audit_request)
        
        assert response.status_code == 200
        data = response.json()
        assert "audit_id" in data
        assert data["target"] == sample_audit_request["target"]
        assert data["frameworks"] == sample_audit_request["frameworks"]
        assert data["status"] == "pending"
        assert data["progress"] == 0.0
    
    def test_create_audit_default_values(self, client):
        """POST /api/audits uses defaults when not specified."""
        minimal_request = {"target": "https://minimal.example.com"}
        
        with patch('api.routes.run_audit_background', new_callable=AsyncMock):
            response = client.post("/api/audits", json=minimal_request)
        
        assert response.status_code == 200
        data = response.json()
        assert data["frameworks"] == ["SOC2"]  # Default framework
    
    def test_create_audit_initializes_stores(self, client, sample_audit_request):
        """Creating an audit initializes related stores."""
        with patch('api.routes.run_audit_background', new_callable=AsyncMock):
            response = client.post("/api/audits", json=sample_audit_request)
        
        audit_id = response.json()["audit_id"]
        
        assert audit_id in findings_store
        assert audit_id in evidence_store
        assert audit_id in agents_state
    
    def test_list_audits_empty(self, client):
        """GET /api/audits returns empty list when no audits."""
        response = client.get("/api/audits")
        
        assert response.status_code == 200
        assert response.json() == []
    
    def test_list_audits_returns_all(self, client, sample_audit_request):
        """GET /api/audits returns all audits."""
        with patch('api.routes.run_audit_background', new_callable=AsyncMock):
            client.post("/api/audits", json=sample_audit_request)
            client.post("/api/audits", json=sample_audit_request)
            client.post("/api/audits", json=sample_audit_request)
        
        response = client.get("/api/audits")
        
        assert response.status_code == 200
        assert len(response.json()) == 3
    
    def test_list_audits_filter_by_status(self, client, sample_audit_request):
        """GET /api/audits filters by status."""
        with patch('api.routes.run_audit_background', new_callable=AsyncMock):
            response = client.post("/api/audits", json=sample_audit_request)
            audit_id = response.json()["audit_id"]
            
            # Manually update one audit's status
            audits[audit_id]["status"] = AuditStatus.COMPLETED
        
        response = client.get("/api/audits?status=completed")
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["status"] == "completed"
    
    def test_list_audits_pagination(self, client, sample_audit_request):
        """GET /api/audits supports pagination."""
        with patch('api.routes.run_audit_background', new_callable=AsyncMock):
            for _ in range(15):
                client.post("/api/audits", json=sample_audit_request)
        
        # Get first page
        response = client.get("/api/audits?limit=5&offset=0")
        assert len(response.json()) == 5
        
        # Get second page
        response = client.get("/api/audits?limit=5&offset=5")
        assert len(response.json()) == 5
        
        # Get third page
        response = client.get("/api/audits?limit=5&offset=10")
        assert len(response.json()) == 5
    
    def test_get_audit_success(self, client, created_audit):
        """GET /api/audits/{audit_id} returns audit details."""
        audit_id = created_audit["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["audit_id"] == audit_id
        assert data["target"] == created_audit["target"]
    
    def test_get_audit_not_found(self, client):
        """GET /api/audits/{audit_id} returns 404 for unknown ID."""
        response = client.get("/api/audits/nonexistent")
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
    
    def test_cancel_audit_success(self, client, created_audit):
        """POST /api/audits/{audit_id}/cancel cancels a running audit."""
        audit_id = created_audit["audit_id"]
        
        response = client.post(f"/api/audits/{audit_id}/cancel")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "cancelled"
        assert "cancelled" in data["message"].lower()
    
    def test_cancel_audit_not_found(self, client):
        """POST /api/audits/{audit_id}/cancel returns 404 for unknown ID."""
        response = client.post("/api/audits/nonexistent/cancel")
        
        assert response.status_code == 404
    
    def test_cancel_completed_audit_fails(self, client, created_audit):
        """Cannot cancel already completed audit."""
        audit_id = created_audit["audit_id"]
        
        # Mark as completed
        audits[audit_id]["status"] = AuditStatus.COMPLETED
        
        response = client.post(f"/api/audits/{audit_id}/cancel")
        
        assert response.status_code == 400
        assert "cannot cancel" in response.json()["detail"].lower()


# =============================================================================
# Agent Monitoring Endpoint Tests
# =============================================================================

class TestAgentEndpoints:
    """Tests for agent monitoring endpoints."""
    
    def test_get_agent_statuses(self, client, created_audit):
        """GET /api/audits/{audit_id}/agents returns agent statuses."""
        audit_id = created_audit["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}/agents")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        
        for agent in data:
            assert "agent_type" in agent
            assert "status" in agent
            assert "progress" in agent
    
    def test_get_agent_statuses_not_found(self, client):
        """GET /api/audits/{audit_id}/agents returns 404 for unknown audit."""
        response = client.get("/api/audits/nonexistent/agents")
        
        assert response.status_code == 404
    
    def test_get_specific_agent_status(self, client, created_audit):
        """GET /api/audits/{audit_id}/agents/{agent_type} returns specific agent."""
        audit_id = created_audit["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/agents/vulnerability_scanner"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["agent_type"] == "vulnerability_scanner"
        assert "status" in data
        assert "progress" in data
    
    def test_get_specific_agent_not_found(self, client, created_audit):
        """GET /api/audits/{audit_id}/agents/{agent_type} returns 404 for unknown agent."""
        audit_id = created_audit["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}/agents/log_analyzer")
        
        # log_analyzer wasn't in the original request
        assert response.status_code == 404


# =============================================================================
# Findings Endpoint Tests
# =============================================================================

class TestFindingsEndpoints:
    """Tests for findings endpoints."""
    
    def test_get_findings_empty(self, client, created_audit):
        """GET /api/audits/{audit_id}/findings returns empty when no findings."""
        audit_id = created_audit["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}/findings")
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["findings"] == []
    
    def test_get_findings_with_data(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/findings returns all findings."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}/findings")
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        assert len(data["findings"]) == 3
        assert "by_severity" in data
    
    def test_get_findings_filter_by_severity(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/findings filters by severity."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/findings?severity=critical"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["findings"][0]["severity"] == "critical"
    
    def test_get_findings_filter_by_agent(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/findings filters by agent."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/findings?agent=code_analyzer"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["findings"][0]["agent_type"] == "code_analyzer"
    
    def test_get_findings_pagination(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/findings supports pagination."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/findings?limit=2&offset=0"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3  # Total count
        assert len(data["findings"]) == 2  # Paginated count
    
    def test_get_findings_not_found(self, client):
        """GET /api/audits/{audit_id}/findings returns 404 for unknown audit."""
        response = client.get("/api/audits/nonexistent/findings")
        
        assert response.status_code == 404
    
    def test_get_specific_finding(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/findings/{finding_id} returns specific finding."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/findings/FND-001"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["finding_id"] == "FND-001"
        assert data["title"] == "SQL Injection"
    
    def test_get_specific_finding_not_found(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/findings/{finding_id} returns 404."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/findings/FND-999"
        )
        
        assert response.status_code == 404


# =============================================================================
# Compliance Endpoint Tests
# =============================================================================

class TestComplianceEndpoints:
    """Tests for compliance endpoints."""
    
    def test_get_compliance_status(self, client, created_audit):
        """GET /api/audits/{audit_id}/compliance returns compliance status."""
        audit_id = created_audit["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}/compliance")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        for status in data:
            assert "framework" in status
            assert "total_controls" in status
            assert "compliant" in status
            assert "compliance_percentage" in status
    
    def test_get_compliance_status_not_found(self, client):
        """GET /api/audits/{audit_id}/compliance returns 404 for unknown audit."""
        response = client.get("/api/audits/nonexistent/compliance")
        
        assert response.status_code == 404
    
    def test_get_control_assessments(self, client, created_audit):
        """GET /api/audits/{audit_id}/compliance/{framework}/controls returns controls."""
        audit_id = created_audit["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/compliance/SOC2/controls"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        
        for control in data:
            assert "control_id" in control
            assert "control_name" in control
            assert "framework" in control
            assert "state" in control
    
    def test_get_control_assessments_filter_by_state(self, client, created_audit):
        """GET /api/audits/{audit_id}/compliance/{framework}/controls filters by state."""
        audit_id = created_audit["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/compliance/SOC2/controls?state=compliant"
        )
        
        assert response.status_code == 200
        data = response.json()
        
        for control in data:
            assert control["state"] == "compliant"


# =============================================================================
# Evidence Endpoint Tests
# =============================================================================

class TestEvidenceEndpoints:
    """Tests for evidence endpoints."""
    
    def test_get_evidence_empty(self, client, created_audit):
        """GET /api/audits/{audit_id}/evidence returns empty when no evidence."""
        audit_id = created_audit["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}/evidence")
        
        assert response.status_code == 200
        assert response.json() == []
    
    def test_get_evidence_with_data(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/evidence returns all evidence."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}/evidence")
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        
        for evidence in data:
            assert "evidence_id" in evidence
            assert "evidence_type" in evidence
            assert "source" in evidence
            assert "content_hash" in evidence
    
    def test_get_evidence_filter_by_type(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/evidence filters by type."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/evidence?evidence_type=scan_result"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["evidence_type"] == "scan_result"
    
    def test_get_evidence_pagination(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/evidence supports pagination."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/evidence?limit=1&offset=0"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
    
    def test_get_evidence_not_found(self, client):
        """GET /api/audits/{audit_id}/evidence returns 404 for unknown audit."""
        response = client.get("/api/audits/nonexistent/evidence")
        
        assert response.status_code == 404
    
    def test_get_specific_evidence(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/evidence/{evidence_id} returns specific evidence."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/evidence/EVD-001"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["evidence_id"] == "EVD-001"
        assert data["source"] == "OWASP ZAP"
    
    def test_get_specific_evidence_not_found(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/evidence/{evidence_id} returns 404."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/evidence/EVD-999"
        )
        
        assert response.status_code == 404


# =============================================================================
# Dashboard Summary Endpoint Tests
# =============================================================================

class TestDashboardEndpoints:
    """Tests for dashboard summary endpoints."""
    
    def test_get_audit_summary(self, client, audit_with_findings):
        """GET /api/audits/{audit_id}/summary returns comprehensive summary."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}/summary")
        
        assert response.status_code == 200
        data = response.json()
        
        # Check structure
        assert data["audit_id"] == audit_id
        assert "status" in data
        assert "target" in data
        assert "progress" in data
        assert "duration_seconds" in data
        
        # Check findings summary
        assert "findings" in data
        assert "total" in data["findings"]
        assert "by_severity" in data["findings"]
        
        # Check evidence summary
        assert "evidence" in data
        assert "total" in data["evidence"]
        
        # Check agents summary
        assert "agents" in data
        assert isinstance(data["agents"], list)
        
        # Check compliance summary
        assert "compliance" in data
        assert "frameworks" in data["compliance"]
    
    def test_get_audit_summary_severity_counts(self, client, audit_with_findings):
        """Summary includes accurate severity breakdown."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}/summary")
        data = response.json()
        
        severity_counts = data["findings"]["by_severity"]
        assert severity_counts["critical"] == 1
        assert severity_counts["high"] == 1
        assert severity_counts["medium"] == 1
    
    def test_get_audit_summary_not_found(self, client):
        """GET /api/audits/{audit_id}/summary returns 404 for unknown audit."""
        response = client.get("/api/audits/nonexistent/summary")
        
        assert response.status_code == 404


# =============================================================================
# WebSocket Tests
# =============================================================================

class TestWebSocketEndpoints:
    """Tests for WebSocket endpoints."""
    
    def test_websocket_connection_success(self, client, created_audit):
        """WebSocket connection succeeds for existing audit."""
        audit_id = created_audit["audit_id"]
        
        with client.websocket_connect(f"/ws/audits/{audit_id}") as websocket:
            # Connection should be established
            assert websocket is not None
    
    def test_websocket_connection_not_found(self, client):
        """WebSocket connection fails for non-existent audit."""
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/audits/nonexistent") as websocket:
                pass
    
    def test_websocket_receive_message(self, client, created_audit):
        """WebSocket can receive messages from client."""
        audit_id = created_audit["audit_id"]
        
        with client.websocket_connect(f"/ws/audits/{audit_id}") as websocket:
            # Send a message
            websocket.send_text("ping")
            # Note: In this implementation, server doesn't respond to pings
            # This just verifies the connection stays open


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for API error handling."""
    
    def test_invalid_audit_id_format(self, client):
        """API handles malformed audit IDs gracefully."""
        response = client.get("/api/audits/!@#$%^&*()")
        
        # Should return 404, not 500
        assert response.status_code == 404
    
    def test_invalid_severity_parameter(self, client, audit_with_findings):
        """API handles invalid enum parameters."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(
            f"/api/audits/{audit_id}/findings?severity=invalid_severity"
        )
        
        # Should return 422 validation error
        assert response.status_code == 422
    
    def test_invalid_pagination_parameters(self, client):
        """API validates pagination parameters."""
        response = client.get("/api/audits?limit=-1")
        assert response.status_code == 422
        
        response = client.get("/api/audits?offset=-5")
        assert response.status_code == 422
    
    def test_missing_required_fields(self, client):
        """API validates required request fields."""
        # Missing 'target' field
        response = client.post("/api/audits", json={})
        
        assert response.status_code == 422


# =============================================================================
# Integration Tests
# =============================================================================

class TestAPIIntegration:
    """Integration tests combining multiple endpoints."""
    
    def test_full_audit_workflow(self, client, sample_audit_request):
        """Test complete audit lifecycle."""
        # 1. Create audit
        with patch('api.routes.run_audit_background', new_callable=AsyncMock):
            create_response = client.post("/api/audits", json=sample_audit_request)
        assert create_response.status_code == 200
        audit_id = create_response.json()["audit_id"]
        
        # 2. Check audit status
        status_response = client.get(f"/api/audits/{audit_id}")
        assert status_response.status_code == 200
        
        # 3. Check agents
        agents_response = client.get(f"/api/audits/{audit_id}/agents")
        assert agents_response.status_code == 200
        
        # 4. Get summary
        summary_response = client.get(f"/api/audits/{audit_id}/summary")
        assert summary_response.status_code == 200
        
        # 5. Cancel audit
        cancel_response = client.post(f"/api/audits/{audit_id}/cancel")
        assert cancel_response.status_code == 200
        assert cancel_response.json()["status"] == "cancelled"
    
    def test_findings_evidence_relationship(self, client, audit_with_findings):
        """Test that findings reference valid evidence."""
        audit_id = audit_with_findings["audit_id"]
        
        # Get findings
        findings_response = client.get(f"/api/audits/{audit_id}/findings")
        findings = findings_response.json()["findings"]
        
        # Get evidence
        evidence_response = client.get(f"/api/audits/{audit_id}/evidence")
        evidence_list = evidence_response.json()
        evidence_ids = {e["evidence_id"] for e in evidence_list}
        
        # Verify findings reference valid evidence
        for finding in findings:
            for eid in finding["evidence_ids"]:
                assert eid in evidence_ids, f"Finding references unknown evidence: {eid}"
    
    def test_multiple_audits_isolation(self, client, sample_audit_request):
        """Test that multiple audits have isolated data."""
        with patch('api.routes.run_audit_background', new_callable=AsyncMock):
            # Create two audits
            response1 = client.post("/api/audits", json=sample_audit_request)
            audit_id_1 = response1.json()["audit_id"]
            
            response2 = client.post("/api/audits", json=sample_audit_request)
            audit_id_2 = response2.json()["audit_id"]
        
        # Add findings to audit 1 only
        findings_store[audit_id_1].append({
            "finding_id": "FND-001",
            "agent_type": "vulnerability_scanner",
            "severity": "high",
            "title": "Test Finding",
            "description": "Test",
            "evidence_ids": [],
            "control_ids": [],
            "remediation": "Test",
            "discovered_at": datetime.now(timezone.utc)
        })
        
        # Verify isolation
        response1 = client.get(f"/api/audits/{audit_id_1}/findings")
        assert response1.json()["total"] == 1
        
        response2 = client.get(f"/api/audits/{audit_id_2}/findings")
        assert response2.json()["total"] == 0


# =============================================================================
# Concurrent Request Tests
# =============================================================================

class TestConcurrentRequests:
    """Tests for handling concurrent requests."""
    
    def test_concurrent_audit_creation(self, client, sample_audit_request):
        """Test creating multiple audits concurrently."""
        import concurrent.futures
        
        with patch('api.routes.run_audit_background', new_callable=AsyncMock):
            def create_audit():
                return client.post("/api/audits", json=sample_audit_request)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(create_audit) for _ in range(10)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        # All should succeed
        assert all(r.status_code == 200 for r in results)
        
        # All should have unique IDs
        audit_ids = {r.json()["audit_id"] for r in results}
        assert len(audit_ids) == 10


# =============================================================================
# Response Format Tests
# =============================================================================

class TestResponseFormats:
    """Tests for API response formats and schemas."""
    
    def test_audit_response_datetime_format(self, client, created_audit):
        """Verify datetime fields are properly formatted."""
        audit_id = created_audit["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}")
        data = response.json()
        
        # Should be ISO 8601 format
        assert "T" in data["created_at"]
        assert "T" in data["updated_at"]
    
    def test_findings_response_structure(self, client, audit_with_findings):
        """Verify findings response matches expected schema."""
        audit_id = audit_with_findings["audit_id"]
        
        response = client.get(f"/api/audits/{audit_id}/findings")
        data = response.json()
        
        assert "total" in data
        assert "findings" in data
        assert "by_severity" in data
        assert isinstance(data["total"], int)
        assert isinstance(data["findings"], list)
        assert isinstance(data["by_severity"], dict)
    
    def test_health_response_structure(self, client):
        """Verify health response matches expected schema."""
        response = client.get("/api/health")
        data = response.json()
        
        assert "status" in data
        assert "timestamp" in data
        assert "components" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
