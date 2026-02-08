"""
AI-Powered Security Auditor API Package.

FastAPI application with WebSocket support for real-time audit monitoring.
Supports multi-framework compliance assessments (SOC 2, GDPR, HIPAA, NIST 800-53A).
"""

from .routes import app
from .models import (
    # Enums
    AuditPhase,
    AuditStatus,
    AssessmentStatus,
    Framework,
    Severity,
    # Request Models
    AuditRequest,
    ControlFilterRequest,
    # Response Models
    AuditStatusResponse,
    AuditSummary,
    Finding,
    ControlAssessment,
    ControlsResponse,
    AntiHallucinationMetrics,
    EvidenceGap,
    AgentStatus,
)

__all__ = [
    # FastAPI app
    "app",
    # Enums
    "AuditPhase",
    "AuditStatus",
    "AssessmentStatus",
    "Framework",
    "Severity",
    # Request Models
    "AuditRequest",
    "ControlFilterRequest",
    # Response Models
    "AuditStatusResponse",
    "AuditSummary",
    "Finding",
    "ControlAssessment",
    "ControlsResponse",
    "AntiHallucinationMetrics",
    "EvidenceGap",
    "AgentStatus",
]

__version__ = "1.0.0"
