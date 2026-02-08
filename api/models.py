"""
API Models for AI-Powered Security Auditor.

Pydantic models and enums for request/response validation.
Aligned with the anti-hallucination framework's six-state assessment model.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# =============================================================================
# ENUMS
# =============================================================================

class AuditPhase(str, Enum):
    """Phases of the security audit workflow."""
    INITIALIZATION = "initialization"
    EVIDENCE_COLLECTION = "evidence_collection"
    VULNERABILITY_SCAN = "vulnerability_scan"
    CODE_ANALYSIS = "code_analysis"
    LOG_ANALYSIS = "log_analysis"
    COMPLIANCE_CHECK = "compliance_check"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    ERROR = "error"


class AuditStatus(str, Enum):
    """Overall audit status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssessmentStatus(str, Enum):
    """
    Six-state assessment model per anti-hallucination framework.
    
    These are the ONLY valid states for control assessments.
    Any other state violates the "If you can't prove it, you can't claim it" principle.
    """
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"


class Framework(str, Enum):
    """Supported compliance frameworks."""
    SOC2 = "SOC2"
    GDPR = "GDPR"
    HIPAA = "HIPAA"
    NIST = "NIST-800-53A"


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# =============================================================================
# REQUEST MODELS
# =============================================================================

class AuditRequest(BaseModel):
    """Request model for starting a new audit."""
    target_path: str = Field(..., description="Path to the target system or codebase")
    frameworks: List[str] = Field(
        default=["SOC2"],
        description="Compliance frameworks to assess against"
    )
    scan_types: List[str] = Field(
        default=["vulnerability", "code", "log", "compliance"],
        description="Types of scans to perform"
    )
    options: Dict[str, Any] = Field(
        default={},
        description="Additional scan options"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "target_path": "/app/src",
                "frameworks": ["SOC2", "NIST-800-53A"],
                "scan_types": ["vulnerability", "code", "compliance"],
                "options": {"severity_threshold": "medium"}
            }
        }


class ControlFilterRequest(BaseModel):
    """Request model for filtering controls."""
    status: Optional[AssessmentStatus] = None
    category: Optional[str] = None
    search: Optional[str] = None
    min_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)


# =============================================================================
# RESPONSE MODELS
# =============================================================================

class Finding(BaseModel):
    """Security finding from any agent."""
    id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Short description of the finding")
    severity: Severity = Field(..., description="Finding severity level")
    agent: str = Field(..., description="Agent that discovered this finding")
    control: str = Field(..., description="Related compliance control ID")
    cwe: Optional[str] = Field(None, description="CWE identifier if applicable")
    description: str = Field(default="", description="Detailed finding description")
    recommendation: str = Field(default="", description="Remediation recommendation")
    evidence_ids: List[str] = Field(default=[], description="Related evidence artifacts")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score")
    file_path: Optional[str] = Field(None, description="File path if code-related")
    line_number: Optional[int] = Field(None, description="Line number if code-related")
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "F001",
                "title": "SQL Injection Vulnerability",
                "severity": "critical",
                "agent": "code_analyzer",
                "control": "CC6.6",
                "cwe": "CWE-89",
                "description": "User input is directly concatenated into SQL query",
                "recommendation": "Use parameterized queries or prepared statements",
                "evidence_ids": ["EVD-001", "EVD-002"],
                "confidence": 0.95,
                "file_path": "src/database/queries.py",
                "line_number": 42
            }
        }


class ControlAssessment(BaseModel):
    """Assessment result for a single compliance control."""
    id: str = Field(..., description="Control identifier (e.g., CC6.1, Art.5, AC-2)")
    name: str = Field(..., description="Control name")
    category: str = Field(..., description="Control category or family")
    status: AssessmentStatus = Field(..., description="Assessment status (six-state model)")
    confidence: float = Field(
        default=0.0, 
        ge=0.0, 
        le=1.0, 
        description="Confidence score (0.0-1.0)"
    )
    evidence_count: int = Field(default=0, description="Number of evidence items collected")
    description: str = Field(default="", description="Control description")
    assessment_objectives: List[str] = Field(
        default=[], 
        description="Specific assessment objectives"
    )
    evidence_ids: List[str] = Field(default=[], description="Collected evidence artifact IDs")
    findings: List[str] = Field(default=[], description="Related finding IDs")
    last_assessed: Optional[datetime] = Field(None, description="Last assessment timestamp")
    assessor_notes: Optional[str] = Field(None, description="Notes from the assessment")
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "CC6.1",
                "name": "Logical Access Security",
                "category": "Common Criteria",
                "status": "PASS",
                "confidence": 0.87,
                "evidence_count": 5,
                "description": "The entity implements logical access security...",
                "evidence_ids": ["EVD-001", "EVD-003"],
                "findings": ["F002"]
            }
        }


class ControlsResponse(BaseModel):
    """Response model for control assessments endpoint."""
    framework: str = Field(..., description="Framework identifier")
    framework_name: str = Field(..., description="Human-readable framework name")
    description: str = Field(..., description="Framework description")
    controls: List[ControlAssessment] = Field(..., description="List of control assessments")
    total_count: int = Field(..., description="Total number of controls")
    assessed_count: int = Field(..., description="Number of assessed controls")
    pass_count: int = Field(..., description="Number of passing controls")
    fail_count: int = Field(..., description="Number of failing controls")


class AntiHallucinationMetrics(BaseModel):
    """Metrics from the anti-hallucination framework."""
    llm_overrides: int = Field(
        default=0, 
        description="Number of LLM assessments overridden (PASS→EVIDENCE_GAP)"
    )
    forbidden_words_detected: int = Field(
        default=0, 
        description="Number of 'weasel words' blocked"
    )
    evidence_citation_rate: float = Field(
        default=0.0, 
        ge=0.0, 
        le=1.0, 
        description="Percentage of claims with evidence citations"
    )
    average_confidence: float = Field(
        default=0.0, 
        ge=0.0, 
        le=1.0, 
        description="Average confidence across all assessments"
    )
    confidence_distribution: List[Dict[str, Any]] = Field(
        default=[], 
        description="Distribution of confidence scores"
    )


class AuditStatusResponse(BaseModel):
    """Response model for audit status endpoint."""
    audit_id: str = Field(..., description="Unique audit identifier")
    status: AuditStatus = Field(..., description="Current audit status")
    current_phase: AuditPhase = Field(..., description="Current processing phase")
    progress: float = Field(
        default=0.0, 
        ge=0.0, 
        le=1.0, 
        description="Overall progress (0.0-1.0)"
    )
    started_at: datetime = Field(..., description="Audit start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Audit completion timestamp")
    findings_count: Dict[str, int] = Field(
        default={}, 
        description="Findings count by severity"
    )
    evidence_count: int = Field(default=0, description="Total evidence collected")
    evidence_gaps: int = Field(default=0, description="Number of evidence gaps")
    anti_hallucination: AntiHallucinationMetrics = Field(
        default_factory=AntiHallucinationMetrics,
        description="Anti-hallucination framework metrics"
    )
    errors: List[str] = Field(default=[], description="Any errors encountered")
    
    class Config:
        json_schema_extra = {
            "example": {
                "audit_id": "AUDIT-20260122-143052",
                "status": "running",
                "current_phase": "code_analysis",
                "progress": 0.45,
                "started_at": "2026-01-22T14:30:52Z",
                "findings_count": {"critical": 1, "high": 3, "medium": 5, "low": 8},
                "evidence_count": 23,
                "evidence_gaps": 2,
                "anti_hallucination": {
                    "llm_overrides": 2,
                    "forbidden_words_detected": 1,
                    "evidence_citation_rate": 0.94,
                    "average_confidence": 0.85
                }
            }
        }


class AuditSummary(BaseModel):
    """Summary of a completed audit."""
    audit_id: str
    framework: str
    overall_status: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    controls_assessed: int
    controls_passed: int
    controls_failed: int
    controls_needs_review: int
    evidence_collected: int
    evidence_gaps: int
    started_at: datetime
    completed_at: datetime
    duration_seconds: float


class EvidenceGap(BaseModel):
    """An identified gap in evidence collection."""
    control: str = Field(..., description="Control ID with missing evidence")
    requirement: str = Field(..., description="Description of required evidence")
    priority: str = Field(..., description="Priority level (high/medium/low)")
    suggested_sources: List[str] = Field(
        default=[], 
        description="Suggested evidence sources"
    )


class AgentStatus(BaseModel):
    """Status of an individual agent."""
    name: str
    status: str  # running, completed, error, pending
    last_run: Optional[datetime] = None
    findings_count: int = 0
    evidence_count: int = 0
    error_message: Optional[str] = None
