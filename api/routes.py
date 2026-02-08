"""
API Routes for Security Auditor Dashboard

FastAPI endpoints for control assessments, audit status, and real-time updates.
Supports multi-framework compliance assessments (SOC 2, GDPR, HIPAA, NIST 800-53A).

Usage:
    uvicorn api.routes:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import asyncio
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# ENUMS AND MODELS
# =============================================================================

class AssessmentStatus(str, Enum):
    """Six-state assessment model per anti-hallucination framework."""
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


# Pydantic Models
class ControlAssessment(BaseModel):
    """Assessment result for a single control."""
    id: str
    name: str
    category: str
    status: AssessmentStatus
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_count: int = 0
    description: str = ""
    assessment_objectives: List[str] = []
    evidence_ids: List[str] = []
    findings: List[str] = []
    last_assessed: Optional[datetime] = None


class ControlsResponse(BaseModel):
    """Response model for control assessments endpoint."""
    framework: str
    framework_name: str
    description: str
    controls: List[ControlAssessment]
    total_count: int
    assessed_count: int
    pass_count: int
    fail_count: int


class AuditRequest(BaseModel):
    """Request model for starting an audit."""
    target_path: str
    frameworks: List[str] = ["SOC2"]
    scan_types: List[str] = ["vulnerability", "code", "log", "compliance"]
    options: Dict[str, Any] = {}


class AuditStatusResponse(BaseModel):
    """Response model for audit status."""
    audit_id: str
    status: str
    current_phase: str
    progress: float
    started_at: str
    completed_at: Optional[str] = None
    findings_count: Dict[str, int]
    evidence_count: int
    evidence_gaps: int
    anti_hallucination: Dict[str, Any]


class Finding(BaseModel):
    """Security finding model."""
    id: str
    title: str
    severity: Severity
    agent: str
    control: str
    cwe: Optional[str] = None
    description: str = ""
    recommendation: str = ""
    evidence_ids: List[str] = []
    confidence: float = 0.0


# =============================================================================
# FRAMEWORK DATA DEFINITIONS
# =============================================================================

FRAMEWORK_CONTROLS: Dict[str, Dict] = {
    Framework.SOC2.value: {
        "name": "SOC 2 Type II",
        "description": "Trust Service Criteria for Service Organizations",
        "controls": [
            {"id": "CC6.1", "name": "Logical Access Security", "category": "Common Criteria", "status": "FAIL", "confidence": 0.85, "evidence_count": 0, "description": "The entity implements logical access security software, infrastructure, and architectures over protected information assets."},
            {"id": "CC6.2", "name": "User Registration", "category": "Common Criteria", "status": "PASS", "confidence": 0.85, "evidence_count": 0, "description": "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users."},
            {"id": "CC6.3", "name": "User Access Removal", "category": "Common Criteria", "status": "PASS", "confidence": 0.85, "evidence_count": 0, "description": "The entity removes access to protected information assets when appropriate."},
            {"id": "CC6.6", "name": "External Threat Protection", "category": "Common Criteria", "status": "FAIL", "confidence": 0.85, "evidence_count": 0, "description": "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software."},
            {"id": "CC6.7", "name": "Information Transmission", "category": "Common Criteria", "status": "NEEDS_MANUAL_REVIEW", "confidence": 0.85, "evidence_count": 0, "description": "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes."},
            {"id": "CC7.1", "name": "Security Event Detection", "category": "Common Criteria", "status": "FAIL", "confidence": 0.85, "evidence_count": 0, "description": "To meet its objectives, the entity uses detection and monitoring procedures to identify anomalies that could indicate attacks."},
            {"id": "CC7.2", "name": "System Monitoring", "category": "Common Criteria", "status": "PASS", "confidence": 0.85, "evidence_count": 0, "description": "The entity monitors system components and the operation of those components for anomalies."},
            {"id": "CC7.3", "name": "Security Event Evaluation", "category": "Common Criteria", "status": "NEEDS_MANUAL_REVIEW", "confidence": 0.85, "evidence_count": 0, "description": "The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives."},
            {"id": "CC8.1", "name": "Change Management", "category": "Common Criteria", "status": "PASS", "confidence": 0.85, "evidence_count": 0, "description": "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures."},
            {"id": "CC9.1", "name": "Risk Assessment", "category": "Common Criteria", "status": "PASS", "confidence": 0.85, "evidence_count": 0, "description": "The entity identifies and assesses risk that could affect the achievement of its objectives."},
            {"id": "A1.1", "name": "Availability Commitments", "category": "Availability", "status": "PASS", "confidence": 0.85, "evidence_count": 0, "description": "The entity maintains, monitors, and evaluates current processing capacity and use of system components."},
            {"id": "C1.1", "name": "Confidentiality Commitments", "category": "Confidentiality", "status": "PASS", "confidence": 0.85, "evidence_count": 0, "description": "The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality."},
        ]
    },
    Framework.GDPR.value: {
        "name": "GDPR",
        "description": "General Data Protection Regulation (EU)",
        "controls": [
            {"id": "Art.5", "name": "Principles of Processing", "category": "Core Principles", "status": "PASS", "confidence": 0.82, "evidence_count": 0, "description": "Personal data shall be processed lawfully, fairly and in a transparent manner."},
            {"id": "Art.6", "name": "Lawfulness of Processing", "category": "Core Principles", "status": "PASS", "confidence": 0.88, "evidence_count": 0, "description": "Processing shall be lawful only if and to the extent that at least one legal basis applies."},
            {"id": "Art.7", "name": "Conditions for Consent", "category": "Consent", "status": "NEEDS_MANUAL_REVIEW", "confidence": 0.75, "evidence_count": 0, "description": "Where processing is based on consent, the controller shall be able to demonstrate that the data subject has consented."},
            {"id": "Art.12", "name": "Transparent Information", "category": "Data Subject Rights", "status": "PASS", "confidence": 0.90, "evidence_count": 0, "description": "The controller shall take appropriate measures to provide information in a concise, transparent, intelligible and easily accessible form."},
            {"id": "Art.13", "name": "Information at Collection", "category": "Data Subject Rights", "status": "PASS", "confidence": 0.87, "evidence_count": 0, "description": "Where personal data are collected from the data subject, the controller shall provide specified information."},
            {"id": "Art.15", "name": "Right of Access", "category": "Data Subject Rights", "status": "PASS", "confidence": 0.85, "evidence_count": 0, "description": "The data subject shall have the right to obtain confirmation as to whether personal data concerning them is being processed."},
            {"id": "Art.17", "name": "Right to Erasure", "category": "Data Subject Rights", "status": "NEEDS_MANUAL_REVIEW", "confidence": 0.72, "evidence_count": 0, "description": "The data subject shall have the right to obtain erasure of personal data (right to be forgotten)."},
            {"id": "Art.25", "name": "Data Protection by Design", "category": "Technical Measures", "status": "FAIL", "confidence": 0.68, "evidence_count": 0, "description": "The controller shall implement appropriate technical and organisational measures designed to implement data-protection principles."},
            {"id": "Art.30", "name": "Records of Processing", "category": "Documentation", "status": "PASS", "confidence": 0.91, "evidence_count": 0, "description": "Each controller shall maintain a record of processing activities under its responsibility."},
            {"id": "Art.32", "name": "Security of Processing", "category": "Technical Measures", "status": "FAIL", "confidence": 0.65, "evidence_count": 0, "description": "The controller and processor shall implement appropriate technical and organisational measures to ensure security."},
            {"id": "Art.33", "name": "Breach Notification", "category": "Incident Response", "status": "NEEDS_MANUAL_REVIEW", "confidence": 0.78, "evidence_count": 0, "description": "In case of a personal data breach, the controller shall notify the supervisory authority within 72 hours."},
            {"id": "Art.35", "name": "Data Protection Impact Assessment", "category": "Risk Assessment", "status": "EVIDENCE_GAP", "confidence": 0.55, "evidence_count": 0, "description": "Where processing is likely to result in high risk, the controller shall carry out an assessment of the impact."},
        ]
    },
    Framework.HIPAA.value: {
        "name": "HIPAA Security Rule",
        "description": "Health Insurance Portability and Accountability Act",
        "controls": [
            {"id": "§164.308(a)(1)", "name": "Security Management Process", "category": "Administrative Safeguards", "status": "PASS", "confidence": 0.86, "evidence_count": 0, "description": "Implement policies and procedures to prevent, detect, contain, and correct security violations."},
            {"id": "§164.308(a)(3)", "name": "Workforce Security", "category": "Administrative Safeguards", "status": "PASS", "confidence": 0.84, "evidence_count": 0, "description": "Implement policies and procedures to ensure appropriate access to ePHI by workforce members."},
            {"id": "§164.308(a)(4)", "name": "Information Access Management", "category": "Administrative Safeguards", "status": "NEEDS_MANUAL_REVIEW", "confidence": 0.76, "evidence_count": 0, "description": "Implement policies and procedures for authorizing access to ePHI consistent with applicable requirements."},
            {"id": "§164.308(a)(5)", "name": "Security Awareness Training", "category": "Administrative Safeguards", "status": "PASS", "confidence": 0.89, "evidence_count": 0, "description": "Implement a security awareness and training program for all workforce members."},
            {"id": "§164.308(a)(6)", "name": "Security Incident Procedures", "category": "Administrative Safeguards", "status": "FAIL", "confidence": 0.62, "evidence_count": 0, "description": "Implement policies and procedures to address security incidents."},
            {"id": "§164.308(a)(7)", "name": "Contingency Plan", "category": "Administrative Safeguards", "status": "NEEDS_MANUAL_REVIEW", "confidence": 0.71, "evidence_count": 0, "description": "Establish policies and procedures for responding to an emergency or other occurrence."},
            {"id": "§164.310(a)(1)", "name": "Facility Access Controls", "category": "Physical Safeguards", "status": "PASS", "confidence": 0.88, "evidence_count": 0, "description": "Implement policies and procedures to limit physical access to electronic information systems."},
            {"id": "§164.310(b)", "name": "Workstation Use", "category": "Physical Safeguards", "status": "PASS", "confidence": 0.85, "evidence_count": 0, "description": "Implement policies and procedures that specify proper functions and physical attributes of workstations."},
            {"id": "§164.310(d)(1)", "name": "Device and Media Controls", "category": "Physical Safeguards", "status": "EVIDENCE_GAP", "confidence": 0.58, "evidence_count": 0, "description": "Implement policies and procedures that govern the receipt and removal of hardware and electronic media."},
            {"id": "§164.312(a)(1)", "name": "Access Control", "category": "Technical Safeguards", "status": "FAIL", "confidence": 0.67, "evidence_count": 0, "description": "Implement technical policies and procedures for electronic information systems that maintain ePHI."},
            {"id": "§164.312(b)", "name": "Audit Controls", "category": "Technical Safeguards", "status": "PASS", "confidence": 0.83, "evidence_count": 0, "description": "Implement hardware, software, and procedural mechanisms that record and examine activity."},
            {"id": "§164.312(c)(1)", "name": "Integrity Controls", "category": "Technical Safeguards", "status": "PASS", "confidence": 0.87, "evidence_count": 0, "description": "Implement policies and procedures to protect ePHI from improper alteration or destruction."},
            {"id": "§164.312(d)", "name": "Authentication", "category": "Technical Safeguards", "status": "PASS", "confidence": 0.90, "evidence_count": 0, "description": "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed."},
            {"id": "§164.312(e)(1)", "name": "Transmission Security", "category": "Technical Safeguards", "status": "FAIL", "confidence": 0.64, "evidence_count": 0, "description": "Implement technical security measures to guard against unauthorized access to ePHI being transmitted."},
        ]
    },
    Framework.NIST.value: {
        "name": "NIST 800-53A",
        "description": "Security and Privacy Controls Assessment",
        "controls": [
            {"id": "AC-1", "name": "Policy and Procedures", "category": "Access Control", "status": "PASS", "confidence": 0.88, "evidence_count": 0, "description": "Develop and document access control policy and procedures."},
            {"id": "AC-2", "name": "Account Management", "category": "Access Control", "status": "PASS", "confidence": 0.85, "evidence_count": 0, "description": "Define and document account types and establish conditions for membership."},
            {"id": "AC-3", "name": "Access Enforcement", "category": "Access Control", "status": "FAIL", "confidence": 0.72, "evidence_count": 0, "description": "Enforce approved authorizations for logical access to information and system resources."},
            {"id": "AC-6", "name": "Least Privilege", "category": "Access Control", "status": "NEEDS_MANUAL_REVIEW", "confidence": 0.78, "evidence_count": 0, "description": "Employ the principle of least privilege, allowing only authorized access."},
            {"id": "AU-2", "name": "Event Logging", "category": "Audit and Accountability", "status": "PASS", "confidence": 0.91, "evidence_count": 0, "description": "Identify events that the system is capable of logging in support of the audit function."},
            {"id": "AU-3", "name": "Content of Audit Records", "category": "Audit and Accountability", "status": "PASS", "confidence": 0.89, "evidence_count": 0, "description": "Ensure that audit records contain information that establishes what event occurred."},
            {"id": "AU-6", "name": "Audit Record Review", "category": "Audit and Accountability", "status": "NEEDS_MANUAL_REVIEW", "confidence": 0.74, "evidence_count": 0, "description": "Review and analyze system audit records for indications of inappropriate activity."},
            {"id": "AU-12", "name": "Audit Record Generation", "category": "Audit and Accountability", "status": "PASS", "confidence": 0.87, "evidence_count": 0, "description": "Provide audit record generation capability for auditable events."},
            {"id": "RA-5", "name": "Vulnerability Monitoring", "category": "Risk Assessment", "status": "FAIL", "confidence": 0.65, "evidence_count": 0, "description": "Monitor and scan for vulnerabilities in the system and applications."},
            {"id": "SI-2", "name": "Flaw Remediation", "category": "System and Information Integrity", "status": "FAIL", "confidence": 0.68, "evidence_count": 0, "description": "Identify, report, and correct system flaws in a timely manner."},
            {"id": "SI-3", "name": "Malicious Code Protection", "category": "System and Information Integrity", "status": "PASS", "confidence": 0.86, "evidence_count": 0, "description": "Implement malicious code protection mechanisms at system entry and exit points."},
            {"id": "SI-4", "name": "System Monitoring", "category": "System and Information Integrity", "status": "NEEDS_MANUAL_REVIEW", "confidence": 0.76, "evidence_count": 0, "description": "Monitor the system to detect attacks and indicators of potential attacks."},
            {"id": "SC-7", "name": "Boundary Protection", "category": "System and Communications Protection", "status": "PASS", "confidence": 0.84, "evidence_count": 0, "description": "Monitor and control communications at the external managed interfaces."},
            {"id": "SC-8", "name": "Transmission Confidentiality", "category": "System and Communications Protection", "status": "PASS", "confidence": 0.88, "evidence_count": 0, "description": "Protect the confidentiality and integrity of transmitted information."},
        ]
    }
}


# =============================================================================
# APPLICATION SETUP
# =============================================================================

app = FastAPI(
    title="AI-Powered Security Auditor API",
    description="REST API for compliance control assessments across multiple frameworks",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",      # React dev server
        "http://localhost:5173",      # Vite dev server
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory state (replace with proper database in production)
_active_audits: Dict[str, Dict] = {}
_connected_websockets: Dict[str, List[WebSocket]] = {}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_framework_data(framework: str) -> Dict:
    """Get framework control data, with fallback handling."""
    # Handle both enum values and string keys
    if framework in FRAMEWORK_CONTROLS:
        return FRAMEWORK_CONTROLS[framework]
    
    # Try to match framework name variations
    framework_upper = framework.upper()
    for key, value in FRAMEWORK_CONTROLS.items():
        if key.upper() == framework_upper or key.replace("-", "").upper() == framework_upper.replace("-", ""):
            return value
    
    raise HTTPException(status_code=404, detail=f"Framework not found: {framework}")


def calculate_statistics(controls: List[Dict]) -> Dict[str, int]:
    """Calculate assessment statistics from controls list."""
    stats = {
        "total": len(controls),
        "assessed": 0,
        "pass": 0,
        "fail": 0,
        "needs_review": 0,
        "evidence_gap": 0,
        "insufficient": 0,
        "conflicting": 0,
    }
    
    for control in controls:
        status = control.get("status", "")
        if status:
            stats["assessed"] += 1
        if status == AssessmentStatus.PASS.value:
            stats["pass"] += 1
        elif status == AssessmentStatus.FAIL.value:
            stats["fail"] += 1
        elif status == AssessmentStatus.NEEDS_MANUAL_REVIEW.value:
            stats["needs_review"] += 1
        elif status == AssessmentStatus.EVIDENCE_GAP.value:
            stats["evidence_gap"] += 1
        elif status == AssessmentStatus.INSUFFICIENT_EVIDENCE.value:
            stats["insufficient"] += 1
        elif status == AssessmentStatus.CONFLICTING_EVIDENCE.value:
            stats["conflicting"] += 1
    
    return stats


# =============================================================================
# API ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API root endpoint."""
    return {
        "name": "AI-Powered Security Auditor API",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/api/health",
            "status": "/api/status",
            "audits": "/api/audits",
            "frameworks": "/api/frameworks",
            "controls": "/api/frameworks/{framework}/controls",
            "docs": "/api/docs"
        }
    }


# =============================================================================
# HEALTH & STATUS ENDPOINTS
# =============================================================================

@app.get("/api/health")
async def health_check():
    """Health check endpoint for monitoring and dashboard connectivity."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "services": {
            "api": "operational",
            "database": "operational",
            "agents": "operational"
        }
    }


@app.get("/api/status")
async def system_status():
    """Get system status and metrics."""
    import time
    return {
        "version": "1.0.0",
        "uptime_seconds": int(time.time() % 86400),  # Simplified uptime
        "active_audits": len([a for a in _active_audits.values() if a.get("status") == "running"]),
        "total_audits": len(_active_audits),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/frameworks")
async def list_frameworks():
    """List all available compliance frameworks."""
    frameworks = []
    for key, data in FRAMEWORK_CONTROLS.items():
        stats = calculate_statistics(data["controls"])
        frameworks.append({
            "id": key,
            "name": data["name"],
            "description": data["description"],
            "control_count": len(data["controls"]),
            "statistics": stats
        })
    return {"frameworks": frameworks}


@app.get("/api/frameworks/{framework}/controls", response_model=ControlsResponse)
async def get_framework_controls(
    framework: str,
    status: Optional[str] = Query(None, description="Filter by assessment status"),
    category: Optional[str] = Query(None, description="Filter by control category"),
    search: Optional[str] = Query(None, description="Search in control ID or name")
):
    """
    Get all controls for a specific compliance framework.
    
    Supports optional filtering by status, category, and search term.
    """
    fw_data = get_framework_data(framework)
    controls = fw_data["controls"].copy()
    
    # Apply filters
    if status:
        controls = [c for c in controls if c.get("status") == status]
    
    if category:
        controls = [c for c in controls if c.get("category", "").lower() == category.lower()]
    
    if search:
        search_lower = search.lower()
        controls = [
            c for c in controls 
            if search_lower in c.get("id", "").lower() or search_lower in c.get("name", "").lower()
        ]
    
    stats = calculate_statistics(controls)
    
    return ControlsResponse(
        framework=framework,
        framework_name=fw_data["name"],
        description=fw_data["description"],
        controls=[ControlAssessment(**c) for c in controls],
        total_count=stats["total"],
        assessed_count=stats["assessed"],
        pass_count=stats["pass"],
        fail_count=stats["fail"]
    )


@app.get("/api/audit/{audit_id}/controls")
async def get_audit_controls(
    audit_id: str,
    framework: str = Query(..., description="Framework to get controls for")
):
    """
    Get control assessments for a specific audit.
    
    Returns real assessment results if audit exists, otherwise returns framework defaults.
    """
    # Check if audit exists
    if audit_id in _active_audits:
        audit = _active_audits[audit_id]
        # Return audit-specific results if available
        if "controls" in audit and framework in audit["controls"]:
            return audit["controls"][framework]
    
    # Fallback to framework defaults
    return await get_framework_controls(framework)


# =============================================================================
# RESTFUL AUDITS ENDPOINTS (Dashboard-compatible)
# =============================================================================

@app.post("/api/audits")
async def create_audit(request: AuditRequest):
    """
    Create and start a new security audit (RESTful endpoint).
    
    This is the dashboard-compatible endpoint that matches /api/audits convention.
    """
    audit_id = f"AUDIT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    _active_audits[audit_id] = {
        "id": audit_id,
        "status": "running",
        "current_phase": "initialization",
        "progress": 0.0,
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "frameworks": request.frameworks,
        "scan_types": request.scan_types,
        "target_path": request.target_path,
        "findings": [],
        "evidence_collected": 0,
        "evidence_gaps": 0,
        "controls": {},
        "agents": {
            "vulnerability_scanner": {"status": "pending", "progress": 0.0, "findings_count": 0},
            "code_analyzer": {"status": "pending", "progress": 0.0, "findings_count": 0},
            "log_analyzer": {"status": "pending", "progress": 0.0, "findings_count": 0},
            "compliance_checker": {"status": "pending", "progress": 0.0, "findings_count": 0},
        }
    }
    
    # Start audit in background
    asyncio.create_task(_run_audit(audit_id, request))
    
    logger.info(f"Started audit {audit_id} for frameworks: {request.frameworks}")
    
    return {
        "id": audit_id,
        "audit_id": audit_id,  # Keep backward compatibility
        "status": "running",
        "current_phase": "initialization",
        "progress": 0.0,
        "started_at": _active_audits[audit_id]["started_at"],
        "frameworks": request.frameworks,
        "message": f"Audit started for {len(request.frameworks)} framework(s)"
    }


@app.get("/api/audits")
async def list_audits(
    status: Optional[str] = Query(None, description="Filter by audit status"),
    limit: int = Query(50, description="Maximum results to return"),
    offset: int = Query(0, description="Results offset for pagination")
):
    """
    List all audits with optional filtering.
    
    Returns list of audit summaries for the dashboard.
    """
    audits = list(_active_audits.values())
    
    # Filter by status if provided
    if status:
        audits = [a for a in audits if a.get("status") == status]
    
    # Sort by started_at descending (newest first)
    audits.sort(key=lambda x: x.get("started_at", ""), reverse=True)
    
    # Apply pagination
    paginated = audits[offset:offset + limit]
    
    # Return audit summaries
    return [
        {
            "id": a.get("id", audit_id),
            "audit_id": audit_id,
            "status": a.get("status"),
            "current_phase": a.get("current_phase"),
            "progress": a.get("progress", 0.0),
            "started_at": a.get("started_at"),
            "completed_at": a.get("completed_at"),
            "frameworks": a.get("frameworks", []),
            "findings_count": len(a.get("findings", [])),
            "evidence_count": a.get("evidence_collected", 0),
        }
        for audit_id, a in _active_audits.items()
        if a in paginated
    ]


@app.get("/api/audits/{audit_id}")
async def get_audit(audit_id: str):
    """
    Get detailed information for a specific audit.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    audit = _active_audits[audit_id]
    findings = audit.get("findings", [])
    
    return {
        "id": audit_id,
        "audit_id": audit_id,
        "status": audit.get("status"),
        "current_phase": audit.get("current_phase"),
        "progress": audit.get("progress", 0.0),
        "started_at": audit.get("started_at"),
        "completed_at": audit.get("completed_at"),
        "frameworks": audit.get("frameworks", []),
        "scan_types": audit.get("scan_types", []),
        "target_path": audit.get("target_path"),
        "findings_count": {
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
            "total": len(findings)
        },
        "evidence_count": audit.get("evidence_collected", 0),
        "evidence_gaps": audit.get("evidence_gaps", 0),
    }


@app.post("/api/audits/{audit_id}/cancel")
async def cancel_audit(audit_id: str):
    """
    Cancel a running audit.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    audit = _active_audits[audit_id]
    
    if audit.get("status") not in ["running", "pending"]:
        raise HTTPException(status_code=400, detail=f"Cannot cancel audit in status: {audit.get('status')}")
    
    audit["status"] = "cancelled"
    audit["completed_at"] = datetime.now().isoformat()
    audit["current_phase"] = "cancelled"
    
    logger.info(f"Cancelled audit {audit_id}")
    
    return await get_audit(audit_id)


@app.get("/api/audits/{audit_id}/summary")
async def get_audit_summary(audit_id: str):
    """
    Get comprehensive audit summary for dashboard display.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    audit = _active_audits[audit_id]
    findings = audit.get("findings", [])
    
    # Calculate compliance stats per framework
    compliance_stats = {}
    for fw in audit.get("frameworks", []):
        fw_data = FRAMEWORK_CONTROLS.get(fw, {})
        controls = fw_data.get("controls", [])
        stats = calculate_statistics(controls)
        compliance_stats[fw] = {
            "total_controls": stats["total"],
            "passed": stats["pass"],
            "failed": stats["fail"],
            "needs_review": stats["needs_review"],
            "evidence_gaps": stats["evidence_gap"],
            "compliance_rate": round((stats["pass"] / stats["total"]) * 100, 1) if stats["total"] > 0 else 0
        }
    
    return {
        "audit_id": audit_id,
        "status": audit.get("status"),
        "progress": audit.get("progress", 0.0),
        "current_phase": audit.get("current_phase"),
        "started_at": audit.get("started_at"),
        "completed_at": audit.get("completed_at"),
        "duration_seconds": None,  # Would calculate from timestamps
        "findings_summary": {
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
            "info": len([f for f in findings if f.get("severity") == "info"]),
            "total": len(findings)
        },
        "compliance_summary": compliance_stats,
        "evidence_summary": {
            "total_collected": audit.get("evidence_collected", 0),
            "gaps_identified": audit.get("evidence_gaps", 0),
            "citation_rate": audit.get("citation_rate", 0.0)
        },
        "anti_hallucination": {
            "llm_overrides": audit.get("llm_overrides", 0),
            "forbidden_words_detected": audit.get("forbidden_words", 0),
            "evidence_citation_rate": audit.get("citation_rate", 0.0),
            "average_confidence": audit.get("avg_confidence", 0.0)
        }
    }


@app.get("/api/audits/{audit_id}/agents")
async def get_agent_statuses(audit_id: str):
    """
    Get status of all agents for an audit.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    audit = _active_audits[audit_id]
    agents = audit.get("agents", {})
    
    return [
        {
            "agent_type": agent_type,
            "status": data.get("status", "unknown"),
            "progress": data.get("progress", 0.0),
            "findings_count": data.get("findings_count", 0),
            "last_update": data.get("last_update"),
            "current_task": data.get("current_task")
        }
        for agent_type, data in agents.items()
    ]


@app.get("/api/audits/{audit_id}/agents/{agent_type}")
async def get_agent_status(audit_id: str, agent_type: str):
    """
    Get status of a specific agent.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    audit = _active_audits[audit_id]
    agents = audit.get("agents", {})
    
    if agent_type not in agents:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_type}")
    
    data = agents[agent_type]
    return {
        "agent_type": agent_type,
        "status": data.get("status", "unknown"),
        "progress": data.get("progress", 0.0),
        "findings_count": data.get("findings_count", 0),
        "last_update": data.get("last_update"),
        "current_task": data.get("current_task")
    }


@app.get("/api/audits/{audit_id}/compliance")
async def get_compliance_status(audit_id: str):
    """
    Get compliance status for all frameworks in an audit.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    audit = _active_audits[audit_id]
    results = []
    
    for fw in audit.get("frameworks", []):
        fw_data = FRAMEWORK_CONTROLS.get(fw, {})
        controls = fw_data.get("controls", [])
        stats = calculate_statistics(controls)
        
        results.append({
            "framework": fw,
            "name": fw_data.get("name", fw),
            "description": fw_data.get("description", ""),
            "total_controls": stats["total"],
            "passed": stats["pass"],
            "failed": stats["fail"],
            "needs_review": stats["needs_review"],
            "evidence_gap": stats["evidence_gap"],
            "compliance_rate": round((stats["pass"] / stats["total"]) * 100, 1) if stats["total"] > 0 else 0
        })
    
    return results


@app.get("/api/audits/{audit_id}/compliance/{framework}/controls")
async def get_compliance_controls(
    audit_id: str,
    framework: str,
    state: Optional[str] = Query(None, description="Filter by assessment state")
):
    """
    Get control assessments for a specific framework in an audit.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    fw_data = get_framework_data(framework)
    controls = fw_data["controls"].copy()
    
    # Filter by state if provided
    if state:
        controls = [c for c in controls if c.get("status") == state]
    
    return controls


@app.get("/api/audits/{audit_id}/evidence")
async def get_evidence(
    audit_id: str,
    evidence_type: Optional[str] = Query(None, description="Filter by evidence type"),
    limit: int = Query(50, description="Maximum results"),
    offset: int = Query(0, description="Results offset")
):
    """
    Get evidence artifacts for an audit.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    # Placeholder - would return actual evidence from audit
    return []


@app.get("/api/audits/{audit_id}/evidence/{evidence_id}")
async def get_evidence_detail(audit_id: str, evidence_id: str):
    """
    Get a specific evidence artifact.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    raise HTTPException(status_code=404, detail=f"Evidence not found: {evidence_id}")


@app.get("/api/audits/{audit_id}/anti-hallucination")
async def get_anti_hallucination_metrics(audit_id: str):
    """
    Get anti-hallucination metrics for an audit.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    audit = _active_audits[audit_id]
    
    return {
        "llm_overrides": audit.get("llm_overrides", 0),
        "forbidden_words_detected": audit.get("forbidden_words", 0),
        "evidence_citation_rate": audit.get("citation_rate", 0.0),
        "average_confidence": audit.get("avg_confidence", 0.0),
        "confidence_distribution": [
            {"range": "0.0-0.2", "count": 0},
            {"range": "0.2-0.4", "count": 0},
            {"range": "0.4-0.6", "count": 2},
            {"range": "0.6-0.8", "count": 5},
            {"range": "0.8-1.0", "count": 8}
        ]
    }


@app.get("/api/audits/{audit_id}/evidence-gaps")
async def get_evidence_gaps(audit_id: str):
    """
    Get evidence gaps identified in an audit.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    # Return placeholder evidence gaps
    return [
        {"control": "CC6.1", "requirement": "Access control logs for past 90 days", "priority": "high"},
        {"control": "CC7.1", "requirement": "SIEM configuration documentation", "priority": "medium"},
    ]


@app.get("/api/audits/{audit_id}/dashboard")
async def get_dashboard_data(audit_id: str):
    """
    Get all dashboard data in one call (performance optimization).
    
    Returns summary, agents, findings, compliance, and anti-hallucination data.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    # Gather all data in parallel-friendly format
    summary = await get_audit_summary(audit_id)
    agents = await get_agent_statuses(audit_id)
    findings_response = await get_audit_findings(audit_id)
    compliance = await get_compliance_status(audit_id)
    anti_hallucination = await get_anti_hallucination_metrics(audit_id)
    evidence_gaps = await get_evidence_gaps(audit_id)
    
    return {
        "summary": summary,
        "agents": agents,
        "findings": findings_response,
        "compliance": compliance,
        "anti_hallucination": anti_hallucination,
        "evidence_gaps": evidence_gaps
    }


@app.get("/api/audits/{audit_id}/findings")
async def get_audit_findings_restful(
    audit_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    agent: Optional[str] = Query(None, description="Filter by agent"),
    limit: int = Query(100, description="Maximum results"),
    offset: int = Query(0, description="Results offset")
):
    """
    Get findings for an audit (RESTful endpoint).
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    findings = _active_audits[audit_id].get("findings", [])
    
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    
    if agent:
        findings = [f for f in findings if f.get("agent") == agent]
    
    paginated = findings[offset:offset + limit]
    
    return {
        "findings": paginated,
        "total": len(findings),
        "limit": limit,
        "offset": offset
    }


@app.get("/api/audits/{audit_id}/findings/{finding_id}")
async def get_finding_detail(audit_id: str, finding_id: str):
    """
    Get a specific finding by ID.
    """
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    findings = _active_audits[audit_id].get("findings", [])
    finding = next((f for f in findings if f.get("id") == finding_id), None)
    
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
    
    return finding


# =============================================================================
# LEGACY ENDPOINTS (Backward compatibility)
# =============================================================================

@app.post("/api/audit/start", deprecated=True)
async def start_audit_legacy(request: AuditRequest):
    """
    Start a new security audit (DEPRECATED).
    
    Use POST /api/audits instead.
    """
    logger.warning("Deprecated endpoint /api/audit/start called. Use POST /api/audits instead.")
    return await create_audit(request)


@app.get("/api/audit/{audit_id}/status", response_model=AuditStatusResponse)
async def get_audit_status(audit_id: str):
    """Get current status and metrics for an audit."""
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    audit = _active_audits[audit_id]
    
    # Calculate findings counts
    findings = audit.get("findings", [])
    findings_count = {
        "critical": len([f for f in findings if f.get("severity") == "critical"]),
        "high": len([f for f in findings if f.get("severity") == "high"]),
        "medium": len([f for f in findings if f.get("severity") == "medium"]),
        "low": len([f for f in findings if f.get("severity") == "low"]),
        "total": len(findings)
    }
    
    return AuditStatusResponse(
        audit_id=audit_id,
        status=audit.get("status", "unknown"),
        current_phase=audit.get("current_phase", "unknown"),
        progress=audit.get("progress", 0.0),
        started_at=audit.get("started_at", ""),
        completed_at=audit.get("completed_at"),
        findings_count=findings_count,
        evidence_count=audit.get("evidence_collected", 0),
        evidence_gaps=audit.get("evidence_gaps", 0),
        anti_hallucination={
            "llm_overrides": audit.get("llm_overrides", 0),
            "forbidden_words_detected": audit.get("forbidden_words", 0),
            "evidence_citation_rate": audit.get("citation_rate", 0.0),
            "average_confidence": audit.get("avg_confidence", 0.0)
        }
    )


@app.get("/api/audit/{audit_id}/findings")
async def get_audit_findings(
    audit_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    agent: Optional[str] = Query(None, description="Filter by agent")
):
    """Get findings for a specific audit."""
    if audit_id not in _active_audits:
        raise HTTPException(status_code=404, detail=f"Audit not found: {audit_id}")
    
    findings = _active_audits[audit_id].get("findings", [])
    
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    
    if agent:
        findings = [f for f in findings if f.get("agent") == agent]
    
    return {"findings": findings, "total": len(findings)}


# =============================================================================
# WEBSOCKET ENDPOINTS
# =============================================================================

@app.websocket("/api/audits/{audit_id}/ws")
async def websocket_audit_updates_restful(websocket: WebSocket, audit_id: str):
    """
    WebSocket endpoint for real-time audit updates (RESTful path).
    
    Sends status updates every second while audit is running.
    """
    await websocket.accept()
    
    # Track connected client
    if audit_id not in _connected_websockets:
        _connected_websockets[audit_id] = []
    _connected_websockets[audit_id].append(websocket)
    
    logger.info(f"WebSocket connected for audit {audit_id}")
    
    try:
        while True:
            if audit_id in _active_audits:
                status = await get_audit_status(audit_id)
                await websocket.send_json(status.dict())
                
                # Stop sending if audit completed
                if status.status in ["completed", "failed", "error", "cancelled"]:
                    break
            
            await asyncio.sleep(1)
            
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for audit {audit_id}")
    finally:
        if audit_id in _connected_websockets:
            _connected_websockets[audit_id].remove(websocket)


@app.websocket("/api/audit/{audit_id}/ws")
async def websocket_audit_updates(websocket: WebSocket, audit_id: str):
    """
    WebSocket endpoint for real-time audit updates.
    
    Sends status updates every second while audit is running.
    """
    await websocket.accept()
    
    # Track connected client
    if audit_id not in _connected_websockets:
        _connected_websockets[audit_id] = []
    _connected_websockets[audit_id].append(websocket)
    
    logger.info(f"WebSocket connected for audit {audit_id}")
    
    try:
        while True:
            if audit_id in _active_audits:
                status = await get_audit_status(audit_id)
                await websocket.send_json(status.dict())
                
                # Stop sending if audit completed
                if status.status in ["completed", "failed", "error"]:
                    break
            
            await asyncio.sleep(1)
            
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for audit {audit_id}")
    finally:
        if audit_id in _connected_websockets:
            _connected_websockets[audit_id].remove(websocket)


# =============================================================================
# BACKGROUND TASKS
# =============================================================================

async def _run_audit(audit_id: str, request: AuditRequest):
    """
    Background task to run the audit.
    
    In production, this would integrate with the actual SecurityAuditOrchestrator.
    """
    phases = [
        ("initialization", 0.1),
        ("evidence_collection", 0.2),
        ("vulnerability_scan", 0.4),
        ("code_analysis", 0.6),
        ("log_analysis", 0.75),
        ("compliance_check", 0.9),
        ("report_generation", 1.0)
    ]
    
    try:
        for phase, progress in phases:
            if audit_id not in _active_audits:
                return
            
            _active_audits[audit_id]["current_phase"] = phase
            _active_audits[audit_id]["progress"] = progress
            
            # Simulate processing time
            await asyncio.sleep(2)
            
            # Broadcast to WebSocket clients
            await _broadcast_status(audit_id)
        
        # Mark as completed
        _active_audits[audit_id]["status"] = "completed"
        _active_audits[audit_id]["completed_at"] = datetime.now().isoformat()
        _active_audits[audit_id]["current_phase"] = "completed"
        
        logger.info(f"Audit {audit_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Audit {audit_id} failed: {e}")
        _active_audits[audit_id]["status"] = "failed"
        _active_audits[audit_id]["error"] = str(e)


async def _broadcast_status(audit_id: str):
    """Broadcast status update to all connected WebSocket clients."""
    if audit_id not in _connected_websockets:
        return
    
    status = await get_audit_status(audit_id)
    
    for websocket in _connected_websockets[audit_id]:
        try:
            await websocket.send_json(status.dict())
        except Exception:
            pass


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
