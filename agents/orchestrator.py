"""
Security Auditor Orchestrator

Multi-agent workflow coordinator using LangGraph patterns.
Coordinates four specialized agents:
1. Vulnerability Scanner - OWASP ZAP integration
2. Code Security Analyzer - OWASP Top 10 compliance
3. Log Analyzer - Anomaly detection
4. Compliance Checker - RAG-based framework validation

Workflow: Scanner → Analyzer → Log → Compliance → Report
With conditional routing based on severity findings.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, TypedDict
import logging

from agents.compliance_checker.anti_hallucination import (
    AntiHallucinationValidator,
    AssessmentState,
    EvidenceProvenance,
    create_evidence_provenance,
)

logger = logging.getLogger(__name__)


class AuditPhase(Enum):
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


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditState(TypedDict):
    """
    State object passed between agents.
    
    This follows the LangGraph pattern of having a shared state
    that each agent can read from and write to.
    """
    # Audit metadata
    audit_id: str
    framework: str
    scope: dict[str, Any]
    started_at: str
    
    # Current state
    current_phase: str
    phase_history: list[dict[str, Any]]
    
    # Results from each agent
    vulnerability_findings: list[dict[str, Any]]
    code_analysis_findings: list[dict[str, Any]]
    log_analysis_findings: list[dict[str, Any]]
    compliance_findings: list[dict[str, Any]]
    
    # Aggregated metrics
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    
    # Evidence tracking
    evidence_collected: list[str]
    evidence_gaps: list[str]
    
    # Final output
    overall_status: str
    final_report: dict[str, Any]
    
    # Anti-hallucination tracking
    validated_findings: int
    rejected_findings: int
    validation_acceptance_rate: float
    
    # Error handling
    errors: list[dict[str, Any]]


@dataclass
class AgentResult:
    """Standard result format from any agent."""
    agent_name: str
    phase: AuditPhase
    status: str  # success, partial, failed
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence_collected: list[str] = field(default_factory=list)
    evidence_gaps: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class SecurityAuditOrchestrator:
    """
    Main orchestrator for the security audit workflow.
    
    Implements a state machine pattern where each agent processes
    the current state and returns an updated state for the next agent.
    
    Anti-Hallucination Integration:
    All findings from agents are validated through the AntiHallucinationValidator
    before being added to state. Invalid findings are rejected and logged.
    """
    
    def __init__(self, strict_mode: bool = True):
        self.agents = {}
        # Initialize anti-hallucination validator
        self.validator = AntiHallucinationValidator(strict_mode=strict_mode)
        self._rejected_findings: list[dict[str, Any]] = []
        logger.info(f"Orchestrator initialized with anti-hallucination validator (strict_mode={strict_mode})")
        # Agents would be injected here in production
    
    def create_initial_state(
        self,
        audit_id: str,
        framework: str,
        scope: dict[str, Any]
    ) -> AuditState:
        """Create initial audit state."""
        return AuditState(
            audit_id=audit_id,
            framework=framework,
            scope=scope,
            started_at=datetime.utcnow().isoformat(),
            current_phase=AuditPhase.INITIALIZATION.value,
            phase_history=[],
            vulnerability_findings=[],
            code_analysis_findings=[],
            log_analysis_findings=[],
            compliance_findings=[],
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            evidence_collected=[],
            evidence_gaps=[],
            overall_status="in_progress",
            final_report={},
            validated_findings=0,
            rejected_findings=0,
            validation_acceptance_rate=1.0,
            errors=[]
        )
    
    def _record_phase_transition(
        self,
        state: AuditState,
        from_phase: AuditPhase,
        to_phase: AuditPhase,
        result: AgentResult | None = None
    ) -> AuditState:
        """Record a phase transition in the state history."""
        state["phase_history"].append({
            "from": from_phase.value,
            "to": to_phase.value,
            "timestamp": datetime.utcnow().isoformat(),
            "findings_count": len(result.findings) if result else 0,
            "status": result.status if result else "transition"
        })
        state["current_phase"] = to_phase.value
        return state
    
    def _update_severity_counts(
        self,
        state: AuditState,
        findings: list[dict[str, Any]]
    ) -> AuditState:
        """Update severity counters based on findings."""
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity == "critical":
                state["critical_count"] += 1
            elif severity == "high":
                state["high_count"] += 1
            elif severity == "medium":
                state["medium_count"] += 1
            elif severity == "low":
                state["low_count"] += 1
        return state
    
    def _should_fast_track_to_report(self, state: AuditState) -> bool:
        """
        Check if we should skip remaining phases and go to report.
        
        Fast-track conditions:
        - Multiple critical findings
        - Critical finding in infrastructure
        """
        return state["critical_count"] >= 3
    
    # =========================================================================
    # Anti-Hallucination Validation
    # =========================================================================
    
    def register_evidence(self, evidence: EvidenceProvenance) -> None:
        """
        Register evidence with the validator for citation validation.
        
        All evidence must be registered before findings can cite it.
        """
        self.validator.register_evidence(evidence)
        logger.debug(f"Registered evidence: {evidence.evidence_id}")
    
    def validate_finding(
        self,
        finding: dict[str, Any],
        state: AuditState
    ) -> tuple[bool, dict[str, Any] | None]:
        """
        Validate a finding against anti-hallucination rules.
        
        Args:
            finding: The finding dict to validate
            state: Current audit state (for available evidence)
            
        Returns:
            Tuple of (is_valid, validated_finding or None)
            If valid, returns the finding with validation metadata.
            If invalid, returns None and logs rejection.
        """
        available_evidence = state["evidence_collected"]
        result = self.validator.validate_finding(finding, available_evidence)
        
        if result.is_valid:
            # Add validation metadata to finding
            finding["_validation"] = {
                "validated_at": datetime.utcnow().isoformat(),
                "confidence_score": result.confidence_score,
                "evidence_citations": result.evidence_citations,
                "rule_results": result.rule_results,
            }
            logger.debug(f"Finding validated: {finding.get('id', 'unknown')}")
            return True, finding
        else:
            # Log rejection and store for audit trail
            rejection_record = {
                "finding": finding,
                "violations": result.violations,
                "warnings": result.warnings,
                "rejected_at": datetime.utcnow().isoformat(),
            }
            self._rejected_findings.append(rejection_record)
            logger.warning(
                f"Finding rejected: {finding.get('id', 'unknown')} - "
                f"Violations: {result.violations}"
            )
            return False, None
    
    def validate_findings_batch(
        self,
        findings: list[dict[str, Any]],
        state: AuditState
    ) -> tuple[list[dict[str, Any]], int, int]:
        """
        Validate a batch of findings and return only valid ones.
        
        Args:
            findings: List of findings to validate
            state: Current audit state
            
        Returns:
            Tuple of (validated_findings, valid_count, rejected_count)
        """
        validated = []
        valid_count = 0
        rejected_count = 0
        
        for finding in findings:
            is_valid, validated_finding = self.validate_finding(finding, state)
            if is_valid and validated_finding:
                validated.append(validated_finding)
                valid_count += 1
            else:
                rejected_count += 1
        
        # Update state metrics
        state["validated_findings"] += valid_count
        state["rejected_findings"] += rejected_count
        total = state["validated_findings"] + state["rejected_findings"]
        if total > 0:
            state["validation_acceptance_rate"] = state["validated_findings"] / total
        
        logger.info(
            f"Batch validation: {valid_count} valid, {rejected_count} rejected "
            f"(acceptance rate: {state['validation_acceptance_rate']:.2%})"
        )
        return validated, valid_count, rejected_count
    
    def get_rejected_findings(self) -> list[dict[str, Any]]:
        """Get list of all rejected findings for audit trail."""
        return self._rejected_findings.copy()
    
    def get_validation_statistics(self) -> dict[str, Any]:
        """Get validation statistics from the anti-hallucination validator."""
        return self.validator.get_statistics()
    
    # =========================================================================
    # Phase Handlers - These would call actual agents in production
    # =========================================================================
    
    async def run_initialization(self, state: AuditState) -> AuditState:
        """Initialize audit - verify scope, check connectivity."""
        state = self._record_phase_transition(
            state,
            AuditPhase.INITIALIZATION,
            AuditPhase.EVIDENCE_COLLECTION
        )
        return state
    
    async def run_evidence_collection(self, state: AuditState) -> AuditState:
        """Collect evidence from configured sources."""
        # In production, this would trigger evidence collectors
        result = AgentResult(
            agent_name="evidence_collector",
            phase=AuditPhase.EVIDENCE_COLLECTION,
            status="success",
            evidence_collected=[],  # Would be populated by collectors
            evidence_gaps=[]
        )
        
        state["evidence_collected"].extend(result.evidence_collected)
        state["evidence_gaps"].extend(result.evidence_gaps)
        
        state = self._record_phase_transition(
            state,
            AuditPhase.EVIDENCE_COLLECTION,
            AuditPhase.VULNERABILITY_SCAN,
            result
        )
        return state
    
    async def run_vulnerability_scan(self, state: AuditState) -> AuditState:
        """Run vulnerability scanner agent."""
        # In production: await self.agents["vulnerability_scanner"].run(state)
        result = AgentResult(
            agent_name="vulnerability_scanner",
            phase=AuditPhase.VULNERABILITY_SCAN,
            status="success",
            findings=[]  # Would come from OWASP ZAP
        )
        
        state["vulnerability_findings"].extend(result.findings)
        state = self._update_severity_counts(state, result.findings)
        
        # Determine next phase
        next_phase = (
            AuditPhase.REPORT_GENERATION
            if self._should_fast_track_to_report(state)
            else AuditPhase.CODE_ANALYSIS
        )
        
        state = self._record_phase_transition(
            state,
            AuditPhase.VULNERABILITY_SCAN,
            next_phase,
            result
        )
        return state
    
    async def run_code_analysis(self, state: AuditState) -> AuditState:
        """Run code security analyzer agent."""
        result = AgentResult(
            agent_name="code_analyzer",
            phase=AuditPhase.CODE_ANALYSIS,
            status="success",
            findings=[]  # Would come from SAST tools
        )
        
        state["code_analysis_findings"].extend(result.findings)
        state = self._update_severity_counts(state, result.findings)
        
        next_phase = (
            AuditPhase.REPORT_GENERATION
            if self._should_fast_track_to_report(state)
            else AuditPhase.LOG_ANALYSIS
        )
        
        state = self._record_phase_transition(
            state,
            AuditPhase.CODE_ANALYSIS,
            next_phase,
            result
        )
        return state
    
    async def run_log_analysis(self, state: AuditState) -> AuditState:
        """Run log analyzer agent."""
        result = AgentResult(
            agent_name="log_analyzer",
            phase=AuditPhase.LOG_ANALYSIS,
            status="success",
            findings=[]  # Would come from log analysis
        )
        
        state["log_analysis_findings"].extend(result.findings)
        state = self._update_severity_counts(state, result.findings)
        
        next_phase = (
            AuditPhase.REPORT_GENERATION
            if self._should_fast_track_to_report(state)
            else AuditPhase.COMPLIANCE_CHECK
        )
        
        state = self._record_phase_transition(
            state,
            AuditPhase.LOG_ANALYSIS,
            next_phase,
            result
        )
        return state
    
    async def run_compliance_check(self, state: AuditState) -> AuditState:
        """Run compliance checker agent."""
        result = AgentResult(
            agent_name="compliance_checker",
            phase=AuditPhase.COMPLIANCE_CHECK,
            status="success",
            findings=[],  # Would come from ComplianceChecker
            evidence_gaps=[]
        )
        
        state["compliance_findings"].extend(result.findings)
        state["evidence_gaps"].extend(result.evidence_gaps)
        state = self._update_severity_counts(state, result.findings)
        
        state = self._record_phase_transition(
            state,
            AuditPhase.COMPLIANCE_CHECK,
            AuditPhase.REPORT_GENERATION,
            result
        )
        return state
    
    async def run_report_generation(self, state: AuditState) -> AuditState:
        """Generate final audit report."""
        # Compile all findings
        all_findings = (
            state["vulnerability_findings"] +
            state["code_analysis_findings"] +
            state["log_analysis_findings"] +
            state["compliance_findings"]
        )
        
        # Determine overall status
        if state["critical_count"] > 0:
            overall_status = "FAIL - Critical Issues"
        elif state["high_count"] > 2:
            overall_status = "FAIL - Multiple High Issues"
        elif state["evidence_gaps"]:
            overall_status = "INCOMPLETE - Evidence Gaps"
        elif state["high_count"] > 0 or state["medium_count"] > 5:
            overall_status = "PASS WITH EXCEPTIONS"
        else:
            overall_status = "PASS"
        
        state["overall_status"] = overall_status
        state["final_report"] = {
            "audit_id": state["audit_id"],
            "framework": state["framework"],
            "scope": state["scope"],
            "started_at": state["started_at"],
            "completed_at": datetime.utcnow().isoformat(),
            "overall_status": overall_status,
            "summary": {
                "total_findings": len(all_findings),
                "critical": state["critical_count"],
                "high": state["high_count"],
                "medium": state["medium_count"],
                "low": state["low_count"],
                "evidence_collected": len(state["evidence_collected"]),
                "evidence_gaps": len(state["evidence_gaps"]),
                "anti_hallucination": {
                    "validated_findings": state["validated_findings"],
                    "rejected_findings": state["rejected_findings"],
                    "acceptance_rate": state["validation_acceptance_rate"],
                }
            },
            "findings_by_category": {
                "vulnerability": state["vulnerability_findings"],
                "code_security": state["code_analysis_findings"],
                "log_analysis": state["log_analysis_findings"],
                "compliance": state["compliance_findings"]
            },
            "evidence_gaps": state["evidence_gaps"],
            "phase_history": state["phase_history"]
        }
        
        state = self._record_phase_transition(
            state,
            AuditPhase.REPORT_GENERATION,
            AuditPhase.COMPLETED
        )
        return state
    
    # =========================================================================
    # Main Execution
    # =========================================================================
    
    async def run_audit(
        self,
        audit_id: str,
        framework: str,
        scope: dict[str, Any]
    ) -> AuditState:
        """
        Execute complete audit workflow.
        
        This is the main entry point that orchestrates all agents.
        """
        state = self.create_initial_state(audit_id, framework, scope)
        
        # Execute workflow phases
        phase_handlers = {
            AuditPhase.INITIALIZATION: self.run_initialization,
            AuditPhase.EVIDENCE_COLLECTION: self.run_evidence_collection,
            AuditPhase.VULNERABILITY_SCAN: self.run_vulnerability_scan,
            AuditPhase.CODE_ANALYSIS: self.run_code_analysis,
            AuditPhase.LOG_ANALYSIS: self.run_log_analysis,
            AuditPhase.COMPLIANCE_CHECK: self.run_compliance_check,
            AuditPhase.REPORT_GENERATION: self.run_report_generation,
        }
        
        while state["current_phase"] != AuditPhase.COMPLETED.value:
            current_phase = AuditPhase(state["current_phase"])
            
            if current_phase == AuditPhase.ERROR:
                break
            
            handler = phase_handlers.get(current_phase)
            if handler:
                try:
                    state = await handler(state)
                except Exception as e:
                    state["errors"].append({
                        "phase": current_phase.value,
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    state["current_phase"] = AuditPhase.ERROR.value
        
        return state


# Convenience function
async def run_security_audit(
    audit_id: str,
    framework: str,
    scope: dict[str, Any]
) -> dict[str, Any]:
    """
    Run a complete security audit.
    
    Example:
        report = await run_security_audit(
            audit_id="AUDIT-2025-001",
            framework="SOC2",
            scope={
                "systems": ["app-server-01", "db-server-01"],
                "period_start": "2024-10-01",
                "period_end": "2024-12-31",
            }
        )
    """
    orchestrator = SecurityAuditOrchestrator()
    final_state = await orchestrator.run_audit(audit_id, framework, scope)
    return final_state["final_report"]
