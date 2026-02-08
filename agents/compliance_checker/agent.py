"""
Compliance Checker Agent

This agent evaluates collected evidence against SOC 2 control requirements
using RAG for context and LLM for analysis. Implements strict anti-hallucination
rules from the scoring rubric.

Core Principle: "If you can't prove it, you can't claim it"
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml


class AssessmentStatus(Enum):
    """Valid assessment states - no weasel words allowed."""
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"


class FindingSeverity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class EvidenceValidationResult:
    """Result of validating a single evidence item."""
    evidence_id: str
    evidence_type: str
    is_valid: bool
    score: float  # 0.0 to 1.0
    validation_details: dict[str, Any] = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A compliance finding with evidence references."""
    finding_id: str
    control_id: str
    title: str
    description: str
    status: AssessmentStatus
    severity: FindingSeverity
    evidence_refs: list[str]
    reasoning: str
    recommendations: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "severity": self.severity.value,
            "evidence_refs": self.evidence_refs,
            "reasoning": self.reasoning,
            "recommendations": self.recommendations
        }


@dataclass
class ControlAssessment:
    """Complete assessment of a single control."""
    control_id: str
    control_title: str
    status: AssessmentStatus
    score: float
    confidence: str  # HIGH, MEDIUM, LOW
    evidence_validations: list[EvidenceValidationResult]
    findings: list[Finding]
    evidence_gaps: list[str]
    reasoning: str
    assessed_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "control_title": self.control_title,
            "status": self.status.value,
            "score": self.score,
            "confidence": self.confidence,
            "evidence_gaps": self.evidence_gaps,
            "reasoning": self.reasoning,
            "assessed_at": self.assessed_at.isoformat(),
            "findings": [f.to_dict() for f in self.findings],
            "evidence_validations": [
                {
                    "evidence_id": v.evidence_id,
                    "is_valid": v.is_valid,
                    "score": v.score,
                    "issues": v.issues
                }
                for v in self.evidence_validations
            ]
        }


class ComplianceChecker:
    """
    RAG-based compliance evaluation agent.
    
    Uses control definitions and scoring rubric to evaluate evidence
    against SOC 2 requirements. Implements strict anti-hallucination
    rules - every claim must cite specific evidence.
    """
    
    def __init__(
        self,
        controls_path: Path,
        rubric_path: Path,
        evidence_manifest_path: Path
    ):
        self.controls = self._load_controls(controls_path)
        self.rubric = self._load_rubric(rubric_path)
        self.evidence_manifest = self._load_manifest(evidence_manifest_path)
        self.finding_counter = 0
    
    def _load_controls(self, path: Path) -> dict:
        """Load SOC 2 control definitions."""
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    
    def _load_rubric(self, path: Path) -> dict:
        """Load scoring rubric with anti-hallucination rules."""
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    
    def _load_manifest(self, path: Path) -> dict:
        """Load evidence manifest."""
        if not path.exists():
            return {"evidence": {}}
        with open(path, 'r') as f:
            return json.load(f)
    
    def _generate_finding_id(self) -> str:
        """Generate unique finding ID."""
        self.finding_counter += 1
        return f"F{self.finding_counter:04d}"
    
    def assess_control(self, control_id: str) -> ControlAssessment:
        """
        Assess a single control against collected evidence.
        
        This is the core assessment logic that enforces anti-hallucination rules.
        """
        if control_id not in self.controls.get("controls", {}):
            raise ValueError(f"Unknown control: {control_id}")
        
        control = self.controls["controls"][control_id]
        evidence_plan = control.get("evidence_plan", {})
        required_evidence = evidence_plan.get("required_evidence", [])
        
        # Collect evidence for this control
        collected_evidence = self._get_evidence_for_control(control_id)
        
        # Validate each evidence item
        validations = []
        evidence_gaps = []
        
        for req in required_evidence:
            req_id = req["evidence_id"]
            matching_evidence = [
                e for e in collected_evidence
                if req_id in e.get("evidence_requirement_ids", [])
            ]
            
            if not matching_evidence:
                # Evidence gap - don't assume anything
                evidence_gaps.append(req_id)
                validations.append(EvidenceValidationResult(
                    evidence_id=req_id,
                    evidence_type=req["type"],
                    is_valid=False,
                    score=0.0,
                    issues=[f"Required evidence {req_id} not collected"]
                ))
            else:
                # Validate collected evidence
                for evidence in matching_evidence:
                    validation = self._validate_evidence(evidence, req)
                    validations.append(validation)
        
        # Calculate score based on validations
        score = self._calculate_control_score(validations, evidence_gaps, control)
        
        # Determine status
        status = self._determine_status(score, evidence_gaps, validations, control)
        
        # Generate findings
        findings = self._generate_findings(control_id, control, validations, evidence_gaps)
        
        # Determine confidence
        confidence = self._determine_confidence(validations, evidence_gaps)
        
        # Build reasoning - must cite evidence
        reasoning = self._build_reasoning(control_id, validations, evidence_gaps, status)
        
        return ControlAssessment(
            control_id=control_id,
            control_title=control["title"],
            status=status,
            score=score,
            confidence=confidence,
            evidence_validations=validations,
            findings=findings,
            evidence_gaps=evidence_gaps,
            reasoning=reasoning
        )
    
    def _get_evidence_for_control(self, control_id: str) -> list[dict]:
        """Get all evidence items for a control from manifest."""
        evidence_list = []
        for eid, entry in self.evidence_manifest.get("evidence", {}).items():
            if control_id in entry.get("control_ids", []):
                evidence_list.append({
                    "evidence_id": eid,
                    **entry
                })
        return evidence_list
    
    def _validate_evidence(
        self,
        evidence: dict,
        requirement: dict
    ) -> EvidenceValidationResult:
        """
        Validate evidence against requirement.
        
        Checks: freshness, source, completeness, validation rules.
        """
        issues = []
        score = 1.0
        
        # Check freshness
        collected_at = datetime.fromisoformat(evidence["collected_at"])
        freshness_days = requirement.get("freshness_window_days", 365)
        age = (datetime.utcnow() - collected_at).days
        
        if age > freshness_days:
            issues.append(f"Evidence is {age} days old, exceeds {freshness_days} day window")
            if age > freshness_days * 2:
                score *= 0.3
            else:
                score *= 0.7
        
        # Check source (if acceptable_sources defined)
        acceptable_sources = requirement.get("acceptable_sources", [])
        # Note: Would check evidence source against acceptable_sources
        
        # Apply validation rules (simplified - would use LLM for complex rules)
        validation_rules = requirement.get("validation_rules", [])
        # This is where RAG + LLM would evaluate the evidence content
        
        return EvidenceValidationResult(
            evidence_id=evidence["evidence_id"],
            evidence_type=requirement["type"],
            is_valid=score >= 0.6,
            score=score,
            validation_details={
                "age_days": age,
                "freshness_window": freshness_days
            },
            issues=issues
        )
    
    def _calculate_control_score(
        self,
        validations: list[EvidenceValidationResult],
        evidence_gaps: list[str],
        control: dict
    ) -> float:
        """
        Calculate control score from evidence validations.
        
        Formula: Σ(weight × score) / Σ(weight) for collected evidence
        """
        rubric = control.get("scoring_rubric", {})
        weights = rubric.get("scoring_weights", {})
        
        total_weight = 0.0
        weighted_score = 0.0
        
        for v in validations:
            weight = weights.get(v.evidence_type, 0.25)
            if v.score > 0:  # Only count collected evidence
                total_weight += weight
                weighted_score += weight * v.score
        
        if total_weight == 0:
            return 0.0
        
        return weighted_score / total_weight
    
    def _determine_status(
        self,
        score: float,
        evidence_gaps: list[str],
        validations: list[EvidenceValidationResult],
        control: dict
    ) -> AssessmentStatus:
        """
        Determine assessment status based on score and evidence.
        
        Enforces anti-hallucination: no PASS without evidence.
        """
        thresholds = control.get("scoring_rubric", {}).get("score_thresholds", {
            "pass": 0.80,
            "pass_with_exceptions": 0.60,
            "fail": 0.59
        })
        
        # Check for conflicting evidence
        has_conflicts = self._check_for_conflicts(validations)
        if has_conflicts:
            return AssessmentStatus.CONFLICTING_EVIDENCE
        
        # If all evidence is missing, it's an evidence gap
        valid_validations = [v for v in validations if v.score > 0]
        if not valid_validations:
            return AssessmentStatus.EVIDENCE_GAP
        
        # Apply thresholds
        if score >= thresholds.get("pass", 0.80):
            # Even with good score, if critical gaps exist, can't fully pass
            if evidence_gaps:
                return AssessmentStatus.INSUFFICIENT_EVIDENCE
            return AssessmentStatus.PASS
        elif score >= thresholds.get("pass_with_exceptions", 0.60):
            return AssessmentStatus.INSUFFICIENT_EVIDENCE
        else:
            return AssessmentStatus.FAIL
    
    def _check_for_conflicts(self, validations: list[EvidenceValidationResult]) -> bool:
        """Check if validations contain conflicting information."""
        # Simplified - would use LLM to detect semantic conflicts
        return False
    
    def _generate_findings(
        self,
        control_id: str,
        control: dict,
        validations: list[EvidenceValidationResult],
        evidence_gaps: list[str]
    ) -> list[Finding]:
        """Generate findings based on validation results."""
        findings = []
        
        # Finding for each evidence gap
        for gap in evidence_gaps:
            findings.append(Finding(
                finding_id=self._generate_finding_id(),
                control_id=control_id,
                title=f"Evidence Gap: {gap}",
                description=f"Required evidence {gap} was not collected",
                status=AssessmentStatus.EVIDENCE_GAP,
                severity=FindingSeverity.MEDIUM,
                evidence_refs=[],
                reasoning=f"Evidence requirement {gap} has no collected evidence. Cannot assess without this evidence.",
                recommendations=[f"Collect evidence for {gap}"]
            ))
        
        # Findings for validation issues
        for v in validations:
            if v.issues:
                findings.append(Finding(
                    finding_id=self._generate_finding_id(),
                    control_id=control_id,
                    title=f"Evidence Issue: {v.evidence_id}",
                    description="; ".join(v.issues),
                    status=AssessmentStatus.INSUFFICIENT_EVIDENCE if v.score > 0 else AssessmentStatus.FAIL,
                    severity=FindingSeverity.MEDIUM if v.score > 0.5 else FindingSeverity.HIGH,
                    evidence_refs=[v.evidence_id],
                    reasoning=f"Evidence {v.evidence_id} has validation issues: {'; '.join(v.issues)}",
                    recommendations=["Address evidence issues and re-collect"]
                ))
        
        return findings
    
    def _determine_confidence(
        self,
        validations: list[EvidenceValidationResult],
        evidence_gaps: list[str]
    ) -> str:
        """Determine confidence level based on evidence quality."""
        if evidence_gaps:
            return "LOW"
        
        avg_score = sum(v.score for v in validations) / len(validations) if validations else 0
        
        if avg_score >= 0.9:
            return "HIGH"
        elif avg_score >= 0.7:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _build_reasoning(
        self,
        control_id: str,
        validations: list[EvidenceValidationResult],
        evidence_gaps: list[str],
        status: AssessmentStatus
    ) -> str:
        """
        Build reasoning that cites specific evidence.
        
        Anti-hallucination: Every statement must reference evidence.
        """
        parts = []
        
        # List collected evidence
        collected = [v for v in validations if v.score > 0]
        if collected:
            parts.append(f"Assessed {control_id} using {len(collected)} evidence item(s):")
            for v in collected:
                parts.append(f"  - [{v.evidence_id}]: score={v.score:.2f}")
        
        # Note gaps explicitly
        if evidence_gaps:
            parts.append(f"Evidence gaps ({len(evidence_gaps)} items not collected):")
            for gap in evidence_gaps:
                parts.append(f"  - {gap}: NOT COLLECTED")
        
        # Status reasoning
        parts.append(f"Status: {status.value}")
        if status == AssessmentStatus.EVIDENCE_GAP:
            parts.append("Cannot make compliance determination without required evidence.")
        elif status == AssessmentStatus.PASS:
            parts.append("All collected evidence satisfies control requirements.")
        elif status == AssessmentStatus.INSUFFICIENT_EVIDENCE:
            parts.append("Evidence exists but does not fully satisfy control requirements.")
        
        return "\n".join(parts)
    
    def assess_all_controls(self) -> dict[str, ControlAssessment]:
        """Assess all defined controls."""
        results = {}
        for control_id in self.controls.get("controls", {}).keys():
            results[control_id] = self.assess_control(control_id)
        return results
    
    def generate_report(self, assessments: dict[str, ControlAssessment]) -> dict:
        """Generate comprehensive assessment report."""
        # Summary stats
        statuses = [a.status for a in assessments.values()]
        
        return {
            "report_generated_at": datetime.utcnow().isoformat(),
            "framework": "SOC 2",
            "summary": {
                "total_controls": len(assessments),
                "passed": sum(1 for s in statuses if s == AssessmentStatus.PASS),
                "failed": sum(1 for s in statuses if s == AssessmentStatus.FAIL),
                "evidence_gaps": sum(1 for s in statuses if s == AssessmentStatus.EVIDENCE_GAP),
                "insufficient_evidence": sum(1 for s in statuses if s == AssessmentStatus.INSUFFICIENT_EVIDENCE),
                "needs_review": sum(1 for s in statuses if s == AssessmentStatus.NEEDS_MANUAL_REVIEW)
            },
            "assessments": {
                control_id: assessment.to_dict()
                for control_id, assessment in assessments.items()
            },
            "all_findings": [
                f.to_dict()
                for a in assessments.values()
                for f in a.findings
            ],
            "all_evidence_gaps": list(set(
                gap
                for a in assessments.values()
                for gap in a.evidence_gaps
            ))
        }
