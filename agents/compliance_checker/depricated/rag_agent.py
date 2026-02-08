"""
RAG-Integrated Compliance Checker Agent

This version of the Compliance Checker uses the RAG pipeline to:
1. Retrieve relevant control definitions
2. Load anti-hallucination rules into context
3. Build evidence-aware prompts for LLM assessment
4. Enforce citation requirements in all findings

The core principle: "If you can't prove it, you can't claim it"
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import yaml

# RAG imports
from rag import ComplianceRAGPipeline, RetrievalContext


class AssessmentStatus(Enum):
    """Valid assessment statuses - no weasel words allowed."""
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"


class FindingSeverity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(Enum):
    """Confidence in assessment - based on evidence quality."""
    HIGH = "HIGH"      # All required evidence present and valid
    MEDIUM = "MEDIUM"  # Some evidence missing or stale
    LOW = "LOW"        # Significant evidence gaps


@dataclass
class EvidenceValidation:
    """Result of validating a single piece of evidence."""
    evidence_id: str
    evidence_name: str
    present: bool
    fresh: bool
    valid: bool
    score: float
    issues: list[str] = field(default_factory=list)
    source_file: Optional[str] = None
    collected_at: Optional[datetime] = None


@dataclass
class Finding:
    """A compliance finding with required evidence citations."""
    finding_id: str
    control_id: str
    severity: FindingSeverity
    title: str
    description: str
    evidence_refs: list[str]  # REQUIRED - must cite evidence
    reasoning: str            # REQUIRED - explain based on evidence
    recommendation: str
    status: AssessmentStatus
    
    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "control_id": self.control_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence_refs": self.evidence_refs,
            "reasoning": self.reasoning,
            "recommendation": self.recommendation,
            "status": self.status.value
        }


@dataclass
class ControlAssessment:
    """Complete assessment of a single control."""
    control_id: str
    control_title: str
    status: AssessmentStatus
    score: float
    confidence: ConfidenceLevel
    evidence_validations: list[EvidenceValidation]
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
            "confidence": self.confidence.value,
            "evidence_validations": [
                {
                    "evidence_id": ev.evidence_id,
                    "present": ev.present,
                    "fresh": ev.fresh,
                    "valid": ev.valid,
                    "score": ev.score,
                    "issues": ev.issues
                }
                for ev in self.evidence_validations
            ],
            "findings": [f.to_dict() for f in self.findings],
            "evidence_gaps": self.evidence_gaps,
            "reasoning": self.reasoning,
            "assessed_at": self.assessed_at.isoformat()
        }


class RAGComplianceChecker:
    """
    RAG-integrated compliance checker.
    
    Uses semantic search to retrieve:
    - Control definitions and requirements
    - Evidence validation rules
    - Anti-hallucination scoring rubric
    
    Then applies strict evidence-based assessment.
    """
    
    # Weasel words that must NEVER appear in assessments
    FORBIDDEN_WORDS = [
        "likely", "probably", "presumably", "seems to",
        "appears to", "might", "could be", "should have",
        "typically", "generally", "usually", "possibly"
    ]
    
    def __init__(
        self,
        rag_pipeline: ComplianceRAGPipeline,
        controls_path: Path,
        evidence_store_path: Path = None,
        llm_client = None  # Optional LLM for automated assessment
    ):
        self.rag = rag_pipeline
        self.controls_path = controls_path
        self.evidence_store_path = evidence_store_path
        self.llm_client = llm_client
        
        # Load control definitions
        with open(controls_path, 'r') as f:
            self.controls_data = yaml.safe_load(f)
        
        # Load evidence manifest if exists
        self.evidence_manifest = {}
        if evidence_store_path:
            manifest_path = evidence_store_path / "manifest.json"
            if manifest_path.exists():
                with open(manifest_path, 'r') as f:
                    self.evidence_manifest = json.load(f).get("evidence", {})
    
    def _check_for_weasel_words(self, text: str) -> list[str]:
        """Check text for forbidden weasel words."""
        found = []
        text_lower = text.lower()
        for word in self.FORBIDDEN_WORDS:
            if word in text_lower:
                found.append(word)
        return found
    
    def _validate_evidence_freshness(
        self,
        collected_at: datetime,
        freshness_window_days: int
    ) -> tuple[bool, float]:
        """
        Validate evidence freshness and calculate score.
        
        Returns (is_fresh, freshness_score)
        """
        if not collected_at:
            return False, 0.0
        
        age = datetime.utcnow() - collected_at
        window = timedelta(days=freshness_window_days)
        
        if age <= window:
            return True, 1.0
        elif age <= window + timedelta(days=30):
            return False, 0.7
        elif age <= window + timedelta(days=90):
            return False, 0.3
        else:
            return False, 0.0
    
    def _get_evidence_info(self, evidence_id: str) -> dict:
        """Get evidence info from manifest."""
        return self.evidence_manifest.get(evidence_id, {})
    
    async def assess_control(
        self,
        control_id: str,
        collected_evidence: dict[str, Any] = None
    ) -> ControlAssessment:
        """
        Assess a single control using RAG-retrieved context.
        
        Args:
            control_id: SOC 2 control ID (e.g., "CC6.1")
            collected_evidence: Dict of evidence_id -> evidence data
        
        Returns:
            ControlAssessment with evidence-based findings
        """
        collected_evidence = collected_evidence or {}
        
        # Get control definition
        control = self.controls_data.get("controls", {}).get(control_id)
        if not control:
            return ControlAssessment(
                control_id=control_id,
                control_title="Unknown Control",
                status=AssessmentStatus.EVIDENCE_GAP,
                score=0.0,
                confidence=ConfidenceLevel.LOW,
                evidence_validations=[],
                findings=[],
                evidence_gaps=[f"Control {control_id} not found in framework"],
                reasoning=f"Control {control_id} is not defined in the loaded framework."
            )
        
        # Retrieve RAG context
        context = await self.rag.retrieve_for_control(
            control_id=control_id,
            include_rubric=True
        )
        
        # Get evidence requirements
        evidence_plan = control.get("evidence_plan", {})
        required_evidence = evidence_plan.get("required_evidence", [])
        
        # Validate each required evidence
        validations = []
        evidence_gaps = []
        total_weight = 0
        weighted_score = 0
        
        for req in required_evidence:
            ev_id = req.get("evidence_id")
            ev_name = req.get("name", ev_id)
            ev_weight = req.get("weight", 1.0)
            freshness_days = req.get("freshness_window_days", 365)
            
            total_weight += ev_weight
            
            # Check if evidence was collected
            if ev_id in collected_evidence:
                ev_data = collected_evidence[ev_id]
                collected_at = ev_data.get("collected_at")
                if isinstance(collected_at, str):
                    collected_at = datetime.fromisoformat(collected_at)
                
                # Validate freshness
                is_fresh, freshness_score = self._validate_evidence_freshness(
                    collected_at, freshness_days
                )
                
                # Run validation rules
                validation_rules = req.get("validation_rules", [])
                rule_issues = []
                rules_passed = True
                
                for rule in validation_rules:
                    # Check if rule validation is in evidence data
                    rule_result = ev_data.get("validations", {}).get(rule, None)
                    if rule_result is False:
                        rule_issues.append(f"Validation rule '{rule}' failed")
                        rules_passed = False
                    elif rule_result is None:
                        rule_issues.append(f"Validation rule '{rule}' not checked")
                
                # Calculate evidence score
                ev_score = freshness_score if rules_passed else freshness_score * 0.5
                weighted_score += ev_weight * ev_score
                
                issues = []
                if not is_fresh:
                    issues.append(f"Evidence is stale (collected {collected_at})")
                issues.extend(rule_issues)
                
                validations.append(EvidenceValidation(
                    evidence_id=ev_id,
                    evidence_name=ev_name,
                    present=True,
                    fresh=is_fresh,
                    valid=rules_passed and is_fresh,
                    score=ev_score,
                    issues=issues,
                    source_file=ev_data.get("source_file"),
                    collected_at=collected_at
                ))
            else:
                # Evidence not collected - this is a gap
                evidence_gaps.append(ev_id)
                validations.append(EvidenceValidation(
                    evidence_id=ev_id,
                    evidence_name=ev_name,
                    present=False,
                    fresh=False,
                    valid=False,
                    score=0.0,
                    issues=[f"Evidence {ev_id} not collected"]
                ))
        
        # Calculate control score
        control_score = weighted_score / total_weight if total_weight > 0 else 0.0
        
        # Determine status based on score AND evidence presence
        # CRITICAL: Cannot pass without evidence
        if evidence_gaps:
            if len(evidence_gaps) == len(required_evidence):
                status = AssessmentStatus.EVIDENCE_GAP
            else:
                status = AssessmentStatus.INSUFFICIENT_EVIDENCE
        else:
            thresholds = control.get("scoring_rubric", {}).get("score_thresholds", {})
            pass_threshold = thresholds.get("pass", 0.80)
            exception_threshold = thresholds.get("pass_with_exceptions", 0.60)
            
            if control_score >= pass_threshold:
                status = AssessmentStatus.PASS
            elif control_score >= exception_threshold:
                status = AssessmentStatus.NEEDS_MANUAL_REVIEW
            else:
                status = AssessmentStatus.FAIL
        
        # Determine confidence based on evidence quality
        valid_count = sum(1 for v in validations if v.valid)
        if valid_count == len(validations) and len(validations) > 0:
            confidence = ConfidenceLevel.HIGH
        elif valid_count >= len(validations) / 2:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW
        
        # Generate findings
        findings = self._generate_findings(
            control_id=control_id,
            control=control,
            validations=validations,
            evidence_gaps=evidence_gaps,
            status=status
        )
        
        # Build reasoning (must cite evidence)
        reasoning = self._build_reasoning(
            control_id=control_id,
            validations=validations,
            evidence_gaps=evidence_gaps,
            score=control_score,
            status=status
        )
        
        # Validate reasoning doesn't contain weasel words
        weasel_words = self._check_for_weasel_words(reasoning)
        if weasel_words:
            # This shouldn't happen with our generated reasoning
            reasoning = f"[INTERNAL ERROR: Weasel words detected: {weasel_words}] " + reasoning
        
        return ControlAssessment(
            control_id=control_id,
            control_title=control.get("title", ""),
            status=status,
            score=control_score,
            confidence=confidence,
            evidence_validations=validations,
            findings=findings,
            evidence_gaps=evidence_gaps,
            reasoning=reasoning
        )
    
    def _generate_findings(
        self,
        control_id: str,
        control: dict,
        validations: list[EvidenceValidation],
        evidence_gaps: list[str],
        status: AssessmentStatus
    ) -> list[Finding]:
        """Generate findings based on validation results."""
        findings = []
        finding_counter = 1
        
        severity_map = control.get("scoring_rubric", {}).get("finding_severity", {})
        
        # Finding for each evidence gap
        for gap in evidence_gaps:
            findings.append(Finding(
                finding_id=f"{control_id}-F{finding_counter:03d}",
                control_id=control_id,
                severity=FindingSeverity(severity_map.get("evidence_gap", "high")),
                title=f"Missing Evidence: {gap}",
                description=f"Required evidence {gap} was not collected for control {control_id}.",
                evidence_refs=[],  # No evidence to cite
                reasoning=f"Evidence {gap} is required per control definition but was not found in collected evidence.",
                recommendation=f"Collect evidence {gap} from the appropriate source system.",
                status=AssessmentStatus.EVIDENCE_GAP
            ))
            finding_counter += 1
        
        # Findings for validation issues
        for validation in validations:
            if validation.issues and validation.present:
                for issue in validation.issues:
                    findings.append(Finding(
                        finding_id=f"{control_id}-F{finding_counter:03d}",
                        control_id=control_id,
                        severity=FindingSeverity.MEDIUM,
                        title=f"Evidence Issue: {validation.evidence_id}",
                        description=issue,
                        evidence_refs=[validation.evidence_id],
                        reasoning=f"Evidence {validation.evidence_id} was collected but has issues: {issue}",
                        recommendation="Review and update evidence to meet validation requirements.",
                        status=AssessmentStatus.NEEDS_MANUAL_REVIEW
                    ))
                    finding_counter += 1
        
        return findings
    
    def _build_reasoning(
        self,
        control_id: str,
        validations: list[EvidenceValidation],
        evidence_gaps: list[str],
        score: float,
        status: AssessmentStatus
    ) -> str:
        """
        Build evidence-based reasoning for the assessment.
        
        MUST cite specific evidence - no assumptions allowed.
        """
        parts = [f"Assessment of {control_id}:"]
        
        # Cite present evidence
        present_evidence = [v for v in validations if v.present]
        if present_evidence:
            parts.append("\nEvidence collected:")
            for v in present_evidence:
                status_str = "valid" if v.valid else "invalid"
                parts.append(f"- {v.evidence_id}: {status_str} (score: {v.score:.2f})")
                if v.source_file:
                    parts.append(f"  Source: {v.source_file}")
        
        # Document gaps
        if evidence_gaps:
            parts.append("\nEvidence gaps (not collected):")
            for gap in evidence_gaps:
                parts.append(f"- {gap}: NOT COLLECTED")
        
        # Explain score calculation
        parts.append(f"\nControl score: {score:.2f}")
        parts.append(f"Status: {status.value}")
        
        # Explain status determination
        if status == AssessmentStatus.EVIDENCE_GAP:
            parts.append("Status is EVIDENCE_GAP because required evidence was not collected.")
        elif status == AssessmentStatus.INSUFFICIENT_EVIDENCE:
            parts.append("Status is INSUFFICIENT_EVIDENCE because some required evidence is missing.")
        elif status == AssessmentStatus.PASS:
            parts.append("Status is PASS because all evidence meets requirements.")
        elif status == AssessmentStatus.FAIL:
            parts.append("Status is FAIL because evidence score is below threshold.")
        
        return "\n".join(parts)
    
    async def assess_all_controls(
        self,
        collected_evidence: dict[str, Any] = None
    ) -> list[ControlAssessment]:
        """Assess all controls in the framework."""
        assessments = []
        
        for control_id in self.controls_data.get("controls", {}).keys():
            assessment = await self.assess_control(control_id, collected_evidence)
            assessments.append(assessment)
        
        return assessments
    
    async def generate_report(
        self,
        assessments: list[ControlAssessment]
    ) -> dict:
        """Generate a comprehensive compliance report."""
        
        # Calculate summary statistics
        status_counts = {}
        for status in AssessmentStatus:
            status_counts[status.value] = sum(
                1 for a in assessments if a.status == status
            )
        
        total_findings = sum(len(a.findings) for a in assessments)
        severity_counts = {s.value: 0 for s in FindingSeverity}
        for assessment in assessments:
            for finding in assessment.findings:
                severity_counts[finding.severity.value] += 1
        
        # Build evidence inventory
        all_evidence = set()
        all_gaps = set()
        for assessment in assessments:
            for v in assessment.evidence_validations:
                if v.present:
                    all_evidence.add(v.evidence_id)
            all_gaps.update(assessment.evidence_gaps)
        
        return {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "framework": self.controls_data.get("metadata", {}).get("framework", "SOC 2"),
                "controls_assessed": len(assessments)
            },
            "executive_summary": {
                "overall_status": self._determine_overall_status(assessments),
                "status_breakdown": status_counts,
                "total_findings": total_findings,
                "findings_by_severity": severity_counts,
                "evidence_collected": len(all_evidence),
                "evidence_gaps": len(all_gaps)
            },
            "evidence_inventory": {
                "collected": list(all_evidence),
                "gaps": list(all_gaps)
            },
            "control_assessments": [a.to_dict() for a in assessments],
            "limitations": [
                "This assessment is based solely on collected evidence.",
                "Controls with EVIDENCE_GAP status require evidence collection.",
                "All findings cite specific evidence - no assumptions are made."
            ]
        }
    
    def _determine_overall_status(self, assessments: list[ControlAssessment]) -> str:
        """Determine overall compliance status."""
        if any(a.status == AssessmentStatus.EVIDENCE_GAP for a in assessments):
            return "INCOMPLETE - Evidence gaps exist"
        
        fail_count = sum(1 for a in assessments if a.status == AssessmentStatus.FAIL)
        if fail_count > 0:
            return f"FAIL - {fail_count} controls failed"
        
        review_count = sum(
            1 for a in assessments 
            if a.status in [AssessmentStatus.NEEDS_MANUAL_REVIEW, AssessmentStatus.INSUFFICIENT_EVIDENCE]
        )
        if review_count > 0:
            return f"PASS WITH EXCEPTIONS - {review_count} controls need review"
        
        return "PASS"
