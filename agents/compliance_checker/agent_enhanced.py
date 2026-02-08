"""
Compliance Checker Agent - Enhanced with SOC2 Type 1/Type 2 Support

This agent evaluates collected evidence against SOC 2 control requirements
using RAG for context and LLM for analysis. Implements strict anti-hallucination
rules from the scoring rubric.

Core Principle: "If you can't prove it, you can't claim it"

SOC 2 Report Types:
- Type 1: Point-in-time assessment of control DESIGN
- Type 2: Period-based assessment of control OPERATING EFFECTIVENESS
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml


# =============================================================================
# ENUMS
# =============================================================================

class AssessmentStatus(Enum):
    """Valid assessment states - no weasel words allowed."""
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class FindingSeverity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SOC2ReportType(Enum):
    """SOC 2 Report Types with distinct assessment methodologies."""
    TYPE_1 = "type_1"
    TYPE_2 = "type_2"


class TestingMethod(Enum):
    """Testing methods for SOC 2 assessment."""
    INQUIRY = "inquiry"
    OBSERVATION = "observation"
    INSPECTION = "inspection"
    REPERFORMANCE = "reperformance"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class AssessmentPeriod:
    """
    Assessment period for SOC 2 evaluations.
    Type 1: Single point in time (start_date = end_date)
    Type 2: Period typically 6-12 months
    """
    start_date: datetime
    end_date: datetime
    
    @property
    def is_point_in_time(self) -> bool:
        """Check if this is a point-in-time assessment (Type 1)."""
        return self.start_date.date() == self.end_date.date()
    
    @property
    def duration_days(self) -> int:
        """Calculate duration in days."""
        return (self.end_date - self.start_date).days
    
    @property
    def duration_months(self) -> int:
        """Approximate duration in months."""
        return max(1, self.duration_days // 30)
    
    def contains(self, date: datetime) -> bool:
        """Check if a date falls within the assessment period."""
        return self.start_date <= date <= self.end_date
    
    def to_dict(self) -> dict:
        return {
            "start_date": self.start_date.isoformat(),
            "end_date": self.end_date.isoformat(),
            "duration_days": self.duration_days,
            "is_point_in_time": self.is_point_in_time
        }


@dataclass
class SampleSelection:
    """
    Sample selection for Type 2 testing.
    Based on AICPA sampling guidance.
    """
    population_size: int
    sample_size: int
    selection_method: str  # random, systematic, haphazard
    items_tested: list[str] = field(default_factory=list)
    exceptions_found: int = 0
    
    @staticmethod
    def calculate_sample_size(
        population_size: int,
        frequency: str,
        report_type: SOC2ReportType
    ) -> int:
        """
        Calculate required sample size based on AICPA guidance.
        
        Type 1: Design testing only - typically 1 item
        Type 2: Operating effectiveness - varies by frequency
        """
        if report_type == SOC2ReportType.TYPE_1:
            return 1  # Design testing requires only 1 sample
        
        # Type 2 sample sizes based on control frequency
        sample_sizes = {
            "annual": 1,
            "quarterly": 2,
            "monthly": 3,
            "weekly": 5,
            "daily": 25,
            "multiple_daily": 25,
            "per_occurrence": 25,
            "continuous": 25
        }
        
        base_size = sample_sizes.get(frequency.lower(), 25)
        
        # Adjust for small populations
        if population_size < base_size:
            return population_size
        
        return base_size
    
    def to_dict(self) -> dict:
        return {
            "population_size": self.population_size,
            "sample_size": self.sample_size,
            "selection_method": self.selection_method,
            "items_tested": self.items_tested,
            "exceptions_found": self.exceptions_found,
            "exception_rate": self.exceptions_found / self.sample_size if self.sample_size > 0 else 0
        }


@dataclass
class EvidenceValidationResult:
    """Result of validating a single evidence item."""
    evidence_id: str
    evidence_type: str
    is_valid: bool
    score: float  # 0.0 to 1.0
    validation_details: dict[str, Any] = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)
    # Type 2 specific
    sample_selection: Optional[SampleSelection] = None
    period_coverage: Optional[dict] = None  # months covered by evidence


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
    # Type 2 specific
    testing_method: Optional[TestingMethod] = None
    sample_details: Optional[SampleSelection] = None
    
    def to_dict(self) -> dict:
        result = {
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
        if self.testing_method:
            result["testing_method"] = self.testing_method.value
        if self.sample_details:
            result["sample_details"] = self.sample_details.to_dict()
        return result


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
    # Type 1/Type 2 specific
    report_type: SOC2ReportType = SOC2ReportType.TYPE_2
    assessment_period: Optional[AssessmentPeriod] = None
    design_effectiveness: Optional[str] = None  # Type 1: Suitably designed
    operating_effectiveness: Optional[str] = None  # Type 2: Operating effectively
    testing_methods_used: list[TestingMethod] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        result = {
            "control_id": self.control_id,
            "control_title": self.control_title,
            "status": self.status.value,
            "score": self.score,
            "confidence": self.confidence,
            "evidence_gaps": self.evidence_gaps,
            "reasoning": self.reasoning,
            "assessed_at": self.assessed_at.isoformat(),
            "report_type": self.report_type.value,
            "findings": [f.to_dict() for f in self.findings],
            "evidence_validations": [
                {
                    "evidence_id": v.evidence_id,
                    "is_valid": v.is_valid,
                    "score": v.score,
                    "issues": v.issues
                }
                for v in self.evidence_validations
            ],
            "testing_methods_used": [m.value for m in self.testing_methods_used]
        }
        if self.assessment_period:
            result["assessment_period"] = self.assessment_period.to_dict()
        if self.design_effectiveness:
            result["design_effectiveness"] = self.design_effectiveness
        if self.operating_effectiveness:
            result["operating_effectiveness"] = self.operating_effectiveness
        return result


# =============================================================================
# MAIN COMPLIANCE CHECKER
# =============================================================================

class ComplianceChecker:
    """
    RAG-based compliance evaluation agent with SOC 2 Type 1/Type 2 support.
    
    Uses control definitions and scoring rubric to evaluate evidence
    against SOC 2 requirements. Implements strict anti-hallucination
    rules - every claim must cite specific evidence.
    
    Type 1 Assessment: Point-in-time evaluation of control DESIGN
    - Answers: "Is the control suitably designed?"
    - Evidence: Control descriptions, policies, procedures
    - Sample size: 1 (design documentation)
    
    Type 2 Assessment: Period-based evaluation of OPERATING EFFECTIVENESS
    - Answers: "Did the control operate effectively throughout the period?"
    - Evidence: Transaction samples, logs, tickets across the period
    - Sample size: 25 for daily controls, varies by frequency
    """
    
    # Type 2 minimum period (typically 6 months for initial, 12 for subsequent)
    MIN_TYPE_2_PERIOD_DAYS = 180
    
    def __init__(
        self,
        controls_path: Path,
        rubric_path: Path,
        evidence_manifest_path: Path,
        report_type: SOC2ReportType = SOC2ReportType.TYPE_2,
        assessment_period: Optional[AssessmentPeriod] = None
    ):
        self.controls = self._load_controls(controls_path)
        self.rubric = self._load_rubric(rubric_path)
        self.evidence_manifest = self._load_manifest(evidence_manifest_path)
        self.finding_counter = 0
        
        # SOC 2 Report Type configuration
        self.report_type = report_type
        self.assessment_period = assessment_period or self._default_assessment_period()
        
        # Validate Type 2 period
        if report_type == SOC2ReportType.TYPE_2:
            self._validate_type_2_period()
    
    def _default_assessment_period(self) -> AssessmentPeriod:
        """Create default assessment period based on report type."""
        now = datetime.utcnow()
        if self.report_type == SOC2ReportType.TYPE_1:
            # Point-in-time
            return AssessmentPeriod(start_date=now, end_date=now)
        else:
            # Type 2: Default 12-month period
            start = now - timedelta(days=365)
            return AssessmentPeriod(start_date=start, end_date=now)
    
    def _validate_type_2_period(self) -> None:
        """Validate that Type 2 assessment period meets minimum requirements."""
        if self.assessment_period.duration_days < self.MIN_TYPE_2_PERIOD_DAYS:
            raise ValueError(
                f"Type 2 assessment requires minimum {self.MIN_TYPE_2_PERIOD_DAYS} day period. "
                f"Current period: {self.assessment_period.duration_days} days"
            )
    
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
    
    def _get_evidence_for_control(self, control_id: str) -> list[dict]:
        """Get all evidence items mapped to a control."""
        evidence_items = []
        for evidence_id, evidence in self.evidence_manifest.get("evidence", {}).items():
            if control_id in evidence.get("control_ids", []):
                evidence_items.append(evidence)
            # Also check evidence_requirement_ids
            for req_id in evidence.get("evidence_requirement_ids", []):
                if req_id.startswith(control_id):
                    evidence_items.append(evidence)
                    break
        return evidence_items
    
    def _get_required_sample_size(self, control: dict, evidence_type: str) -> int:
        """
        Get required sample size based on report type and control frequency.
        """
        frequency = control.get("frequency", "daily")
        
        # Get population size from evidence manifest
        population_size = 100  # Default, would be calculated from actual data
        
        return SampleSelection.calculate_sample_size(
            population_size=population_size,
            frequency=frequency,
            report_type=self.report_type
        )
    
    def _validate_evidence(
        self,
        evidence: dict,
        requirement: dict
    ) -> EvidenceValidationResult:
        """
        Validate a single evidence item against requirements.
        
        Enhanced for Type 1/Type 2:
        - Type 1: Validates design documentation exists and is current
        - Type 2: Validates operating evidence covers the assessment period
        """
        issues = []
        score = 1.0
        sample_selection = None
        period_coverage = None
        
        # Basic freshness validation
        evidence_date_str = evidence.get("collected_at") or evidence.get("timestamp")
        if evidence_date_str:
            evidence_date = datetime.fromisoformat(evidence_date_str.replace('Z', '+00:00'))
            
            # For Type 2, evidence must fall within assessment period
            if self.report_type == SOC2ReportType.TYPE_2:
                if not self.assessment_period.contains(evidence_date):
                    issues.append(
                        f"Evidence dated {evidence_date.date()} falls outside "
                        f"assessment period ({self.assessment_period.start_date.date()} "
                        f"to {self.assessment_period.end_date.date()})"
                    )
                    score *= 0.3
        
        # Type-specific validation
        if self.report_type == SOC2ReportType.TYPE_1:
            # Type 1: Design effectiveness - need control documentation
            required_design_evidence = ["policy", "procedure", "control_description"]
            evidence_type = evidence.get("type", "").lower()
            if evidence_type not in required_design_evidence:
                issues.append(f"Type 1 requires design evidence (policy/procedure), got: {evidence_type}")
                score *= 0.7
                
        else:  # TYPE_2
            # Type 2: Operating effectiveness - need samples across period
            control_frequency = requirement.get("frequency", "daily")
            required_samples = SampleSelection.calculate_sample_size(
                population_size=100,  # Would be from actual data
                frequency=control_frequency,
                report_type=self.report_type
            )
            
            # Check if evidence includes sample information
            samples_provided = evidence.get("sample_count", 1)
            if samples_provided < required_samples:
                issues.append(
                    f"Type 2 requires {required_samples} samples for {control_frequency} control, "
                    f"only {samples_provided} provided"
                )
                score *= (samples_provided / required_samples)
            
            # Create sample selection record
            sample_selection = SampleSelection(
                population_size=evidence.get("population_size", 100),
                sample_size=samples_provided,
                selection_method=evidence.get("selection_method", "random"),
                items_tested=evidence.get("items_tested", []),
                exceptions_found=evidence.get("exceptions_found", 0)
            )
            
            # Check period coverage
            period_coverage = self._assess_period_coverage(evidence)
            if period_coverage.get("coverage_percentage", 0) < 80:
                issues.append(
                    f"Evidence covers only {period_coverage.get('coverage_percentage', 0):.0f}% "
                    f"of assessment period"
                )
                score *= 0.8
        
        # Freshness check
        freshness_days = requirement.get("freshness_window_days", 365)
        if evidence_date_str:
            age = (datetime.utcnow() - evidence_date).days
            if age > freshness_days:
                issues.append(f"Evidence is {age} days old, exceeds {freshness_days} day freshness window")
                score *= 0.5
        
        return EvidenceValidationResult(
            evidence_id=evidence.get("evidence_id", "unknown"),
            evidence_type=requirement.get("type", "unknown"),
            is_valid=score >= 0.6 and len(issues) == 0,
            score=score,
            validation_details={
                "report_type": self.report_type.value,
                "assessment_period": self.assessment_period.to_dict() if self.assessment_period else None
            },
            issues=issues,
            sample_selection=sample_selection,
            period_coverage=period_coverage
        )
    
    def _assess_period_coverage(self, evidence: dict) -> dict:
        """
        Assess how well evidence covers the assessment period.
        For Type 2, we need evidence spanning the entire period.
        """
        if not self.assessment_period:
            return {"coverage_percentage": 100, "months_covered": []}
        
        # Get evidence timestamps
        timestamps = evidence.get("timestamps", [])
        if not timestamps and evidence.get("collected_at"):
            timestamps = [evidence["collected_at"]]
        
        # Calculate months in assessment period
        total_months = self.assessment_period.duration_months
        
        # Track which months have evidence
        months_covered = set()
        for ts_str in timestamps:
            try:
                ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                if self.assessment_period.contains(ts):
                    months_covered.add((ts.year, ts.month))
            except (ValueError, AttributeError):
                continue
        
        coverage_percentage = (len(months_covered) / max(1, total_months)) * 100
        
        return {
            "coverage_percentage": min(100, coverage_percentage),
            "months_covered": list(months_covered),
            "total_months_required": total_months
        }
    
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
        
        Type 1: Based on design documentation
        Type 2: Based on operating evidence across period
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
        
        # Type 2 specific: Check for sample exceptions
        if self.report_type == SOC2ReportType.TYPE_2:
            total_exceptions = sum(
                v.sample_selection.exceptions_found 
                for v in validations 
                if v.sample_selection
            )
            if total_exceptions > 0:
                # Any exceptions in Type 2 testing is a finding
                return AssessmentStatus.FAIL
        
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
        # Would use LLM to detect semantic conflicts
        return False
    
    def _determine_testing_methods(self, control: dict) -> list[TestingMethod]:
        """
        Determine which testing methods to use based on control type.
        """
        methods = []
        control_type = control.get("control_type", "process")
        
        if self.report_type == SOC2ReportType.TYPE_1:
            # Type 1: Primarily inspection and inquiry
            methods = [TestingMethod.INSPECTION, TestingMethod.INQUIRY]
        else:
            # Type 2: All four methods may be needed
            if control_type == "automated":
                methods = [TestingMethod.INSPECTION, TestingMethod.REPERFORMANCE]
            elif control_type == "manual":
                methods = [TestingMethod.INSPECTION, TestingMethod.INQUIRY, TestingMethod.OBSERVATION]
            else:
                methods = [TestingMethod.INSPECTION, TestingMethod.INQUIRY]
        
        return methods
    
    def _generate_findings(
        self,
        control_id: str,
        control: dict,
        validations: list[EvidenceValidationResult],
        evidence_gaps: list[str]
    ) -> list[Finding]:
        """Generate findings based on validation results."""
        findings = []
        testing_methods = self._determine_testing_methods(control)
        
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
                recommendations=[f"Collect evidence for {gap}"],
                testing_method=TestingMethod.INSPECTION
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
                    recommendations=["Address evidence issues and re-collect"],
                    testing_method=testing_methods[0] if testing_methods else None,
                    sample_details=v.sample_selection
                ))
            
            # Type 2: Findings for sample exceptions
            if v.sample_selection and v.sample_selection.exceptions_found > 0:
                findings.append(Finding(
                    finding_id=self._generate_finding_id(),
                    control_id=control_id,
                    title=f"Sample Exception: {v.evidence_id}",
                    description=(
                        f"Found {v.sample_selection.exceptions_found} exception(s) "
                        f"in sample of {v.sample_selection.sample_size} items"
                    ),
                    status=AssessmentStatus.FAIL,
                    severity=FindingSeverity.HIGH,
                    evidence_refs=[v.evidence_id],
                    reasoning=(
                        f"Type 2 testing identified {v.sample_selection.exceptions_found} "
                        f"deviation(s) from expected control operation."
                    ),
                    recommendations=[
                        "Investigate root cause of exceptions",
                        "Implement corrective controls",
                        "Expand testing to assess extent of deviation"
                    ],
                    testing_method=TestingMethod.REPERFORMANCE,
                    sample_details=v.sample_selection
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
        
        # Type 2: Also consider period coverage
        if self.report_type == SOC2ReportType.TYPE_2:
            coverages = [
                v.period_coverage.get("coverage_percentage", 0) 
                for v in validations 
                if v.period_coverage
            ]
            if coverages:
                avg_coverage = sum(coverages) / len(coverages)
                if avg_coverage < 80:
                    return "LOW"
        
        if avg_score >= 0.9:
            return "HIGH"
        elif avg_score >= 0.7:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _determine_effectiveness(
        self,
        status: AssessmentStatus,
        score: float
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Determine design and operating effectiveness conclusions.
        
        Returns: (design_effectiveness, operating_effectiveness)
        """
        design_effectiveness = None
        operating_effectiveness = None
        
        if status == AssessmentStatus.PASS:
            if self.report_type == SOC2ReportType.TYPE_1:
                design_effectiveness = "Suitably designed"
            else:
                design_effectiveness = "Suitably designed"
                operating_effectiveness = "Operating effectively"
        elif status == AssessmentStatus.FAIL:
            if self.report_type == SOC2ReportType.TYPE_1:
                design_effectiveness = "Not suitably designed"
            else:
                design_effectiveness = "Design requires improvement"
                operating_effectiveness = "Not operating effectively"
        elif status in [AssessmentStatus.INSUFFICIENT_EVIDENCE, AssessmentStatus.EVIDENCE_GAP]:
            design_effectiveness = "Unable to conclude - insufficient evidence"
            if self.report_type == SOC2ReportType.TYPE_2:
                operating_effectiveness = "Unable to conclude - insufficient evidence"
        
        return design_effectiveness, operating_effectiveness
    
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
        
        # Report type context
        parts.append(f"Assessment Type: SOC 2 {self.report_type.value.replace('_', ' ').title()}")
        if self.assessment_period:
            parts.append(
                f"Assessment Period: {self.assessment_period.start_date.date()} "
                f"to {self.assessment_period.end_date.date()} "
                f"({self.assessment_period.duration_days} days)"
            )
        parts.append("")
        
        # List collected evidence
        collected = [v for v in validations if v.score > 0]
        if collected:
            parts.append(f"Assessed {control_id} using {len(collected)} evidence item(s):")
            for v in collected:
                line = f"  - [{v.evidence_id}]: score={v.score:.2f}"
                if v.sample_selection:
                    line += f" (samples: {v.sample_selection.sample_size}, exceptions: {v.sample_selection.exceptions_found})"
                parts.append(line)
        
        # Note gaps explicitly
        if evidence_gaps:
            parts.append(f"\nEvidence gaps ({len(evidence_gaps)} items not collected):")
            for gap in evidence_gaps:
                parts.append(f"  - {gap}: NOT COLLECTED")
        
        # Status reasoning
        parts.append(f"\nStatus: {status.value}")
        if status == AssessmentStatus.EVIDENCE_GAP:
            parts.append("Cannot make compliance determination without required evidence.")
        elif status == AssessmentStatus.PASS:
            if self.report_type == SOC2ReportType.TYPE_1:
                parts.append("Control is suitably designed based on collected evidence.")
            else:
                parts.append("Control operated effectively throughout the assessment period.")
        elif status == AssessmentStatus.INSUFFICIENT_EVIDENCE:
            parts.append("Evidence exists but does not fully satisfy control requirements.")
        elif status == AssessmentStatus.FAIL:
            if self.report_type == SOC2ReportType.TYPE_2:
                parts.append("Exceptions found during testing indicate control did not operate effectively.")
        
        return "\n".join(parts)
    
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
            req_id = req.get("evidence_id", req.get("id", "unknown"))
            matching_evidence = [
                e for e in collected_evidence
                if req_id in e.get("evidence_requirement_ids", [])
            ]
            
            if not matching_evidence:
                # Evidence gap - don't assume anything
                evidence_gaps.append(req_id)
                validations.append(EvidenceValidationResult(
                    evidence_id=req_id,
                    evidence_type=req.get("type", "unknown"),
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
        
        # Determine effectiveness conclusions
        design_eff, operating_eff = self._determine_effectiveness(status, score)
        
        # Build reasoning - must cite evidence
        reasoning = self._build_reasoning(control_id, validations, evidence_gaps, status)
        
        # Get testing methods used
        testing_methods = self._determine_testing_methods(control)
        
        return ControlAssessment(
            control_id=control_id,
            control_title=control.get("title", control_id),
            status=status,
            score=score,
            confidence=confidence,
            evidence_validations=validations,
            findings=findings,
            evidence_gaps=evidence_gaps,
            reasoning=reasoning,
            report_type=self.report_type,
            assessment_period=self.assessment_period,
            design_effectiveness=design_eff,
            operating_effectiveness=operating_eff,
            testing_methods_used=testing_methods
        )
    
    def assess_all_controls(self) -> dict[str, ControlAssessment]:
        """Assess all defined controls."""
        results = {}
        for control_id in self.controls.get("controls", {}).keys():
            results[control_id] = self.assess_control(control_id)
        return results
    
    def generate_report(self, assessments: dict[str, ControlAssessment]) -> dict:
        """Generate comprehensive SOC 2 Type 1 or Type 2 assessment report."""
        statuses = [a.status for a in assessments.values()]
        
        # Determine overall opinion
        if all(s == AssessmentStatus.PASS for s in statuses):
            overall_opinion = "Unqualified"
        elif any(s == AssessmentStatus.FAIL for s in statuses):
            overall_opinion = "Qualified" if sum(1 for s in statuses if s == AssessmentStatus.FAIL) <= 2 else "Adverse"
        elif any(s == AssessmentStatus.EVIDENCE_GAP for s in statuses):
            overall_opinion = "Scope Limitation"
        else:
            overall_opinion = "Qualified"
        
        report = {
            "report_type": f"SOC 2 {self.report_type.value.replace('_', ' ').title()}",
            "report_generated_at": datetime.utcnow().isoformat(),
            "framework": "SOC 2",
            "assessment_period": self.assessment_period.to_dict() if self.assessment_period else None,
            "overall_opinion": overall_opinion,
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
        
        # Type-specific report sections
        if self.report_type == SOC2ReportType.TYPE_1:
            report["management_assertion"] = (
                "Management asserts that the controls are suitably designed "
                f"as of {self.assessment_period.end_date.date()}"
            )
        else:
            report["management_assertion"] = (
                "Management asserts that the controls were suitably designed "
                f"and operated effectively throughout the period "
                f"{self.assessment_period.start_date.date()} to {self.assessment_period.end_date.date()}"
            )
            
            # Type 2: Include sample summary
            total_samples = sum(
                v.sample_selection.sample_size
                for a in assessments.values()
                for v in a.evidence_validations
                if v.sample_selection
            )
            total_exceptions = sum(
                v.sample_selection.exceptions_found
                for a in assessments.values()
                for v in a.evidence_validations
                if v.sample_selection
            )
            report["testing_summary"] = {
                "total_samples_tested": total_samples,
                "total_exceptions_found": total_exceptions,
                "exception_rate": total_exceptions / total_samples if total_samples > 0 else 0
            }
        
        return report


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_type_1_checker(
    controls_path: Path,
    rubric_path: Path,
    evidence_manifest_path: Path,
    as_of_date: Optional[datetime] = None
) -> ComplianceChecker:
    """Create a Type 1 (point-in-time) compliance checker."""
    as_of = as_of_date or datetime.utcnow()
    period = AssessmentPeriod(start_date=as_of, end_date=as_of)
    
    return ComplianceChecker(
        controls_path=controls_path,
        rubric_path=rubric_path,
        evidence_manifest_path=evidence_manifest_path,
        report_type=SOC2ReportType.TYPE_1,
        assessment_period=period
    )


def create_type_2_checker(
    controls_path: Path,
    rubric_path: Path,
    evidence_manifest_path: Path,
    start_date: datetime,
    end_date: datetime
) -> ComplianceChecker:
    """Create a Type 2 (period-based) compliance checker."""
    period = AssessmentPeriod(start_date=start_date, end_date=end_date)
    
    return ComplianceChecker(
        controls_path=controls_path,
        rubric_path=rubric_path,
        evidence_manifest_path=evidence_manifest_path,
        report_type=SOC2ReportType.TYPE_2,
        assessment_period=period
    )
