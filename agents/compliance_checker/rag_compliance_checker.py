"""
RAG-Enhanced Compliance Checker with Type 1/Type 2 SOC 2 Support

Merged implementation combining:
- rag_agent.py: Time-decay freshness scoring, forbidden words, evidence manifest
- rag_checker.py: Optional LLM with anti-hallucination override, evidence chains

Plus Type 1/Type 2 SOC 2 assessment methodology:
- Type 1: Point-in-time design effectiveness
- Type 2: Period-based operating effectiveness with sampling

Core Principle: "If you can't prove it, you can't claim it."
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import hashlib
import json
import re


# =============================================================================
# ENUMS
# =============================================================================

class AssessmentStatus(Enum):
    """Six valid assessment states - no ambiguity allowed."""
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
    """Confidence in assessment accuracy."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ReportType(Enum):
    """SOC 2 report types."""
    TYPE_1 = "type1"  # Point-in-time design effectiveness
    TYPE_2 = "type2"  # Period-based operating effectiveness


class TestingMethod(Enum):
    """Testing methods per AICPA standards."""
    INQUIRY = "inquiry"
    OBSERVATION = "observation"
    INSPECTION = "inspection"
    REPERFORMANCE = "reperformance"


# =============================================================================
# ANTI-HALLUCINATION CONFIGURATION
# =============================================================================

FORBIDDEN_WORDS = frozenset([
    "likely", "probably", "presumably", "seems to", "appears to",
    "might", "could be", "should have", "typically", "generally",
    "usually", "possibly", "perhaps", "maybe", "suggests",
    "implies", "may indicate", "assumed", "presumably"
])

# Evidence freshness scoring (time-decay)
FRESHNESS_THRESHOLDS = {
    0: 1.0,    # Fresh (within threshold)
    30: 0.7,   # 30 days stale
    90: 0.3,   # 90 days stale
    180: 0.1,  # 180 days stale
}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class AssessmentPeriod:
    """Defines the assessment period for Type 1 or Type 2 reports."""
    report_type: ReportType
    as_of_date: datetime  # Type 1: point-in-time date
    period_start: Optional[datetime] = None  # Type 2 only
    period_end: Optional[datetime] = None    # Type 2 only
    
    def __post_init__(self):
        if self.report_type == ReportType.TYPE_2:
            if not self.period_start or not self.period_end:
                raise ValueError("Type 2 reports require period_start and period_end")
            if self.period_start >= self.period_end:
                raise ValueError("period_start must be before period_end")
    
    @property
    def period_days(self) -> int:
        """Return assessment period length in days."""
        if self.report_type == ReportType.TYPE_1:
            return 0
        return (self.period_end - self.period_start).days
    
    def evidence_in_period(self, evidence_date: datetime) -> bool:
        """Check if evidence falls within assessment period."""
        if self.report_type == ReportType.TYPE_1:
            # Type 1: evidence must be as of or before the as_of_date
            return evidence_date <= self.as_of_date
        else:
            # Type 2: evidence must be within the period
            return self.period_start <= evidence_date <= self.period_end


@dataclass
class EvidenceReference:
    """Reference to a specific piece of evidence with provenance."""
    evidence_id: str
    source_file: str
    collected_at: datetime
    relevant_excerpt: str = ""
    confidence: float = 1.0
    hash: str = ""
    collector: str = ""
    scope: str = ""
    
    def __post_init__(self):
        if not self.hash and self.relevant_excerpt:
            self.hash = hashlib.sha256(
                self.relevant_excerpt.encode()
            ).hexdigest()[:12]


@dataclass
class EvidenceValidation:
    """Result of evidence validation."""
    evidence_id: str
    is_valid: bool
    freshness_score: float
    issues: list[str] = field(default_factory=list)
    in_period: bool = True  # For Type 2 assessments


@dataclass
class Finding:
    """A specific finding with mandatory evidence citations."""
    finding_id: str
    title: str
    description: str
    severity: FindingSeverity
    control_id: str
    evidence_refs: list[str]  # Must not be empty for FAIL findings
    remediation: str = ""
    cwe_id: Optional[int] = None
    owasp_category: str = ""
    
    def __post_init__(self):
        if self.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
            if not self.evidence_refs:
                raise ValueError(
                    f"Finding {self.finding_id}: Critical/High findings "
                    "must cite evidence"
                )


@dataclass
class SampleSelection:
    """Sample selection for Type 2 testing."""
    population_size: int
    sample_size: int
    selection_method: str  # "random", "judgmental", "haphazard"
    items_tested: list[str] = field(default_factory=list)
    exceptions_found: int = 0
    
    @classmethod
    def calculate_sample_size(cls, population: int) -> int:
        """
        Calculate sample size based on AICPA guidance.
        
        Population Size -> Sample Size:
        1-5: All items
        6-50: 5-10 items
        51-250: 10-25 items
        251-1000: 25-45 items
        1000+: 45-60 items
        """
        if population <= 5:
            return population
        elif population <= 50:
            return min(10, population)
        elif population <= 250:
            return 25
        elif population <= 1000:
            return 45
        else:
            return 60


@dataclass
class TestingResult:
    """Result of a specific test procedure."""
    test_id: str
    method: TestingMethod
    description: str
    performed_by: str
    performed_at: datetime
    evidence_refs: list[str]
    result: str  # "no_exceptions", "exception_noted", "not_tested"
    sample: Optional[SampleSelection] = None
    notes: str = ""


@dataclass
class ControlAssessment:
    """Complete assessment of a single control."""
    control_id: str
    control_title: str
    status: AssessmentStatus
    confidence: ConfidenceLevel
    score: float  # 0.0 to 1.0
    findings: list[Finding]
    evidence_refs: list[EvidenceReference]
    evidence_gaps: list[str]
    reasoning: str
    assessed_at: datetime = field(default_factory=datetime.utcnow)
    
    # Type 2 specific
    testing_results: list[TestingResult] = field(default_factory=list)
    sample_selection: Optional[SampleSelection] = None
    
    # Anti-hallucination tracking
    llm_overridden: bool = False
    original_llm_status: Optional[str] = None


@dataclass 
class ComplianceReport:
    """Complete compliance assessment report."""
    report_id: str
    framework: str
    report_type: ReportType
    assessment_period: AssessmentPeriod
    generated_at: datetime
    assessments: list[ControlAssessment]
    overall_status: AssessmentStatus
    summary: dict[str, Any]
    evidence_inventory: list[str]
    
    def to_dict(self) -> dict:
        """Convert report to dictionary."""
        return {
            "report_id": self.report_id,
            "framework": self.framework,
            "report_type": self.report_type.value,
            "assessment_period": {
                "type": self.assessment_period.report_type.value,
                "as_of_date": self.assessment_period.as_of_date.isoformat(),
                "period_start": (
                    self.assessment_period.period_start.isoformat()
                    if self.assessment_period.period_start else None
                ),
                "period_end": (
                    self.assessment_period.period_end.isoformat()
                    if self.assessment_period.period_end else None
                ),
                "period_days": self.assessment_period.period_days,
            },
            "generated_at": self.generated_at.isoformat(),
            "overall_status": self.overall_status.value,
            "summary": self.summary,
            "assessments": [
                {
                    "control_id": a.control_id,
                    "control_title": a.control_title,
                    "status": a.status.value,
                    "confidence": a.confidence.value,
                    "score": a.score,
                    "findings_count": len(a.findings),
                    "evidence_gaps": a.evidence_gaps,
                    "llm_overridden": a.llm_overridden,
                }
                for a in self.assessments
            ],
            "evidence_inventory": self.evidence_inventory,
        }


# =============================================================================
# RAG COMPLIANCE CHECKER
# =============================================================================

class RAGComplianceChecker:
    """
    RAG-enhanced compliance checker with Type 1/Type 2 support.
    
    Features:
    - RAG retrieval for control definitions and evidence
    - Optional LLM integration with anti-hallucination override
    - Time-decay freshness scoring
    - Forbidden words validation
    - Type 1 (point-in-time) and Type 2 (period-based) assessments
    - Sample size calculations for Type 2
    
    Core principle: No PASS without cited evidence.
    """
    
    def __init__(
        self,
        rag_pipeline: Optional[Any] = None,
        llm_client: Optional[Any] = None,
        evidence_store_path: Optional[Path] = None,
        framework_path: Optional[Path] = None,
        use_llm: bool = False,
    ):
        """
        Initialize the compliance checker.
        
        Args:
            rag_pipeline: RAG pipeline for semantic search (e.g., ComplianceRAGPipeline)
            llm_client: LLM client for enhanced assessment (optional)
            evidence_store_path: Path to evidence directory with manifest.json
            framework_path: Path to framework YAML files
            use_llm: Whether to use LLM for assessment (default: False)
        """
        self.rag_pipeline = rag_pipeline
        self.llm_client = llm_client
        self.evidence_store_path = evidence_store_path
        self.framework_path = framework_path
        self.use_llm = use_llm and llm_client is not None
        
        # Load evidence manifest if available
        self.evidence_manifest: dict[str, Any] = {}
        if evidence_store_path:
            self._load_evidence_manifest()
        
        # Load framework controls if available
        self.controls: dict[str, dict] = {}
        if framework_path:
            self._load_framework_controls()
    
    # =========================================================================
    # INITIALIZATION
    # =========================================================================
    
    def _load_evidence_manifest(self) -> None:
        """Load evidence manifest from evidence store."""
        manifest_path = self.evidence_store_path / "manifest.json"
        if manifest_path.exists():
            with open(manifest_path) as f:
                self.evidence_manifest = json.load(f)
    
    def _load_framework_controls(self) -> None:
        """Load control definitions from framework YAML files."""
        import yaml
        
        if not self.framework_path.exists():
            return
        
        for yaml_file in self.framework_path.glob("*.yaml"):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                    if "controls" in data:
                        for control_id, control_def in data["controls"].items():
                            self.controls[control_id] = control_def
            except Exception:
                continue
    
    # =========================================================================
    # EVIDENCE VALIDATION
    # =========================================================================
    
    def calculate_freshness_score(
        self,
        evidence_date: datetime,
        reference_date: datetime,
    ) -> float:
        """
        Calculate evidence freshness score with time-decay.
        
        Returns:
            Score from 0.0 (stale) to 1.0 (fresh)
        """
        age_days = (reference_date - evidence_date).days
        
        if age_days < 0:
            # Future-dated evidence is suspicious
            return 0.0
        
        # Find applicable threshold
        score = 0.0
        for threshold_days, threshold_score in sorted(FRESHNESS_THRESHOLDS.items()):
            if age_days <= threshold_days:
                return threshold_score
            score = threshold_score
        
        return score
    
    def validate_evidence(
        self,
        evidence: EvidenceReference,
        assessment_period: AssessmentPeriod,
        required_freshness_days: int = 90,
    ) -> EvidenceValidation:
        """
        Validate a piece of evidence against requirements.
        
        Checks:
        - Evidence exists and has content
        - Freshness meets requirements
        - Evidence falls within assessment period (Type 2)
        - Provenance is complete
        """
        issues = []
        
        # Check basic validity
        if not evidence.source_file:
            issues.append("Missing source file reference")
        
        if not evidence.relevant_excerpt and not evidence.hash:
            issues.append("No content or hash to verify")
        
        # Check freshness
        reference_date = (
            assessment_period.as_of_date
            if assessment_period.report_type == ReportType.TYPE_1
            else assessment_period.period_end
        )
        freshness_score = self.calculate_freshness_score(
            evidence.collected_at,
            reference_date
        )
        
        if freshness_score < 0.3:
            issues.append(f"Evidence is stale (freshness: {freshness_score:.1f})")
        
        # Check period alignment for Type 2
        in_period = True
        if assessment_period.report_type == ReportType.TYPE_2:
            in_period = assessment_period.evidence_in_period(evidence.collected_at)
            if not in_period:
                issues.append(
                    f"Evidence dated {evidence.collected_at.isoformat()} "
                    f"falls outside assessment period"
                )
        
        # Check provenance
        if not evidence.collector:
            issues.append("Missing collector information")
        
        return EvidenceValidation(
            evidence_id=evidence.evidence_id,
            is_valid=len(issues) == 0,
            freshness_score=freshness_score,
            issues=issues,
            in_period=in_period,
        )
    
    def check_forbidden_words(self, text: str) -> list[str]:
        """
        Check text for forbidden weasel words.
        
        Returns list of forbidden words found.
        """
        text_lower = text.lower()
        found = []
        for word in FORBIDDEN_WORDS:
            if word in text_lower:
                found.append(word)
        return found
    
    # =========================================================================
    # RAG RETRIEVAL
    # =========================================================================
    
    def retrieve_control_context(
        self,
        control_id: str,
        query: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Retrieve context for a control using RAG.
        
        Returns:
            Dictionary with control definition, requirements, and related content
        """
        context = {
            "control_definition": None,
            "requirements": [],
            "related_content": [],
            "evidence_requirements": [],
        }
        
        # Get from loaded controls first
        if control_id in self.controls:
            context["control_definition"] = self.controls[control_id]
            context["requirements"] = self.controls[control_id].get(
                "evidence_requirements", []
            )
        
        # Enhance with RAG retrieval
        if self.rag_pipeline:
            try:
                search_query = query or f"control {control_id} requirements evidence"
                results = self.rag_pipeline.retrieve(
                    query=search_query,
                    filter_metadata={"control_id": control_id},
                    top_k=5,
                )
                context["related_content"] = results
            except Exception:
                pass
        
        return context
    
    def retrieve_evidence_for_control(
        self,
        control_id: str,
        assessment_period: AssessmentPeriod,
    ) -> list[EvidenceReference]:
        """
        Retrieve evidence artifacts for a control.
        
        Returns evidence from manifest that matches the control and period.
        """
        evidence_list = []
        
        # Check evidence manifest
        for evidence_id, evidence_data in self.evidence_manifest.items():
            if control_id in evidence_data.get("controls", []):
                collected_at = datetime.fromisoformat(
                    evidence_data.get("collected_at", datetime.utcnow().isoformat())
                )
                
                evidence = EvidenceReference(
                    evidence_id=evidence_id,
                    source_file=evidence_data.get("source_file", ""),
                    collected_at=collected_at,
                    relevant_excerpt=evidence_data.get("excerpt", ""),
                    collector=evidence_data.get("collector", ""),
                    scope=evidence_data.get("scope", ""),
                )
                evidence_list.append(evidence)
        
        # Also check RAG pipeline for indexed evidence
        if self.rag_pipeline:
            try:
                results = self.rag_pipeline.retrieve(
                    query=f"evidence for {control_id}",
                    filter_metadata={"type": "evidence", "control_id": control_id},
                    top_k=10,
                )
                for result in results:
                    if result.get("evidence_id") not in [e.evidence_id for e in evidence_list]:
                        evidence_list.append(EvidenceReference(
                            evidence_id=result.get("evidence_id", f"RAG-{len(evidence_list)}"),
                            source_file=result.get("source", ""),
                            collected_at=datetime.fromisoformat(
                                result.get("date", datetime.utcnow().isoformat())
                            ),
                            relevant_excerpt=result.get("content", "")[:500],
                        ))
            except Exception:
                pass
        
        return evidence_list
    
    # =========================================================================
    # SAMPLE SIZE CALCULATION (TYPE 2)
    # =========================================================================
    
    def calculate_sample_selection(
        self,
        control_id: str,
        population_description: str,
        population_size: int,
    ) -> SampleSelection:
        """
        Calculate sample selection for Type 2 testing.
        
        Uses AICPA guidance for sample sizes based on population.
        """
        sample_size = SampleSelection.calculate_sample_size(population_size)
        
        return SampleSelection(
            population_size=population_size,
            sample_size=sample_size,
            selection_method="random" if population_size > 50 else "all_items",
        )
    
    # =========================================================================
    # LLM ASSESSMENT (OPTIONAL)
    # =========================================================================
    
    def _build_assessment_prompt(
        self,
        control_id: str,
        control_context: dict[str, Any],
        evidence_list: list[EvidenceReference],
        assessment_period: AssessmentPeriod,
    ) -> str:
        """Build prompt for LLM assessment."""
        
        # Format evidence for prompt
        evidence_text = "\n".join([
            f"- [{e.evidence_id}] {e.source_file}: {e.relevant_excerpt[:200]}..."
            for e in evidence_list
        ]) if evidence_list else "No evidence collected."
        
        period_text = (
            f"As of: {assessment_period.as_of_date.isoformat()}"
            if assessment_period.report_type == ReportType.TYPE_1
            else f"Period: {assessment_period.period_start.isoformat()} to {assessment_period.period_end.isoformat()}"
        )
        
        prompt = f"""Assess compliance for control {control_id}.

CONTROL DEFINITION:
{json.dumps(control_context.get('control_definition', {}), indent=2)}

ASSESSMENT PERIOD ({assessment_period.report_type.value.upper()}):
{period_text}

COLLECTED EVIDENCE:
{evidence_text}

REQUIREMENTS:
1. You MUST cite specific evidence IDs for any claims
2. You CANNOT claim PASS without evidence citations
3. Do NOT use words like: likely, probably, seems, appears, might, could be
4. If evidence is missing, status must be EVIDENCE_GAP or INSUFFICIENT_EVIDENCE

Respond in this exact format:
STATUS: [PASS|FAIL|INSUFFICIENT_EVIDENCE|EVIDENCE_GAP|NEEDS_MANUAL_REVIEW]
EVIDENCE_REFS: [comma-separated evidence IDs that support your assessment]
GAPS: [list any missing evidence]
REASONING: [your assessment reasoning with specific evidence citations]
"""
        return prompt
    
    def _call_llm(self, prompt: str) -> Optional[str]:
        """Call LLM with assessment prompt."""
        if not self.llm_client:
            return None
        
        try:
            # Assumes OpenAI-compatible client
            response = self.llm_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a compliance auditor. You must cite specific "
                            "evidence for all claims. Never claim PASS without "
                            "evidence citations. Never use uncertain language."
                        )
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # Low temperature for consistency
            )
            return response.choices[0].message.content
        except Exception as e:
            return None
    
    def _parse_llm_response(
        self,
        response: str,
    ) -> tuple[AssessmentStatus, list[str], list[str], str]:
        """
        Parse structured LLM response.
        
        Returns: (status, evidence_refs, gaps, reasoning)
        """
        status = AssessmentStatus.NEEDS_MANUAL_REVIEW
        evidence_refs = []
        gaps = []
        reasoning = ""
        
        # Parse STATUS
        status_match = re.search(r"STATUS:\s*(\w+)", response, re.IGNORECASE)
        if status_match:
            status_str = status_match.group(1).upper()
            try:
                status = AssessmentStatus(status_str)
            except ValueError:
                status = AssessmentStatus.NEEDS_MANUAL_REVIEW
        
        # Parse EVIDENCE_REFS
        refs_match = re.search(
            r"EVIDENCE_REFS:\s*\[?([^\]]+)\]?",
            response,
            re.IGNORECASE
        )
        if refs_match:
            refs_str = refs_match.group(1)
            evidence_refs = [
                r.strip() for r in refs_str.split(",")
                if r.strip() and r.strip().lower() != "none"
            ]
        
        # Parse GAPS
        gaps_match = re.search(r"GAPS:\s*\[?([^\]]+)\]?", response, re.IGNORECASE)
        if gaps_match:
            gaps_str = gaps_match.group(1)
            gaps = [
                g.strip() for g in gaps_str.split(",")
                if g.strip() and g.strip().lower() != "none"
            ]
        
        # Parse REASONING
        reasoning_match = re.search(
            r"REASONING:\s*(.+)",
            response,
            re.IGNORECASE | re.DOTALL
        )
        if reasoning_match:
            reasoning = reasoning_match.group(1).strip()
        
        return status, evidence_refs, gaps, reasoning
    
    def _apply_anti_hallucination_override(
        self,
        status: AssessmentStatus,
        evidence_refs: list[str],
        reasoning: str,
    ) -> tuple[AssessmentStatus, str, bool]:
        """
        Apply anti-hallucination override to LLM response.
        
        Rules:
        1. PASS without evidence citations → EVIDENCE_GAP
        2. Forbidden words in reasoning → flag for review
        
        Returns: (final_status, final_reasoning, was_overridden)
        """
        overridden = False
        final_status = status
        final_reasoning = reasoning
        
        # Rule 1: No PASS without evidence
        if status == AssessmentStatus.PASS and not evidence_refs:
            final_status = AssessmentStatus.EVIDENCE_GAP
            final_reasoning = (
                "OVERRIDE: LLM claimed PASS without citing evidence. "
                f"Original reasoning: {reasoning}"
            )
            overridden = True
        
        # Rule 2: Check for forbidden words
        forbidden_found = self.check_forbidden_words(reasoning)
        if forbidden_found and not overridden:
            final_reasoning = (
                f"WARNING: Uncertain language detected ({', '.join(forbidden_found)}). "
                f"Original: {reasoning}"
            )
            # Don't override status, but flag it
            if status == AssessmentStatus.PASS:
                final_status = AssessmentStatus.NEEDS_MANUAL_REVIEW
                overridden = True
        
        return final_status, final_reasoning, overridden
    
    # =========================================================================
    # CONTROL ASSESSMENT
    # =========================================================================
    
    def assess_control(
        self,
        control_id: str,
        assessment_period: AssessmentPeriod,
        testing_population: Optional[int] = None,
    ) -> ControlAssessment:
        """
        Assess a single control.
        
        Process:
        1. Retrieve control context via RAG
        2. Gather evidence for the control
        3. Validate evidence freshness and period alignment
        4. Optionally use LLM for assessment (with override)
        5. Apply rule-based assessment as fallback/verification
        6. Calculate sample sizes for Type 2
        7. Return assessment with findings
        
        Args:
            control_id: Control identifier (e.g., "CC6.1")
            assessment_period: Type 1 or Type 2 assessment period
            testing_population: Population size for Type 2 sampling
        
        Returns:
            ControlAssessment with status, findings, and evidence
        """
        # Step 1: Retrieve context
        control_context = self.retrieve_control_context(control_id)
        control_def = control_context.get("control_definition", {})
        control_title = control_def.get("title", control_id)
        
        # Step 2: Gather evidence
        evidence_list = self.retrieve_evidence_for_control(
            control_id, assessment_period
        )
        
        # Step 3: Validate evidence
        validations = []
        valid_evidence = []
        for evidence in evidence_list:
            validation = self.validate_evidence(evidence, assessment_period)
            validations.append(validation)
            if validation.is_valid:
                valid_evidence.append(evidence)
        
        # Determine evidence gaps
        required_evidence = control_context.get("requirements", [])
        if isinstance(required_evidence, dict):
            required_evidence = required_evidence.get("required_artifacts", [])
        
        collected_ids = {e.evidence_id for e in evidence_list}
        evidence_gaps = []
        for req in required_evidence:
            req_type = req.get("artifact_type", req) if isinstance(req, dict) else req
            if not any(req_type.lower() in eid.lower() for eid in collected_ids):
                evidence_gaps.append(req_type)
        
        # Step 4: Calculate sample for Type 2
        sample_selection = None
        if assessment_period.report_type == ReportType.TYPE_2 and testing_population:
            sample_selection = self.calculate_sample_selection(
                control_id,
                f"Testing population for {control_id}",
                testing_population,
            )
        
        # Step 5: Assess (LLM or rule-based)
        llm_overridden = False
        original_llm_status = None
        
        if self.use_llm and self.llm_client:
            # LLM assessment
            prompt = self._build_assessment_prompt(
                control_id, control_context, evidence_list, assessment_period
            )
            llm_response = self._call_llm(prompt)
            
            if llm_response:
                status, cited_refs, llm_gaps, reasoning = self._parse_llm_response(
                    llm_response
                )
                original_llm_status = status.value
                
                # Apply anti-hallucination override
                status, reasoning, llm_overridden = self._apply_anti_hallucination_override(
                    status, cited_refs, reasoning
                )
                
                # Merge gaps
                evidence_gaps = list(set(evidence_gaps + llm_gaps))
            else:
                # LLM failed, fall back to rule-based
                status, reasoning = self._rule_based_assessment(
                    control_id, valid_evidence, evidence_gaps, assessment_period
                )
        else:
            # Rule-based assessment only
            status, reasoning = self._rule_based_assessment(
                control_id, valid_evidence, evidence_gaps, assessment_period
            )
        
        # Step 6: Calculate confidence and score
        confidence = self._calculate_confidence(
            valid_evidence, evidence_gaps, validations
        )
        score = self._calculate_score(
            valid_evidence, evidence_gaps, validations, assessment_period
        )
        
        # Step 7: Generate findings
        findings = self._generate_findings(
            control_id, status, valid_evidence, evidence_gaps
        )
        
        return ControlAssessment(
            control_id=control_id,
            control_title=control_title,
            status=status,
            confidence=confidence,
            score=score,
            findings=findings,
            evidence_refs=valid_evidence,
            evidence_gaps=evidence_gaps,
            reasoning=reasoning,
            sample_selection=sample_selection,
            llm_overridden=llm_overridden,
            original_llm_status=original_llm_status,
        )
    
    def _rule_based_assessment(
        self,
        control_id: str,
        valid_evidence: list[EvidenceReference],
        evidence_gaps: list[str],
        assessment_period: AssessmentPeriod,
    ) -> tuple[AssessmentStatus, str]:
        """
        Perform rule-based assessment without LLM.
        
        Logic:
        - No evidence at all → EVIDENCE_GAP
        - Some evidence missing → INSUFFICIENT_EVIDENCE
        - All evidence present and valid → PASS
        - Evidence shows issues → FAIL
        """
        if not valid_evidence and evidence_gaps:
            return (
                AssessmentStatus.EVIDENCE_GAP,
                f"No evidence collected for {control_id}. "
                f"Required: {', '.join(evidence_gaps)}"
            )
        
        if not valid_evidence:
            return (
                AssessmentStatus.EVIDENCE_GAP,
                f"No valid evidence found for {control_id}"
            )
        
        if evidence_gaps:
            evidence_ids = [e.evidence_id for e in valid_evidence]
            return (
                AssessmentStatus.INSUFFICIENT_EVIDENCE,
                f"Partial evidence for {control_id}. "
                f"Collected: {', '.join(evidence_ids)}. "
                f"Missing: {', '.join(evidence_gaps)}"
            )
        
        # All evidence present
        evidence_ids = [e.evidence_id for e in valid_evidence]
        return (
            AssessmentStatus.PASS,
            f"Control {control_id} satisfied. "
            f"Evidence: {', '.join(evidence_ids)}"
        )
    
    def _calculate_confidence(
        self,
        valid_evidence: list[EvidenceReference],
        evidence_gaps: list[str],
        validations: list[EvidenceValidation],
    ) -> ConfidenceLevel:
        """Calculate confidence level for assessment."""
        if not valid_evidence:
            return ConfidenceLevel.LOW
        
        if evidence_gaps:
            if len(evidence_gaps) <= 1:
                return ConfidenceLevel.MEDIUM
            return ConfidenceLevel.LOW
        
        # Check validation results
        valid_count = sum(1 for v in validations if v.is_valid)
        if validations and valid_count == len(validations):
            return ConfidenceLevel.HIGH
        elif validations and valid_count >= len(validations) * 0.5:
            return ConfidenceLevel.MEDIUM
        
        return ConfidenceLevel.LOW
    
    def _calculate_score(
        self,
        valid_evidence: list[EvidenceReference],
        evidence_gaps: list[str],
        validations: list[EvidenceValidation],
        assessment_period: AssessmentPeriod,
    ) -> float:
        """
        Calculate numeric score for control (0.0 to 1.0).
        
        Components:
        - Evidence completeness (40%)
        - Evidence freshness (30%)
        - Period alignment for Type 2 (30%)
        """
        if not valid_evidence and not evidence_gaps:
            return 0.0
        
        # Evidence completeness
        total_required = len(valid_evidence) + len(evidence_gaps)
        completeness = len(valid_evidence) / total_required if total_required > 0 else 0.0
        
        # Average freshness
        if validations:
            avg_freshness = sum(v.freshness_score for v in validations) / len(validations)
        else:
            avg_freshness = 0.0
        
        # Period alignment (Type 2)
        if assessment_period.report_type == ReportType.TYPE_2 and validations:
            in_period_count = sum(1 for v in validations if v.in_period)
            period_alignment = in_period_count / len(validations)
        else:
            period_alignment = 1.0  # Type 1 doesn't have period alignment
        
        # Weighted score
        score = (
            completeness * 0.4 +
            avg_freshness * 0.3 +
            period_alignment * 0.3
        )
        
        return round(score, 2)
    
    def _generate_findings(
        self,
        control_id: str,
        status: AssessmentStatus,
        valid_evidence: list[EvidenceReference],
        evidence_gaps: list[str],
    ) -> list[Finding]:
        """Generate findings based on assessment results."""
        findings = []
        
        if status == AssessmentStatus.FAIL:
            findings.append(Finding(
                finding_id=f"{control_id}-F001",
                title=f"Control {control_id} Failed",
                description=f"Assessment determined control {control_id} is not operating effectively",
                severity=FindingSeverity.HIGH,
                control_id=control_id,
                evidence_refs=[e.evidence_id for e in valid_evidence],
                remediation="Review control implementation and address deficiencies",
            ))
        
        elif status == AssessmentStatus.EVIDENCE_GAP:
            findings.append(Finding(
                finding_id=f"{control_id}-G001",
                title=f"Evidence Gap for {control_id}",
                description=f"Required evidence not collected: {', '.join(evidence_gaps)}",
                severity=FindingSeverity.MEDIUM,
                control_id=control_id,
                evidence_refs=[],  # No evidence to cite
                remediation="Collect required evidence artifacts",
            ))
        
        elif status == AssessmentStatus.INSUFFICIENT_EVIDENCE:
            findings.append(Finding(
                finding_id=f"{control_id}-I001",
                title=f"Insufficient Evidence for {control_id}",
                description=f"Partial evidence collected. Missing: {', '.join(evidence_gaps)}",
                severity=FindingSeverity.MEDIUM,
                control_id=control_id,
                evidence_refs=[e.evidence_id for e in valid_evidence],
                remediation="Collect additional evidence to complete assessment",
            ))
        
        return findings
    
    # =========================================================================
    # FULL ASSESSMENT
    # =========================================================================
    
    def assess(
        self,
        control_ids: list[str],
        assessment_period: AssessmentPeriod,
        testing_populations: Optional[dict[str, int]] = None,
    ) -> ComplianceReport:
        """
        Assess multiple controls and generate compliance report.
        
        Args:
            control_ids: List of control IDs to assess
            assessment_period: Type 1 or Type 2 assessment period
            testing_populations: Dict of control_id → population size for Type 2
        
        Returns:
            ComplianceReport with all assessments
        """
        testing_populations = testing_populations or {}
        assessments = []
        
        for control_id in control_ids:
            population = testing_populations.get(control_id)
            assessment = self.assess_control(
                control_id,
                assessment_period,
                testing_population=population,
            )
            assessments.append(assessment)
        
        # Calculate overall status
        overall_status = self._determine_overall_status(assessments)
        
        # Build summary
        summary = self._build_summary(assessments, assessment_period)
        
        # Gather evidence inventory
        evidence_inventory = list({
            e.evidence_id
            for a in assessments
            for e in a.evidence_refs
        })
        
        report_id = (
            f"SOC2-{assessment_period.report_type.value.upper()}-"
            f"{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        )
        
        return ComplianceReport(
            report_id=report_id,
            framework="SOC2",
            report_type=assessment_period.report_type,
            assessment_period=assessment_period,
            generated_at=datetime.utcnow(),
            assessments=assessments,
            overall_status=overall_status,
            summary=summary,
            evidence_inventory=evidence_inventory,
        )
    
    def _determine_overall_status(
        self,
        assessments: list[ControlAssessment],
    ) -> AssessmentStatus:
        """
        Determine overall compliance status.
        
        Rules:
        - Any FAIL → FAIL
        - >20% EVIDENCE_GAP → INSUFFICIENT_EVIDENCE
        - All PASS → PASS
        - Otherwise → NEEDS_MANUAL_REVIEW
        """
        if not assessments:
            return AssessmentStatus.EVIDENCE_GAP
        
        status_counts = {}
        for a in assessments:
            status_counts[a.status] = status_counts.get(a.status, 0) + 1
        
        # Any failure
        if status_counts.get(AssessmentStatus.FAIL, 0) > 0:
            return AssessmentStatus.FAIL
        
        # Too many gaps
        gap_count = (
            status_counts.get(AssessmentStatus.EVIDENCE_GAP, 0) +
            status_counts.get(AssessmentStatus.INSUFFICIENT_EVIDENCE, 0)
        )
        if gap_count / len(assessments) > 0.2:
            return AssessmentStatus.INSUFFICIENT_EVIDENCE
        
        # All pass
        if status_counts.get(AssessmentStatus.PASS, 0) == len(assessments):
            return AssessmentStatus.PASS
        
        # Manual review needed
        if status_counts.get(AssessmentStatus.NEEDS_MANUAL_REVIEW, 0) > 0:
            return AssessmentStatus.NEEDS_MANUAL_REVIEW
        
        # Passed with some exceptions
        return AssessmentStatus.PASS
    
    def _build_summary(
        self,
        assessments: list[ControlAssessment],
        assessment_period: AssessmentPeriod,
    ) -> dict[str, Any]:
        """Build summary statistics for report."""
        status_counts = {}
        for a in assessments:
            status_counts[a.status.value] = status_counts.get(a.status.value, 0) + 1
        
        severity_counts = {}
        for a in assessments:
            for f in a.findings:
                severity_counts[f.severity.value] = severity_counts.get(
                    f.severity.value, 0
                ) + 1
        
        llm_overrides = sum(1 for a in assessments if a.llm_overridden)
        
        avg_score = (
            sum(a.score for a in assessments) / len(assessments)
            if assessments else 0.0
        )
        
        return {
            "total_controls": len(assessments),
            "status_breakdown": status_counts,
            "severity_breakdown": severity_counts,
            "average_score": round(avg_score, 2),
            "llm_overrides": llm_overrides,
            "report_type": assessment_period.report_type.value,
            "period_days": assessment_period.period_days,
            "total_findings": sum(len(a.findings) for a in assessments),
            "total_evidence_gaps": sum(len(a.evidence_gaps) for a in assessments),
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_type1_assessment(
    as_of_date: Optional[datetime] = None,
) -> AssessmentPeriod:
    """Create a Type 1 (point-in-time) assessment period."""
    return AssessmentPeriod(
        report_type=ReportType.TYPE_1,
        as_of_date=as_of_date or datetime.utcnow(),
    )


def create_type2_assessment(
    period_start: datetime,
    period_end: datetime,
) -> AssessmentPeriod:
    """Create a Type 2 (period-based) assessment period."""
    return AssessmentPeriod(
        report_type=ReportType.TYPE_2,
        as_of_date=period_end,
        period_start=period_start,
        period_end=period_end,
    )


def create_checker(
    evidence_path: Optional[Path] = None,
    framework_path: Optional[Path] = None,
    use_llm: bool = False,
    llm_client: Optional[Any] = None,
) -> RAGComplianceChecker:
    """
    Factory function to create a compliance checker.
    
    Args:
        evidence_path: Path to evidence directory
        framework_path: Path to framework YAML files
        use_llm: Whether to enable LLM assessment
        llm_client: LLM client (required if use_llm=True)
    
    Returns:
        Configured RAGComplianceChecker instance
    """
    return RAGComplianceChecker(
        evidence_store_path=evidence_path,
        framework_path=framework_path,
        use_llm=use_llm,
        llm_client=llm_client,
    )


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    # Example: Type 1 Assessment
    print("=== Type 1 Assessment Example ===")
    
    checker = create_checker(
        evidence_path=Path("./evidence"),
        framework_path=Path("./frameworks/soc2"),
        use_llm=False,  # Rule-based only
    )
    
    period_type1 = create_type1_assessment(
        as_of_date=datetime(2025, 1, 13)
    )
    
    controls = ["CC6.1", "CC6.6", "CC7.1"]
    report = checker.assess(controls, period_type1)
    
    print(f"Report ID: {report.report_id}")
    print(f"Overall Status: {report.overall_status.value}")
    print(f"Summary: {json.dumps(report.summary, indent=2)}")
    
    # Example: Type 2 Assessment
    print("\n=== Type 2 Assessment Example ===")
    
    period_type2 = create_type2_assessment(
        period_start=datetime(2024, 10, 1),
        period_end=datetime(2024, 12, 31),
    )
    
    # Type 2 with testing populations
    populations = {
        "CC6.1": 500,   # 500 access requests to sample
        "CC6.6": 100,   # 100 vulnerability scans
        "CC7.1": 10000, # 10000 log entries
    }
    
    report_type2 = checker.assess(
        controls,
        period_type2,
        testing_populations=populations,
    )
    
    print(f"Report ID: {report_type2.report_id}")
    print(f"Period: {report_type2.assessment_period.period_days} days")
    print(f"Overall Status: {report_type2.overall_status.value}")
    
    # Print sample selections
    for assessment in report_type2.assessments:
        if assessment.sample_selection:
            print(f"\n{assessment.control_id} Sample:")
            print(f"  Population: {assessment.sample_selection.population_size}")
            print(f"  Sample Size: {assessment.sample_selection.sample_size}")
