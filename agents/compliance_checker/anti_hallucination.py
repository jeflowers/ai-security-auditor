"""
Anti-Hallucination Framework for Compliance Assessments.

Implements the "If you can't prove it, you can't claim it" principle.
Ensures all compliance claims are backed by verifiable evidence.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import re
import hashlib


def utc_now() -> datetime:
    """Get current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


class AssessmentState(Enum):
    """Bounded assessment states - no ambiguous intermediate states."""
    PASS = "pass"
    FAIL = "fail"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    EVIDENCE_GAP = "evidence_gap"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"
    # Legacy states for backward compatibility
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_ASSESSED = "not_assessed"


class ConfidenceLevel(Enum):
    """Confidence levels for assessments."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class EvidenceType(Enum):
    """Types of evidence that can support compliance claims."""
    LOG_ARTIFACT = "log_artifact"
    SCAN_RESULT = "scan_result"
    CODE_ANALYSIS = "code_analysis"
    CONFIGURATION = "configuration"
    POLICY_DOCUMENT = "policy_document"
    INTERVIEW_RECORD = "interview_record"
    SCREENSHOT = "screenshot"
    API_RESPONSE = "api_response"


@dataclass
class EvidenceProvenance:
    """Tracks the provenance chain for evidence."""
    evidence_id: str
    source: str
    source_type: str
    collected_at: datetime
    collector: str
    content_hash: str
    chain: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    
    def add_to_chain(self, step: str) -> None:
        """Add a step to the provenance chain."""
        self.chain.append(f"{utc_now().isoformat()}: {step}")


def create_evidence_provenance(
    evidence_id: str,
    source: str,
    source_type: str,
    collector: str,
    content: str,
    metadata: dict = None
) -> EvidenceProvenance:
    """Factory function to create evidence provenance."""
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    return EvidenceProvenance(
        evidence_id=evidence_id,
        source=source,
        source_type=source_type,
        collected_at=utc_now(),
        collector=collector,
        content_hash=content_hash,
        metadata=metadata or {}
    )


@dataclass
class Evidence:
    """Immutable evidence record with full provenance tracking."""
    evidence_id: str
    evidence_type: EvidenceType
    source: str
    collected_at: datetime
    content_hash: str
    summary: str
    raw_content: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    provenance: Optional[EvidenceProvenance] = None
    
    def __post_init__(self):
        """Validate evidence on creation."""
        if not self.evidence_id:
            raise ValueError("Evidence must have an ID")
        if not self.source:
            raise ValueError("Evidence must have a source")
        if not self.content_hash:
            raise ValueError("Evidence must have a content hash")
    
    @classmethod
    def create(cls, evidence_type: EvidenceType, source: str, 
               content: str, summary: str, metadata: dict = None) -> "Evidence":
        """Factory method to create evidence with automatic hashing."""
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        evidence_id = f"EVD-{content_hash[:12]}"
        return cls(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            source=source,
            collected_at=utc_now(),
            content_hash=content_hash,
            summary=summary,
            raw_content=content,
            metadata=metadata or {}
        )


@dataclass
class ValidationResult:
    """Result of anti-hallucination validation."""
    is_valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.NONE
    validated_at: datetime = field(default_factory=utc_now)
    
    def add_error(self, error: str) -> None:
        """Add an error to the result."""
        self.errors.append(error)
        self.is_valid = False
    
    def add_warning(self, warning: str) -> None:
        """Add a warning to the result."""
        self.warnings.append(warning)


@dataclass
class ComplianceClaim:
    """A compliance claim that must be backed by evidence."""
    claim_id: str
    control_id: str
    statement: str
    assessment_state: AssessmentState
    evidence_ids: list[str] = field(default_factory=list)
    reasoning: str = ""
    assessed_at: Optional[datetime] = None
    assessor: str = "ai-security-auditor"
    confidence: ConfidenceLevel = ConfidenceLevel.NONE
    
    def is_valid(self) -> bool:
        """Check if claim has required evidence backing."""
        if self.assessment_state in (AssessmentState.PASS, AssessmentState.COMPLIANT):
            return len(self.evidence_ids) > 0
        if self.assessment_state in (AssessmentState.FAIL, AssessmentState.NON_COMPLIANT):
            return len(self.evidence_ids) > 0
        return True  # Other states don't require evidence


class WeaselWordDetector:
    """Detects prohibited hedging language in compliance statements."""
    
    FORBIDDEN_PATTERNS = [
        r'\blikely\b',
        r'\bprobably\b',
        r'\bpossibly\b',
        r'\bmight\b',
        r'\bcould be\b',
        r'\bshould be\b',
        r'\bappears to\b',
        r'\bseems to\b',
        r'\bbelieved to\b',
        r'\bassumed\b',
        r'\bpresumably\b',
        r'\bgenerally\b',
        r'\btypically\b',
        r'\busually\b',
        r'\boften\b',
        r'\bsometimes\b',
        r'\bmay\b',
        r'\bmostly\b',
        r'\blargely\b',
        r'\bpartially\b',
        r'\bsomewhat\b',
        r'\broughly\b',
        r'\bapproximately\b',
        r'\babout\b(?!\s+this)',  # "about" but not "about this"
        r'\baround\b(?!\s+the)',  # "around" but not "around the"
        r'\bnearly\b',
        r'\balmost\b',
        r'\bin most cases\b',
        r'\bfor the most part\b',
        r'\bto some extent\b',
        r'\bit seems\b',
        r'\bone could argue\b',
        r'\bit is thought\b',
        r'\bit is believed\b',
    ]
    
    def __init__(self):
        self._compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.FORBIDDEN_PATTERNS
        ]
    
    def detect(self, text: str) -> list[dict]:
        """
        Detect weasel words in text.
        
        Returns:
            List of detected violations with pattern and location.
        """
        violations = []
        for pattern in self._compiled_patterns:
            for match in pattern.finditer(text):
                violations.append({
                    "pattern": pattern.pattern,
                    "matched_text": match.group(),
                    "start": match.start(),
                    "end": match.end(),
                    "context": text[max(0, match.start()-20):match.end()+20]
                })
        return violations
    
    def is_clean(self, text: str) -> bool:
        """Check if text is free of weasel words."""
        return len(self.detect(text)) == 0


class EvidenceRequirementChecker:
    """Validates that claims have sufficient evidence backing."""
    
    # Minimum evidence requirements by claim type
    MIN_EVIDENCE_BY_STATE = {
        AssessmentState.PASS: 1,
        AssessmentState.FAIL: 1,
        AssessmentState.COMPLIANT: 1,
        AssessmentState.NON_COMPLIANT: 1,
        AssessmentState.NOT_ASSESSED: 0,
        AssessmentState.INSUFFICIENT_EVIDENCE: 0,
        AssessmentState.EVIDENCE_GAP: 0,
        AssessmentState.CONFLICTING_EVIDENCE: 1,
        AssessmentState.NEEDS_MANUAL_REVIEW: 0,
    }
    
    def __init__(self, evidence_registry: dict[str, Evidence] = None):
        self.evidence_registry = evidence_registry or {}
    
    def register_evidence(self, evidence: Evidence) -> None:
        """Add evidence to the registry."""
        self.evidence_registry[evidence.evidence_id] = evidence
    
    def validate_claim(self, claim: ComplianceClaim) -> tuple[bool, list[str]]:
        """
        Validate that a claim has sufficient evidence.
        
        Returns:
            Tuple of (is_valid, list of validation errors)
        """
        errors = []
        
        # Check minimum evidence requirement
        min_required = self.MIN_EVIDENCE_BY_STATE.get(claim.assessment_state, 1)
        if len(claim.evidence_ids) < min_required:
            errors.append(
                f"Claim requires at least {min_required} evidence items, "
                f"but has {len(claim.evidence_ids)}"
            )
        
        # Verify all evidence IDs exist in registry
        for eid in claim.evidence_ids:
            if eid not in self.evidence_registry:
                errors.append(f"Evidence ID '{eid}' not found in registry")
        
        # Ensure reasoning is provided for non-trivial states
        if claim.assessment_state in (AssessmentState.PASS, AssessmentState.FAIL,
                                       AssessmentState.COMPLIANT, AssessmentState.NON_COMPLIANT):
            if not claim.reasoning or len(claim.reasoning.strip()) < 10:
                errors.append("Claims must include substantive reasoning")
        
        return len(errors) == 0, errors


class AntiHallucinationValidator:
    """
    Main validator combining all anti-hallucination checks.
    
    Implements the five fundamental rules:
    1. CITE_OR_ABSTAIN - Every compliance claim must cite specific evidence
    2. CONFIDENCE_SCORING - Evidence must be verifiable artifacts
    3. NO_WEASEL_WORDS - Assessment states must be bounded
    4. SCOPE_BOUNDARY - No inference from missing evidence
    5. PROVENANCE_CHAIN - Explicit mapping between findings and claims
    """
    
    def __init__(self):
        self.weasel_detector = WeaselWordDetector()
        self.evidence_checker = EvidenceRequirementChecker()
        self.validation_errors: list[dict] = []
    
    def register_evidence(self, evidence: Evidence) -> None:
        """Register evidence for validation."""
        self.evidence_checker.register_evidence(evidence)
    
    def validate_claim(self, claim: ComplianceClaim) -> ValidationResult:
        """
        Perform full validation on a compliance claim.
        
        Returns:
            ValidationResult with is_valid status and any errors.
        """
        result = ValidationResult(is_valid=True)
        
        # Rule 1: Check for weasel words in statement
        statement_violations = self.weasel_detector.detect(claim.statement)
        if statement_violations:
            for v in statement_violations:
                result.add_error(
                    f"Weasel word detected in statement: '{v['matched_text']}'"
                )
        
        # Rule 1: Check for weasel words in reasoning
        if claim.reasoning:
            reasoning_violations = self.weasel_detector.detect(claim.reasoning)
            if reasoning_violations:
                for v in reasoning_violations:
                    result.add_error(
                        f"Weasel word detected in reasoning: '{v['matched_text']}'"
                    )
        
        # Rule 2 & 5: Validate evidence requirements
        is_valid, evidence_errors = self.evidence_checker.validate_claim(claim)
        for error in evidence_errors:
            result.add_error(error)
        
        # Rule 3: Validate assessment state is bounded
        if claim.assessment_state not in AssessmentState:
            result.add_error(f"Invalid assessment state: {claim.assessment_state}")
        
        # Rule 4: Prevent inference from missing evidence
        if (claim.assessment_state in (AssessmentState.PASS, AssessmentState.COMPLIANT) and 
            not claim.evidence_ids):
            result.add_error(
                "Cannot claim COMPLIANT/PASS status without supporting evidence"
            )
        
        # Set confidence level based on validation
        if result.is_valid:
            if len(claim.evidence_ids) >= 3:
                result.confidence = ConfidenceLevel.HIGH
            elif len(claim.evidence_ids) >= 1:
                result.confidence = ConfidenceLevel.MEDIUM
            else:
                result.confidence = ConfidenceLevel.LOW
        
        # Store errors for reporting
        if not result.is_valid:
            self.validation_errors.append({
                "claim_id": claim.claim_id,
                "control_id": claim.control_id,
                "errors": result.errors,
                "timestamp": utc_now().isoformat()
            })
        
        return result
    
    def validate(self, claim: ComplianceClaim) -> ValidationResult:
        """Alias for validate_claim for backward compatibility."""
        return self.validate_claim(claim)
    
    def validate_assessment_report(self, claims: list[ComplianceClaim]) -> dict:
        """
        Validate an entire assessment report.
        
        Returns:
            Validation summary with pass/fail status and details.
        """
        results = {
            "total_claims": len(claims),
            "valid_claims": 0,
            "invalid_claims": 0,
            "claim_results": [],
            "overall_valid": True,
            "validated_at": utc_now().isoformat()
        }
        
        for claim in claims:
            validation_result = self.validate_claim(claim)
            results["claim_results"].append({
                "claim_id": claim.claim_id,
                "control_id": claim.control_id,
                "is_valid": validation_result.is_valid,
                "errors": validation_result.errors
            })
            
            if validation_result.is_valid:
                results["valid_claims"] += 1
            else:
                results["invalid_claims"] += 1
                results["overall_valid"] = False
        
        return results
    
    def get_validation_errors(self) -> list[dict]:
        """Get all validation errors encountered."""
        return self.validation_errors.copy()
    
    def clear_errors(self) -> None:
        """Clear stored validation errors."""
        self.validation_errors.clear()


# Alias for backward compatibility
AssessmentValidator = AntiHallucinationValidator


class ComplianceStatementBuilder:
    """
    Helper to build compliant statements without weasel words.
    
    Provides templates and guidance for creating evidence-backed claims.
    """
    
    COMPLIANT_TEMPLATES = {
        "control_implemented": (
            "Control {control_id} is implemented. "
            "Evidence: {evidence_summary}. "
            "Verification method: {verification_method}."
        ),
        "control_not_implemented": (
            "Control {control_id} is not implemented. "
            "Finding: {finding}. "
            "Evidence: {evidence_summary}."
        ),
        "partial_implementation": (
            "Control {control_id} implementation is incomplete. "
            "Implemented aspects: {implemented}. "
            "Missing aspects: {missing}. "
            "Evidence: {evidence_summary}."
        ),
        "not_assessed": (
            "Control {control_id} was not assessed. "
            "Reason: {reason}."
        ),
        "insufficient_evidence": (
            "Control {control_id} assessment requires additional evidence. "
            "Available evidence: {available}. "
            "Required evidence: {required}."
        ),
    }
    
    def __init__(self):
        self.weasel_detector = WeaselWordDetector()
    
    def build_compliant_statement(self, template_name: str, **kwargs) -> str:
        """Build a statement using an approved template."""
        if template_name not in self.COMPLIANT_TEMPLATES:
            raise ValueError(f"Unknown template: {template_name}")
        
        statement = self.COMPLIANT_TEMPLATES[template_name].format(**kwargs)
        
        # Validate the built statement
        if not self.weasel_detector.is_clean(statement):
            violations = self.weasel_detector.detect(statement)
            raise ValueError(
                f"Generated statement contains weasel words: "
                f"{[v['matched_text'] for v in violations]}"
            )
        
        return statement
    
    def validate_custom_statement(self, statement: str) -> tuple[bool, list[str]]:
        """Validate a custom statement for weasel words."""
        violations = self.weasel_detector.detect(statement)
        if violations:
            return False, [v['matched_text'] for v in violations]
        return True, []


class ProvenanceTracker:
    """
    Tracks the full provenance chain of compliance assessments.
    
    Maps: Finding -> Evidence -> Control -> Framework
    """
    
    def __init__(self):
        self.mappings: dict[str, dict] = {}
        self.chains: list[dict] = []
    
    def add_mapping(self, finding_id: str, evidence_id: str, 
                    control_id: str, framework: str) -> None:
        """Add a provenance mapping."""
        mapping = {
            "finding_id": finding_id,
            "evidence_id": evidence_id,
            "control_id": control_id,
            "framework": framework,
            "created_at": utc_now().isoformat()
        }
        
        key = f"{finding_id}:{evidence_id}:{control_id}"
        self.mappings[key] = mapping
        self.chains.append(mapping)
    
    def get_evidence_for_finding(self, finding_id: str) -> list[str]:
        """Get all evidence IDs associated with a finding."""
        return [
            m["evidence_id"] for m in self.chains 
            if m["finding_id"] == finding_id
        ]
    
    def get_controls_for_evidence(self, evidence_id: str) -> list[str]:
        """Get all control IDs that cite specific evidence."""
        return list(set(
            m["control_id"] for m in self.chains 
            if m["evidence_id"] == evidence_id
        ))
    
    def get_full_chain(self, finding_id: str) -> list[dict]:
        """Get complete provenance chain for a finding."""
        return [m for m in self.chains if m["finding_id"] == finding_id]
    
    def validate_chain_completeness(self) -> tuple[bool, list[str]]:
        """Ensure all chains have complete mappings."""
        errors = []
        for mapping in self.chains:
            if not mapping.get("finding_id"):
                errors.append("Mapping missing finding_id")
            if not mapping.get("evidence_id"):
                errors.append("Mapping missing evidence_id")
            if not mapping.get("control_id"):
                errors.append("Mapping missing control_id")
            if not mapping.get("framework"):
                errors.append("Mapping missing framework")
        
        return len(errors) == 0, errors
    
    def export_provenance_report(self) -> dict:
        """Export full provenance data for audit trail."""
        return {
            "total_mappings": len(self.mappings),
            "chains": self.chains,
            "exported_at": utc_now().isoformat()
        }
