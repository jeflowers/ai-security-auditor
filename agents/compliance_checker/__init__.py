"""
Compliance Checker Agent

Three implementations available:
1. ComplianceChecker - Rule-based checker (no RAG)
2. RAGComplianceChecker - RAG-enhanced checker with vector search
3. AntiHallucinationValidator - Validation framework for all findings

Anti-Hallucination Framework:
- All findings must pass validation before being added to audit state
- 5 core rules: CITE_OR_ABSTAIN, CONFIDENCE_SCORING, NO_WEASEL_WORDS, 
  SCOPE_BOUNDARY, PROVENANCE_CHAIN
- 6 valid assessment states only: PASS, FAIL, INSUFFICIENT_EVIDENCE,
  EVIDENCE_GAP, CONFLICTING_EVIDENCE, NEEDS_MANUAL_REVIEW
"""

from .agent import (
    ComplianceChecker,
    ControlAssessment,
    Finding,
    AssessmentStatus,
    FindingSeverity,
    EvidenceValidationResult,
)

from .anti_hallucination import (
    AntiHallucinationValidator,
    AssessmentState,
    ConfidenceLevel,
    EvidenceProvenance,
    ValidationResult,
    create_evidence_provenance,
)

# Try to import RAG checker (optional dependency)
try:
    from .rag_compliance_checker import (
        RAGComplianceChecker,
    )
    _HAS_RAG = True
except ImportError:
    _HAS_RAG = False
    RAGComplianceChecker = None

__all__ = [
    # Original checker
    "ComplianceChecker",
    "ControlAssessment",
    "Finding",
    "AssessmentStatus",
    "FindingSeverity",
    "EvidenceValidationResult",
    
    # Anti-hallucination framework
    "AntiHallucinationValidator",
    "AssessmentState",
    "ConfidenceLevel",
    "EvidenceProvenance",
    "ValidationResult",
    "create_evidence_provenance",
    
    # RAG-enhanced checker (if available)
    "RAGComplianceChecker",
]
