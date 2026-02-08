"""
HIPAA Security Rule Framework Module

Provides loading and assessment functionality for HIPAA compliance.
Part of the AI-Powered Security Auditor multi-framework support.

Usage:
    from frameworks.hipaa import HIPAAFramework
    
    framework = HIPAAFramework()
    controls = framework.get_controls_by_category("Technical Safeguards")
    mapping = framework.map_cwe_to_controls(311)  # Missing Encryption
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
import yaml


class HIPAACategory(Enum):
    """HIPAA Security Rule categories."""
    ADMINISTRATIVE = "Administrative Safeguards"
    PHYSICAL = "Physical Safeguards"
    TECHNICAL = "Technical Safeguards"
    ORGANIZATIONAL = "Organizational Requirements"
    POLICIES = "Policies and Procedures"
    BREACH = "Breach Notification"


class SpecificationStatus(Enum):
    """HIPAA implementation specification status."""
    REQUIRED = "Required"
    ADDRESSABLE = "Addressable"


class AssessmentState(Enum):
    """Valid HIPAA assessment states per anti-hallucination framework."""
    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class EvidenceRequirement:
    """Evidence requirement for a HIPAA control."""
    id: str
    description: str
    artifact_types: list[str]
    required: bool


@dataclass
class ImplementationSpec:
    """HIPAA implementation specification."""
    id: str
    title: str
    status: SpecificationStatus
    description: str


@dataclass
class HIPAAControl:
    """HIPAA Security Rule control definition."""
    id: str
    title: str
    regulation_ref: str
    category: HIPAACategory
    status: SpecificationStatus
    description: str
    implementation_specs: list[ImplementationSpec] = field(default_factory=list)
    evidence_requirements: list[EvidenceRequirement] = field(default_factory=list)
    testing_procedures: list[str] = field(default_factory=list)
    related_cwe_ids: list[int] = field(default_factory=list)


@dataclass
class ControlAssessment:
    """Assessment result for a HIPAA control."""
    control_id: str
    state: AssessmentState
    evidence_ids: list[str]
    findings: list[str]
    recommendations: list[str]
    spec_assessments: dict[str, AssessmentState] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "control_id": self.control_id,
            "state": self.state.value,
            "evidence_ids": self.evidence_ids,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "spec_assessments": {
                k: v.value for k, v in self.spec_assessments.items()
            }
        }


class HIPAAFramework:
    """
    HIPAA Security Rule framework for compliance assessment.
    
    Loads control definitions and scoring rules from YAML configuration.
    Provides mapping utilities for CWE and OWASP to HIPAA controls.
    """
    
    def __init__(self, framework_dir: Path | None = None):
        """
        Initialize HIPAA framework.
        
        Args:
            framework_dir: Path to framework YAML files.
                          Defaults to ./frameworks/hipaa
        """
        if framework_dir is None:
            framework_dir = Path(__file__).parent
        
        self.framework_dir = Path(framework_dir)
        self._controls: dict[str, HIPAAControl] = {}
        self._cwe_mapping: dict[int, list[str]] = {}
        self._owasp_mapping: dict[str, list[str]] = {}
        self._prohibited_phrases: list[str] = []
        self._loaded = False
    
    def _load(self) -> None:
        """Load framework configuration from YAML files."""
        if self._loaded:
            return
        
        controls_file = self.framework_dir / "controls.yaml"
        rubric_file = self.framework_dir / "scoring_rubric.yaml"
        
        if controls_file.exists():
            self._load_controls(controls_file)
        
        if rubric_file.exists():
            self._load_rubric(rubric_file)
        
        self._loaded = True
    
    def _load_controls(self, controls_file: Path) -> None:
        """Load control definitions from YAML."""
        with open(controls_file, 'r') as f:
            data = yaml.safe_load(f)
        
        # Load controls
        for control_id, control_data in data.get("controls", {}).items():
            category = HIPAACategory(control_data.get("category"))
            status = SpecificationStatus(control_data.get("status", "Required"))
            
            # Parse implementation specifications
            impl_specs = []
            for spec_data in control_data.get("implementation_specifications", []):
                impl_specs.append(ImplementationSpec(
                    id=spec_data["id"],
                    title=spec_data["title"],
                    status=SpecificationStatus(spec_data["status"]),
                    description=spec_data["description"]
                ))
            
            # Parse evidence requirements
            evidence_reqs = []
            for ev_data in control_data.get("evidence_requirements", []):
                evidence_reqs.append(EvidenceRequirement(
                    id=ev_data["id"],
                    description=ev_data["description"],
                    artifact_types=ev_data.get("artifact_types", []),
                    required=ev_data.get("required", True)
                ))
            
            self._controls[control_id] = HIPAAControl(
                id=control_id,
                title=control_data["title"],
                regulation_ref=control_data["regulation_ref"],
                category=category,
                status=status,
                description=control_data["description"],
                implementation_specs=impl_specs,
                evidence_requirements=evidence_reqs,
                testing_procedures=control_data.get("testing_procedures", []),
                related_cwe_ids=control_data.get("related_cwe_ids", [])
            )
        
        # Load CWE mapping
        for cwe_id, mapping_data in data.get("cwe_mapping", {}).items():
            cwe_num = int(cwe_id.replace("CWE-", ""))
            self._cwe_mapping[cwe_num] = mapping_data.get("controls", [])
        
        # Load OWASP mapping
        for owasp_id, mapping_data in data.get("owasp_mapping", {}).items():
            self._owasp_mapping[owasp_id] = mapping_data.get("controls", [])
    
    def _load_rubric(self, rubric_file: Path) -> None:
        """Load scoring rubric from YAML."""
        with open(rubric_file, 'r') as f:
            data = yaml.safe_load(f)
        
        # Load prohibited phrases
        for rule in data.get("fundamental_rules", []):
            if rule.get("id") == "HIPAA-FR-005":
                phrases = rule.get("prohibited_phrases", {})
                for category_phrases in phrases.values():
                    if isinstance(category_phrases, list):
                        self._prohibited_phrases.extend(category_phrases)
    
    # =========================================================================
    # Control Access Methods
    # =========================================================================
    
    def get_control(self, control_id: str) -> HIPAAControl | None:
        """Get a specific control by ID."""
        self._load()
        return self._controls.get(control_id)
    
    def get_all_controls(self) -> list[HIPAAControl]:
        """Get all HIPAA controls."""
        self._load()
        return list(self._controls.values())
    
    def get_controls_by_category(
        self, 
        category: HIPAACategory | str
    ) -> list[HIPAAControl]:
        """Get controls for a specific category."""
        self._load()
        
        if isinstance(category, str):
            category = HIPAACategory(category)
        
        return [
            c for c in self._controls.values()
            if c.category == category
        ]
    
    def get_required_controls(self) -> list[HIPAAControl]:
        """Get all controls with Required status."""
        self._load()
        return [
            c for c in self._controls.values()
            if c.status == SpecificationStatus.REQUIRED
        ]
    
    def get_addressable_controls(self) -> list[HIPAAControl]:
        """Get all controls with Addressable specifications."""
        self._load()
        return [
            c for c in self._controls.values()
            if any(s.status == SpecificationStatus.ADDRESSABLE 
                   for s in c.implementation_specs)
        ]
    
    # =========================================================================
    # Mapping Methods
    # =========================================================================
    
    def map_cwe_to_controls(self, cwe_id: int) -> list[str]:
        """
        Map a CWE ID to relevant HIPAA controls.
        
        Args:
            cwe_id: CWE identifier (e.g., 311 for Missing Encryption)
        
        Returns:
            List of HIPAA control IDs
        """
        self._load()
        return self._cwe_mapping.get(cwe_id, [])
    
    def map_owasp_to_controls(self, owasp_id: str) -> list[str]:
        """
        Map an OWASP Top 10 category to HIPAA controls.
        
        Args:
            owasp_id: OWASP identifier (e.g., "A01:2021-Broken Access Control")
        
        Returns:
            List of HIPAA control IDs
        """
        self._load()
        return self._owasp_mapping.get(owasp_id, [])
    
    def get_controls_for_finding(
        self,
        cwe_id: int | None = None,
        owasp_category: str | None = None
    ) -> list[HIPAAControl]:
        """
        Get HIPAA controls relevant to a security finding.
        
        Args:
            cwe_id: Optional CWE identifier
            owasp_category: Optional OWASP category
        
        Returns:
            List of relevant HIPAAControl objects
        """
        self._load()
        
        control_ids = set()
        
        if cwe_id:
            control_ids.update(self.map_cwe_to_controls(cwe_id))
        
        if owasp_category:
            control_ids.update(self.map_owasp_to_controls(owasp_category))
        
        return [
            self._controls[cid] 
            for cid in control_ids 
            if cid in self._controls
        ]
    
    # =========================================================================
    # Anti-Hallucination Validation
    # =========================================================================
    
    def get_prohibited_phrases(self) -> list[str]:
        """Get list of prohibited phrases for assessments."""
        self._load()
        return self._prohibited_phrases.copy()
    
    def validate_assessment_text(self, text: str) -> tuple[bool, list[str]]:
        """
        Validate assessment text for prohibited phrases.
        
        Args:
            text: Assessment text to validate
        
        Returns:
            Tuple of (is_valid, list of violations found)
        """
        self._load()
        
        text_lower = text.lower()
        violations = []
        
        for phrase in self._prohibited_phrases:
            if phrase.lower() in text_lower:
                violations.append(phrase)
        
        return len(violations) == 0, violations
    
    def validate_evidence_citation(self, text: str) -> bool:
        """
        Validate that assessment text contains proper evidence citation.
        
        Args:
            text: Assessment text to validate
        
        Returns:
            True if evidence citation pattern is found
        """
        import re
        
        # Look for evidence ID pattern: [HIPAA-XX-XXX.XX-E#-...]
        pattern = r'\[HIPAA-[A-Z]{2}-\d{3}\.[a-z0-9]+(?:\.[ivx]+)?-E\d+[^\]]*\]'
        return bool(re.search(pattern, text))
    
    # =========================================================================
    # Assessment Helpers
    # =========================================================================
    
    def get_evidence_requirements_for_control(
        self, 
        control_id: str
    ) -> list[EvidenceRequirement]:
        """Get evidence requirements for a control."""
        control = self.get_control(control_id)
        if control:
            return control.evidence_requirements
        return []
    
    def create_assessment(
        self,
        control_id: str,
        state: AssessmentState,
        evidence_ids: list[str],
        findings: list[str],
        recommendations: list[str] | None = None
    ) -> ControlAssessment:
        """
        Create a validated control assessment.
        
        Args:
            control_id: HIPAA control ID
            state: Assessment state
            evidence_ids: List of evidence artifact IDs
            findings: List of finding descriptions
            recommendations: Optional remediation recommendations
        
        Returns:
            ControlAssessment object
        
        Raises:
            ValueError: If control doesn't exist or validation fails
        """
        self._load()
        
        if control_id not in self._controls:
            raise ValueError(f"Unknown control: {control_id}")
        
        # Validate findings text
        for finding in findings:
            is_valid, violations = self.validate_assessment_text(finding)
            if not is_valid:
                raise ValueError(
                    f"Finding contains prohibited phrases: {violations}"
                )
        
        # Validate evidence citation for non-gap states
        if state not in [AssessmentState.EVIDENCE_GAP, AssessmentState.NOT_APPLICABLE]:
            if not evidence_ids:
                raise ValueError(
                    f"State {state.value} requires evidence citations"
                )
        
        return ControlAssessment(
            control_id=control_id,
            state=state,
            evidence_ids=evidence_ids,
            findings=findings,
            recommendations=recommendations or []
        )
    
    # =========================================================================
    # Reporting
    # =========================================================================
    
    def get_framework_summary(self) -> dict[str, Any]:
        """Get summary of the HIPAA framework."""
        self._load()
        
        by_category = {}
        for category in HIPAACategory:
            controls = self.get_controls_by_category(category)
            by_category[category.value] = {
                "count": len(controls),
                "control_ids": [c.id for c in controls]
            }
        
        return {
            "framework": "HIPAA Security Rule",
            "total_controls": len(self._controls),
            "by_category": by_category,
            "cwe_mappings": len(self._cwe_mapping),
            "owasp_mappings": len(self._owasp_mapping),
            "prohibited_phrases": len(self._prohibited_phrases)
        }


# Convenience functions
def load_hipaa_framework(framework_dir: Path | None = None) -> HIPAAFramework:
    """Load and return HIPAA framework instance."""
    return HIPAAFramework(framework_dir)


def map_finding_to_hipaa(
    cwe_id: int | None = None,
    owasp_category: str | None = None,
    framework_dir: Path | None = None
) -> list[str]:
    """
    Map a security finding to HIPAA control IDs.
    
    Args:
        cwe_id: CWE identifier
        owasp_category: OWASP Top 10 category
        framework_dir: Optional path to framework files
    
    Returns:
        List of HIPAA control IDs
    """
    framework = HIPAAFramework(framework_dir)
    controls = framework.get_controls_for_finding(cwe_id, owasp_category)
    return [c.id for c in controls]


if __name__ == "__main__":
    # Quick test
    framework = HIPAAFramework()
    summary = framework.get_framework_summary()
    
    print("HIPAA Security Rule Framework")
    print("=" * 50)
    print(f"Total Controls: {summary['total_controls']}")
    print(f"CWE Mappings: {summary['cwe_mappings']}")
    print(f"OWASP Mappings: {summary['owasp_mappings']}")
    print(f"Prohibited Phrases: {summary['prohibited_phrases']}")
    print()
    print("Controls by Category:")
    for category, data in summary['by_category'].items():
        print(f"  {category}: {data['count']} controls")
