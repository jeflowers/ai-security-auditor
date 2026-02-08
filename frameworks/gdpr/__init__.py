"""
GDPR (General Data Protection Regulation) Framework

Implements GDPR compliance assessment based on EU Regulation 2016/679.

Chapters covered:
- Chapter II: Principles (Articles 5-11)
- Chapter III: Rights of Data Subject (Articles 12-23)
- Chapter IV: Controller and Processor (Articles 24-43)
- Chapter V: Transfers to Third Countries (Articles 44-50)

Usage:
    from frameworks.gdpr import GDPRFramework
    
    framework = GDPRFramework()
    controls = framework.get_controls()
    article = framework.get_control("ART5.1a")
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml


FRAMEWORK_DIR = Path(__file__).parent


@dataclass
class GDPRControl:
    """Represents a GDPR article/control with evidence requirements."""
    id: str
    article: str
    title: str
    chapter: str
    description: str
    keywords: list[str] = field(default_factory=list)
    evidence_requirements: list[dict[str, Any]] = field(default_factory=list)
    assessment_criteria: dict[str, str] = field(default_factory=dict)
    related_controls: list[str] = field(default_factory=list)
    severity_if_fail: str = "medium"


@dataclass
class GDPRFramework:
    """GDPR (General Data Protection Regulation) compliance framework."""
    
    id: str = "GDPR"
    name: str = "General Data Protection Regulation"
    version: str = "2016/679"
    jurisdiction: str = "European Union"
    effective_date: str = "2018-05-25"
    
    def __post_init__(self):
        self._controls: dict[str, GDPRControl] = {}
        self._scoring_rubric: dict[str, Any] = {}
        self._load_controls()
        self._load_scoring_rubric()
    
    def _load_controls(self) -> None:
        """Load controls from YAML file."""
        controls_file = FRAMEWORK_DIR / "controls.yaml"
        if controls_file.exists():
            with open(controls_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if data and 'controls' in data:
                for control_data in data['controls']:
                    control_id = control_data.get('id', '')
                    self._controls[control_id] = GDPRControl(
                        id=control_id,
                        article=control_data.get('article', ''),
                        title=control_data.get('title', ''),
                        chapter=control_data.get('chapter', ''),
                        description=control_data.get('description', ''),
                        keywords=control_data.get('keywords', []),
                        evidence_requirements=control_data.get('evidence_requirements', []),
                        assessment_criteria=control_data.get('assessment_criteria', {}),
                        related_controls=control_data.get('related_controls', []),
                        severity_if_fail=control_data.get('severity_if_fail', 'medium'),
                    )
    
    def _load_scoring_rubric(self) -> None:
        """Load scoring rubric from YAML file."""
        rubric_file = FRAMEWORK_DIR / "scoring_rubric.yaml"
        if rubric_file.exists():
            with open(rubric_file, 'r') as f:
                self._scoring_rubric = yaml.safe_load(f) or {}
    
    def get_controls(self) -> dict[str, GDPRControl]:
        """Get all controls."""
        return self._controls
    
    def get_control(self, control_id: str) -> GDPRControl | None:
        """Get a specific control by ID."""
        return self._controls.get(control_id)
    
    def get_scoring_rubric(self) -> dict[str, Any]:
        """Get the scoring rubric with anti-hallucination rules."""
        return self._scoring_rubric
    
    def get_control_ids(self) -> list[str]:
        """Get list of all control IDs."""
        return list(self._controls.keys())
    
    def get_controls_by_chapter(self, chapter: str) -> list[GDPRControl]:
        """Get controls filtered by chapter."""
        return [
            c for c in self._controls.values()
            if chapter.lower() in c.chapter.lower()
        ]
    
    def get_controls_by_severity(self, severity: str) -> list[GDPRControl]:
        """Get controls filtered by failure severity."""
        return [
            c for c in self._controls.values()
            if c.severity_if_fail.lower() == severity.lower()
        ]
    
    def get_evidence_requirements(self, control_id: str) -> list[dict[str, Any]]:
        """Get evidence requirements for a specific control."""
        control = self.get_control(control_id)
        if control:
            return control.evidence_requirements
        return []
    
    def search_controls_by_keyword(self, keyword: str) -> list[GDPRControl]:
        """Search controls by keyword."""
        keyword_lower = keyword.lower()
        return [
            c for c in self._controls.values()
            if any(keyword_lower in kw.lower() for kw in c.keywords)
        ]
    
    def validate_assessment_state(self, state: str) -> bool:
        """
        Validate that an assessment state is one of the six valid states.
        
        Anti-hallucination rule: Only these states are permitted.
        """
        valid_states = {
            'PASS',
            'FAIL',
            'INSUFFICIENT_EVIDENCE',
            'EVIDENCE_GAP',
            'CONFLICTING_EVIDENCE',
            'NEEDS_MANUAL_REVIEW'
        }
        return state.upper() in valid_states
    
    def get_forbidden_phrases(self) -> list[str]:
        """
        Get list of forbidden 'weasel words' that cannot appear in assessments.
        
        Anti-hallucination rule: These phrases indicate uncertainty
        and are prohibited in compliance assessments.
        """
        return [
            "likely", "probably", "possibly",
            "appears to be", "seems to", "suggests",
            "may indicate", "could be", "might",
            "presumably", "apparently", "evidently"
        ]
    
    def get_data_subject_rights(self) -> list[GDPRControl]:
        """Get all data subject rights controls (Chapter III)."""
        return self.get_controls_by_chapter("Rights of Data Subject")
    
    def get_security_controls(self) -> list[GDPRControl]:
        """Get security-related controls (Article 32, 33, 34)."""
        security_ids = ["ART32", "ART33", "ART34"]
        return [
            self._controls[cid] for cid in security_ids
            if cid in self._controls
        ]


# CWE to GDPR Control Mapping
CWE_TO_GDPR_MAPPING: dict[int, list[str]] = {
    # Security of Processing (ART32)
    311: ["ART5.1f", "ART32"],  # Missing Encryption
    319: ["ART5.1f", "ART32"],  # Cleartext Transmission
    327: ["ART5.1f", "ART32"],  # Broken Cryptography
    
    # Access Control
    287: ["ART5.1f", "ART32"],  # Improper Authentication
    306: ["ART5.1f", "ART32"],  # Missing Authentication
    798: ["ART5.1f", "ART32"],  # Hardcoded Credentials
    
    # Logging (Accountability)
    778: ["ART5.2", "ART30"],   # Insufficient Logging
    
    # Data Protection
    359: ["ART5.1f"],          # Privacy Violation
    200: ["ART5.1f", "ART32"], # Information Exposure
}

# OWASP Top 10 to GDPR Control Mapping
OWASP_TO_GDPR_MAPPING: dict[str, list[str]] = {
    "A01:2021-Broken Access Control": ["ART5.1f", "ART32"],
    "A02:2021-Cryptographic Failures": ["ART5.1f", "ART32"],
    "A03:2021-Injection": ["ART5.1f", "ART32"],
    "A04:2021-Insecure Design": ["ART25", "ART32"],
    "A05:2021-Security Misconfiguration": ["ART32"],
    "A06:2021-Vulnerable Components": ["ART32"],
    "A07:2021-Auth Failures": ["ART5.1f", "ART32"],
    "A08:2021-Integrity Failures": ["ART5.1f", "ART32"],
    "A09:2021-Logging Failures": ["ART5.2", "ART30", "ART33"],
    "A10:2021-SSRF": ["ART32"],
}


def get_gdpr_controls_for_cwe(cwe_id: int) -> list[str]:
    """Map a CWE ID to relevant GDPR controls."""
    return CWE_TO_GDPR_MAPPING.get(cwe_id, [])


def get_gdpr_controls_for_owasp(owasp_category: str) -> list[str]:
    """Map an OWASP category to relevant GDPR controls."""
    return OWASP_TO_GDPR_MAPPING.get(owasp_category, [])


__all__ = [
    "GDPRFramework",
    "GDPRControl",
    "CWE_TO_GDPR_MAPPING",
    "OWASP_TO_GDPR_MAPPING",
    "get_gdpr_controls_for_cwe",
    "get_gdpr_controls_for_owasp",
]
