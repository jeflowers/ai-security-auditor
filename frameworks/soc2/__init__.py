"""
SOC 2 Trust Services Criteria Framework

Implements SOC 2 compliance assessment based on AICPA Trust Services Criteria.

Controls covered:
- CC6: Logical and Physical Access Controls
- CC7: System Operations  
- CC8: Change Management
- CC9: Risk Mitigation

Usage:
    from frameworks.soc2 import SOC2Framework
    
    framework = SOC2Framework()
    controls = framework.get_controls()
    rubric = framework.get_scoring_rubric()
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml


FRAMEWORK_DIR = Path(__file__).parent


@dataclass
class SOC2Control:
    """Represents a SOC 2 control with evidence requirements."""
    id: str
    title: str
    description: str
    category: str
    subcategory: str
    evidence_plan: dict[str, Any] = field(default_factory=dict)
    scoring_rubric: dict[str, Any] = field(default_factory=dict)


@dataclass
class SOC2Framework:
    """SOC 2 Trust Services Criteria compliance framework."""
    
    id: str = "SOC2"
    name: str = "SOC 2 Trust Services Criteria"
    version: str = "2017"
    
    def __post_init__(self):
        self._controls: dict[str, SOC2Control] = {}
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
                for control_id, control_data in data['controls'].items():
                    self._controls[control_id] = SOC2Control(
                        id=control_id,
                        title=control_data.get('title', ''),
                        description=control_data.get('description', ''),
                        category=control_data.get('category', ''),
                        subcategory=control_data.get('subcategory', ''),
                        evidence_plan=control_data.get('evidence_plan', {}),
                        scoring_rubric=control_data.get('scoring_rubric', {}),
                    )
    
    def _load_scoring_rubric(self) -> None:
        """Load scoring rubric from YAML file."""
        rubric_file = FRAMEWORK_DIR / "scoring_rubric.yaml"
        if rubric_file.exists():
            with open(rubric_file, 'r') as f:
                self._scoring_rubric = yaml.safe_load(f) or {}
    
    def get_controls(self) -> dict[str, SOC2Control]:
        """Get all controls."""
        return self._controls
    
    def get_control(self, control_id: str) -> SOC2Control | None:
        """Get a specific control by ID."""
        return self._controls.get(control_id)
    
    def get_scoring_rubric(self) -> dict[str, Any]:
        """Get the scoring rubric with anti-hallucination rules."""
        return self._scoring_rubric
    
    def get_control_ids(self) -> list[str]:
        """Get list of all control IDs."""
        return list(self._controls.keys())
    
    def get_controls_by_category(self, category: str) -> list[SOC2Control]:
        """Get controls filtered by category (CC, A, PI, C, P)."""
        return [
            c for c in self._controls.values()
            if c.category == category
        ]
    
    def get_evidence_requirements(self, control_id: str) -> list[dict[str, Any]]:
        """Get evidence requirements for a specific control."""
        control = self.get_control(control_id)
        if control and control.evidence_plan:
            return control.evidence_plan.get('required_evidence', [])
        return []
    
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


# CWE to SOC 2 Control Mapping
CWE_TO_SOC2_MAPPING: dict[int, list[str]] = {
    # Access Control (CC6.x)
    287: ["CC6.1"],  # Improper Authentication
    306: ["CC6.1"],  # Missing Authentication
    798: ["CC6.1"],  # Hardcoded Credentials
    522: ["CC6.1"],  # Insufficiently Protected Credentials
    
    # External Threats (CC6.6)
    89: ["CC6.6"],   # SQL Injection
    79: ["CC6.6"],   # XSS
    78: ["CC6.6"],   # OS Command Injection
    94: ["CC6.6"],   # Code Injection
    
    # Data Protection (CC6.7)
    311: ["CC6.7"],  # Missing Encryption
    319: ["CC6.7"],  # Cleartext Transmission
    327: ["CC6.7"],  # Broken Cryptography
    
    # Logging/Monitoring (CC7.x)
    778: ["CC7.1", "CC7.2"],  # Insufficient Logging
    117: ["CC7.2"],  # Log Injection
    
    # Change Management (CC8.1)
    494: ["CC8.1"],  # Download Without Integrity Check
}

# OWASP Top 10 to SOC 2 Control Mapping
OWASP_TO_SOC2_MAPPING: dict[str, list[str]] = {
    "A01:2021-Broken Access Control": ["CC6.1", "CC6.2", "CC6.3"],
    "A02:2021-Cryptographic Failures": ["CC6.7"],
    "A03:2021-Injection": ["CC6.6"],
    "A04:2021-Insecure Design": ["CC8.1", "CC9.1"],
    "A05:2021-Security Misconfiguration": ["CC6.6", "CC8.1"],
    "A06:2021-Vulnerable Components": ["CC6.6", "CC8.1"],
    "A07:2021-Auth Failures": ["CC6.1"],
    "A08:2021-Integrity Failures": ["CC8.1"],
    "A09:2021-Logging Failures": ["CC7.1", "CC7.2"],
    "A10:2021-SSRF": ["CC6.6"],
}


def get_soc2_controls_for_cwe(cwe_id: int) -> list[str]:
    """Map a CWE ID to relevant SOC 2 controls."""
    return CWE_TO_SOC2_MAPPING.get(cwe_id, [])


def get_soc2_controls_for_owasp(owasp_category: str) -> list[str]:
    """Map an OWASP category to relevant SOC 2 controls."""
    return OWASP_TO_SOC2_MAPPING.get(owasp_category, [])


__all__ = [
    "SOC2Framework",
    "SOC2Control",
    "CWE_TO_SOC2_MAPPING",
    "OWASP_TO_SOC2_MAPPING",
    "get_soc2_controls_for_cwe",
    "get_soc2_controls_for_owasp",
]
