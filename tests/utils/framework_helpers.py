"""
Framework test helper utilities.

Provides utility functions for testing NIST 800-53A framework integration,
including YAML validation, evidence generation, and anti-hallucination checks.
"""

from pathlib import Path
from datetime import datetime
from typing import Any
import hashlib
import re
import yaml


# =============================================================================
# YAML Utilities
# =============================================================================

def load_yaml_file(file_path: Path) -> dict[str, Any]:
    """Load and parse a YAML file."""
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)


def validate_yaml_structure(data: dict, required_keys: list[str]) -> tuple[bool, list[str]]:
    """
    Validate that a YAML structure contains required keys.
    
    Returns:
        Tuple of (is_valid, list of missing keys)
    """
    missing = [key for key in required_keys if key not in data]
    return len(missing) == 0, missing


def get_nested_value(data: dict, key_path: str, default: Any = None) -> Any:
    """
    Get a nested value from a dictionary using dot notation.
    
    Example:
        get_nested_value(data, 'framework.assessment.methods')
    """
    keys = key_path.split('.')
    value = data
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default
    return value


# =============================================================================
# Control Validation Utilities
# =============================================================================

def extract_control_ids(yaml_data: dict) -> list[str]:
    """Extract all control IDs from a control family YAML."""
    control_ids = []
    
    # Check for 'controls' key (AC, AU families)
    if 'controls' in yaml_data:
        control_ids.extend(yaml_data['controls'].keys())
    
    # Check for family-specific control keys (RA-SI combined)
    if 'ra_controls' in yaml_data:
        control_ids.extend(yaml_data['ra_controls'].keys())
    if 'si_controls' in yaml_data:
        control_ids.extend(yaml_data['si_controls'].keys())
    
    return control_ids


def extract_assessment_objectives(control: dict) -> list[dict]:
    """Extract assessment objectives from a control definition."""
    return control.get('assessment_objectives', [])


def validate_control_structure(control: dict) -> tuple[bool, list[str]]:
    """
    Validate a control has required structure.
    
    Returns:
        Tuple of (is_valid, list of missing/invalid elements)
    """
    issues = []
    
    if 'title' not in control:
        issues.append('missing title')
    
    if 'baseline' not in control:
        issues.append('missing baseline')
    elif not isinstance(control['baseline'], list):
        issues.append('baseline must be a list')
    
    if 'assessment_objectives' not in control:
        issues.append('missing assessment_objectives')
    elif not isinstance(control['assessment_objectives'], list):
        issues.append('assessment_objectives must be a list')
    
    return len(issues) == 0, issues


def validate_assessment_objective(objective: dict) -> tuple[bool, list[str]]:
    """
    Validate an assessment objective has required fields.
    
    Returns:
        Tuple of (is_valid, list of missing/invalid fields)
    """
    required_fields = ['id', 'description', 'method', 'objects']
    issues = []
    
    for field in required_fields:
        if field not in objective:
            issues.append(f'missing {field}')
    
    if 'method' in objective:
        valid_methods = ['EXAMINE', 'INTERVIEW', 'TEST']
        if objective['method'] not in valid_methods:
            issues.append(f"invalid method: {objective['method']}")
    
    if 'objects' in objective and not isinstance(objective['objects'], list):
        issues.append('objects must be a list')
    
    return len(issues) == 0, issues


# =============================================================================
# Anti-Hallucination Utilities
# =============================================================================

FORBIDDEN_WEASEL_WORDS = [
    'likely', 'probably', 'possibly', 'appears to be', 'seems to',
    'suggests', 'implies', 'may indicate', 'could be', 'might',
    'presumably', 'apparently', 'supposedly', 'arguably'
]

VALID_ASSESSMENT_STATES = [
    'PASS', 'FAIL', 'INSUFFICIENT_EVIDENCE', 
    'EVIDENCE_GAP', 'CONFLICTING_EVIDENCE', 'NEEDS_MANUAL_REVIEW'
]


def check_for_weasel_words(text: str) -> list[str]:
    """
    Check text for forbidden weasel words.
    
    Returns:
        List of weasel words found in the text
    """
    text_lower = text.lower()
    found = []
    for word in FORBIDDEN_WEASEL_WORDS:
        if word in text_lower:
            found.append(word)
    return found


def validate_assessment_state(state: str) -> bool:
    """Check if an assessment state is valid."""
    return state in VALID_ASSESSMENT_STATES


def validate_evidence_citation(text: str) -> bool:
    """
    Validate that text contains proper evidence citation.
    
    Looks for patterns like [ARTIFACT-ID] or evidence IDs.
    """
    # Pattern for artifact IDs: [XX-123-...] or similar
    citation_patterns = [
        r'\[[\w\-]+\]',  # [ARTIFACT-ID]
        r'Evidence\s+[\w\-]+',  # Evidence ARTIFACT-ID
        r'artifact_id:\s*[\w\-]+',  # artifact_id: ID
        r'evidence_id:\s*[\w\-]+'  # evidence_id: ID
    ]
    
    for pattern in citation_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def validate_provenance(artifact: dict) -> tuple[bool, list[str]]:
    """
    Validate that an evidence artifact has complete provenance.
    
    Required provenance fields:
    - source
    - timestamp
    - collector
    - scope
    - hash
    
    Returns:
        Tuple of (is_valid, list of missing fields)
    """
    required_fields = ['source', 'timestamp', 'collector', 'scope', 'hash']
    missing = [field for field in required_fields if field not in artifact]
    return len(missing) == 0, missing


# =============================================================================
# Evidence Generation Utilities
# =============================================================================

def generate_evidence_id(
    control_id: str,
    evidence_type: str,
    sequence: int = 1
) -> str:
    """Generate a standardized evidence artifact ID."""
    timestamp = datetime.utcnow().strftime('%Y%m%d')
    return f"{control_id}-E{sequence}-{evidence_type.upper()}-{timestamp}"


def generate_artifact_hash(content: str) -> str:
    """Generate SHA-256 hash for artifact content."""
    return f"sha256:{hashlib.sha256(content.encode()).hexdigest()[:16]}"


def create_evidence_artifact(
    control_id: str,
    evidence_type: str,
    content: str,
    agent: str,
    scope: str
) -> dict[str, Any]:
    """
    Create a complete evidence artifact with provenance.
    
    Returns:
        Dictionary containing the evidence artifact
    """
    return {
        'artifact_id': generate_evidence_id(control_id, evidence_type),
        'artifact_type': evidence_type,
        'source': f'{agent}_automated',
        'timestamp': datetime.utcnow().isoformat(),
        'collector': agent,
        'scope': scope,
        'hash': generate_artifact_hash(content),
        'content_summary': content[:100] if len(content) > 100 else content
    }


# =============================================================================
# Mapping Utilities
# =============================================================================

def get_soc2_to_nist_mapping(
    soc2_control: str,
    mapping_data: dict
) -> list[dict]:
    """Get NIST controls mapped to a SOC 2 control."""
    if 'soc2_to_nist' not in mapping_data:
        return []
    
    mappings = mapping_data['soc2_to_nist']
    if soc2_control in mappings:
        return mappings[soc2_control].get('nist_controls', [])
    return []


def get_cwe_to_control_mapping(
    cwe_id: int,
    mapping_data: dict
) -> list[str]:
    """Get NIST controls mapped to a CWE ID."""
    # Check vulnerability scanner configuration for CWE mappings
    if 'vulnerability_scanner_configuration' in mapping_data:
        config = mapping_data['vulnerability_scanner_configuration']
        if 'owasp_zap' in config and 'cwe_to_control_mapping' in config['owasp_zap']:
            cwe_key = f'CWE-{cwe_id}'
            if cwe_key in config['owasp_zap']['cwe_to_control_mapping']:
                return config['owasp_zap']['cwe_to_control_mapping'][cwe_key].get('controls', [])
    return []


def validate_cross_framework_mapping(
    soc2_control: str,
    expected_nist_controls: list[str],
    mapping_data: dict
) -> tuple[bool, list[str]]:
    """
    Validate SOC 2 to NIST mapping contains expected controls.
    
    Returns:
        Tuple of (all_present, missing_controls)
    """
    actual_mappings = get_soc2_to_nist_mapping(soc2_control, mapping_data)
    actual_control_ids = [m['control_id'] for m in actual_mappings]
    
    missing = [c for c in expected_nist_controls if c not in actual_control_ids]
    return len(missing) == 0, missing


# =============================================================================
# Agent Capability Utilities
# =============================================================================

def get_agent_capabilities(
    agent_name: str,
    framework_data: dict
) -> dict[str, Any]:
    """Get the capabilities defined for an agent in the framework."""
    methods = framework_data.get('assessment', {}).get('methods', [])
    
    for method in methods:
        if 'agent_mapping' in method:
            for mapping in method['agent_mapping']:
                if mapping.get('agent') == agent_name:
                    return {
                        'method': method['id'],
                        'objects': mapping.get('objects', [])
                    }
    return {}


def validate_agent_control_coverage(
    agent_name: str,
    expected_controls: list[str],
    control_data: dict
) -> tuple[bool, list[str]]:
    """
    Validate an agent covers expected controls.
    
    Returns:
        Tuple of (full_coverage, missing_controls)
    """
    covered_controls = []
    
    controls = control_data.get('controls', {})
    for control_id, control in controls.items():
        for objective in control.get('assessment_objectives', []):
            if objective.get('agent') == agent_name:
                covered_controls.append(control_id)
                break
    
    missing = [c for c in expected_controls if c not in covered_controls]
    return len(missing) == 0, missing


# =============================================================================
# Test Data Generation
# =============================================================================

def create_mock_assessment_result(
    control_id: str,
    state: str,
    evidence_artifacts: list[str],
    findings: list[dict] | None = None
) -> dict[str, Any]:
    """Create a mock assessment result for testing."""
    return {
        'control_id': control_id,
        'assessment_state': state,
        'timestamp': datetime.utcnow().isoformat(),
        'evidence_artifacts': evidence_artifacts,
        'findings': findings or [],
        'confidence': 0.95 if evidence_artifacts else 0.0,
        'assessor': 'automated_assessment'
    }


def create_mock_finding(
    finding_type: str,
    severity: str,
    control_mapping: list[str],
    cwe_id: int | None = None
) -> dict[str, Any]:
    """Create a mock security finding for testing."""
    return {
        'id': f'{finding_type.upper()}-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}',
        'type': finding_type,
        'severity': severity,
        'control_mapping': control_mapping,
        'cwe_id': cwe_id,
        'timestamp': datetime.utcnow().isoformat(),
        'description': f'Mock {finding_type} finding for testing',
        'evidence_id': generate_evidence_id(control_mapping[0] if control_mapping else 'UNKNOWN', finding_type)
    }
