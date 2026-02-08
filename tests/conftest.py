"""
Pytest configuration for AI Security Auditor tests.

This file sets up the Python path and provides fixtures for testing
the NIST 800-53A framework integration and agent functionality.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
import yaml
import pytest

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure pytest-asyncio
pytest_plugins = ['pytest_asyncio']


# =============================================================================
# Path Fixtures
# =============================================================================

@pytest.fixture
def project_root_path() -> Path:
    """Return the project root directory path."""
    return project_root


@pytest.fixture
def frameworks_dir(project_root_path: Path) -> Path:
    """Return the frameworks directory path."""
    return project_root_path / "frameworks"


@pytest.fixture
def test_data_dir() -> Path:
    """Return the test data directory path."""
    return Path(__file__).parent / "data"


# =============================================================================
# YAML Loading Fixtures
# =============================================================================

@pytest.fixture
def framework_yaml(frameworks_dir: Path) -> dict[str, Any]:
    """Load and return the main framework.yaml configuration."""
    framework_path = frameworks_dir / "framework.yaml"
    with open(framework_path, 'r') as f:
        return yaml.safe_load(f)


@pytest.fixture
def soc2_mapping_yaml(frameworks_dir: Path) -> dict[str, Any]:
    """Load and return the SOC 2 to NIST mapping configuration."""
    mapping_path = frameworks_dir / "soc2-mapping.yaml"
    with open(mapping_path, 'r') as f:
        return yaml.safe_load(f)


@pytest.fixture
def ac_controls_yaml(frameworks_dir: Path) -> dict[str, Any]:
    """Load and return the Access Control (AC) family configuration."""
    ac_path = frameworks_dir / "ac.yaml"
    with open(ac_path, 'r') as f:
        return yaml.safe_load(f)


@pytest.fixture
def au_controls_yaml(frameworks_dir: Path) -> dict[str, Any]:
    """Load and return the Audit and Accountability (AU) family configuration."""
    au_path = frameworks_dir / "au.yaml"
    with open(au_path, 'r') as f:
        return yaml.safe_load(f)


@pytest.fixture
def ra_si_controls_yaml(frameworks_dir: Path) -> dict[str, Any]:
    """Load and return the Risk Assessment (RA) & System Integrity (SI) configuration."""
    ra_si_path = frameworks_dir / "ra-si.yaml"
    with open(ra_si_path, 'r') as f:
        return yaml.safe_load(f)


@pytest.fixture
def all_framework_yamls(
    framework_yaml: dict,
    soc2_mapping_yaml: dict,
    ac_controls_yaml: dict,
    au_controls_yaml: dict,
    ra_si_controls_yaml: dict
) -> dict[str, dict]:
    """Return all framework YAML configurations as a dictionary."""
    return {
        'framework': framework_yaml,
        'soc2_mapping': soc2_mapping_yaml,
        'ac_controls': ac_controls_yaml,
        'au_controls': au_controls_yaml,
        'ra_si_controls': ra_si_controls_yaml
    }


# =============================================================================
# Mock Agent Fixtures
# =============================================================================

class MockCodeAnalyzerAgent:
    """Mock Code Security Analyzer Agent for testing."""
    
    def __init__(self, findings: list[dict] | None = None):
        self.findings = findings or []
        self.analysis_called = False
    
    def analyze_file(self, file_path: Path) -> list[dict]:
        self.analysis_called = True
        return self.findings
    
    def analyze_directory(self, dir_path: Path) -> dict:
        self.analysis_called = True
        return {'findings': self.findings, 'files_analyzed': 1}


class MockLogAnalyzerAgent:
    """Mock Log Analyzer Agent for testing."""
    
    def __init__(self, findings: list[dict] | None = None):
        self.findings = findings or []
        self.analysis_called = False
    
    def analyze_logs(self, log_path: Path) -> list[dict]:
        self.analysis_called = True
        return self.findings


class MockVulnerabilityScannerAgent:
    """Mock Vulnerability Scanner Agent for testing."""
    
    def __init__(self, vulnerabilities: list[dict] | None = None):
        self.vulnerabilities = vulnerabilities or []
        self.scan_called = False
    
    def scan(self, target: str) -> dict:
        self.scan_called = True
        return {'vulnerabilities': self.vulnerabilities, 'target': target}


class MockComplianceCheckerAgent:
    """Mock Compliance Checker Agent for testing."""
    
    def __init__(self, assessments: list[dict] | None = None):
        self.assessments = assessments or []
        self.check_called = False
    
    def assess(self, evidence_path: Path) -> dict:
        self.check_called = True
        return {'assessments': self.assessments}


@pytest.fixture
def mock_code_analyzer():
    """Return a factory for creating mock code analyzer agents."""
    def _create(findings: list[dict] | None = None):
        return MockCodeAnalyzerAgent(findings)
    return _create


@pytest.fixture
def mock_log_analyzer():
    """Return a factory for creating mock log analyzer agents."""
    def _create(findings: list[dict] | None = None):
        return MockLogAnalyzerAgent(findings)
    return _create


@pytest.fixture
def mock_vulnerability_scanner():
    """Return a factory for creating mock vulnerability scanner agents."""
    def _create(vulnerabilities: list[dict] | None = None):
        return MockVulnerabilityScannerAgent(vulnerabilities)
    return _create


@pytest.fixture
def mock_compliance_checker():
    """Return a factory for creating mock compliance checker agents."""
    def _create(assessments: list[dict] | None = None):
        return MockComplianceCheckerAgent(assessments)
    return _create


# =============================================================================
# Sample Evidence Fixtures
# =============================================================================

@pytest.fixture
def sample_code_finding() -> dict[str, Any]:
    """Return a sample code security finding."""
    return {
        'id': 'CODE-001',
        'title': 'SQL Injection Vulnerability',
        'severity': 'HIGH',
        'cwe_id': 89,
        'owasp_category': 'A03:2021-Injection',
        'file': 'app/database.py',
        'line': 42,
        'description': 'User input directly concatenated into SQL query',
        'remediation': 'Use parameterized queries',
        'evidence_id': 'SI-10-E1-CODE-001',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


@pytest.fixture
def sample_log_finding() -> dict[str, Any]:
    """Return a sample log analysis finding."""
    return {
        'id': 'LOG-001',
        'event_type': 'authentication_failure',
        'severity': 'MEDIUM',
        'count': 15,
        'source_ip': '192.168.1.100',
        'description': 'Multiple failed login attempts detected',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'control_mapping': ['AU-2', 'AU-6', 'AC-7']
    }


@pytest.fixture
def sample_vulnerability() -> dict[str, Any]:
    """Return a sample vulnerability scan finding."""
    return {
        'id': 'VULN-001',
        'title': 'Cross-Site Scripting (XSS)',
        'severity': 'HIGH',
        'cwe_id': 79,
        'cvss_score': 7.5,
        'url': 'https://example.com/search',
        'parameter': 'q',
        'evidence': 'Reflected XSS in search parameter',
        'control_mapping': ['SI-10', 'RA-5']
    }


@pytest.fixture
def sample_evidence_artifact() -> dict[str, Any]:
    """Return a sample evidence artifact with full provenance."""
    return {
        'artifact_id': 'CC6.6-E4-SCAN-20251231',
        'artifact_type': 'vulnerability_scan_report',
        'source': 'OWASP ZAP',
        'timestamp': datetime.utcnow().isoformat(),
        'collector': 'vulnerability_scanner_agent',
        'scope': 'production_web_application',
        'hash': 'sha256:abc123def456',
        'content_summary': 'Vulnerability scan covering 150 endpoints',
        'findings_count': 12
    }


@pytest.fixture
def sample_provenance_metadata() -> dict[str, Any]:
    """Return sample provenance metadata for anti-hallucination compliance."""
    return {
        'source': 'automated_scan',
        'timestamp': datetime.utcnow().isoformat(),
        'collector': 'code_analyzer_agent',
        'scope': 'repository:main_branch',
        'hash': 'sha256:789xyz',
        'verification_status': 'verified'
    }


# =============================================================================
# Assessment State Fixtures
# =============================================================================

@pytest.fixture
def valid_assessment_states() -> list[str]:
    """Return the list of valid assessment states per anti-hallucination rules."""
    return [
        'PASS',
        'FAIL',
        'INSUFFICIENT_EVIDENCE',
        'EVIDENCE_GAP',
        'CONFLICTING_EVIDENCE',
        'NEEDS_MANUAL_REVIEW'
    ]


@pytest.fixture
def forbidden_weasel_words() -> list[str]:
    """Return the list of forbidden 'weasel words' for assessments."""
    return [
        'likely',
        'probably',
        'possibly',
        'appears to be',
        'seems to',
        'suggests',
        'implies',
        'may indicate',
        'could be',
        'might'
    ]


# =============================================================================
# NIST-Specific Fixtures
# =============================================================================

@pytest.fixture
def nist_assessment_methods() -> list[str]:
    """Return the valid NIST 800-53A assessment methods."""
    return ['EXAMINE', 'INTERVIEW', 'TEST']


@pytest.fixture
def nist_depth_levels() -> list[str]:
    """Return the NIST assessment depth levels."""
    return ['basic', 'focused', 'comprehensive']


@pytest.fixture
def fedramp_baselines() -> list[str]:
    """Return the FedRAMP baseline levels."""
    return ['low', 'moderate', 'high']


@pytest.fixture
def sample_nist_control() -> dict[str, Any]:
    """Return a sample NIST 800-53 control structure."""
    return {
        'control_id': 'AC-2',
        'title': 'Account Management',
        'family': 'AC',
        'baseline': ['low', 'moderate', 'high'],
        'assessment_objectives': [
            {
                'id': 'AC-2.a',
                'description': 'Define and document account types',
                'method': 'EXAMINE',
                'objects': ['account management procedures', 'user access policy'],
                'automated': True,
                'agent': 'compliance_checker'
            }
        ]
    }


@pytest.fixture
def sample_soc2_to_nist_mapping() -> dict[str, Any]:
    """Return a sample SOC 2 to NIST control mapping."""
    return {
        'soc2_control': 'CC6.1',
        'title': 'Logical Access Security',
        'nist_controls': [
            {'control_id': 'AC-2', 'relationship': 'direct'},
            {'control_id': 'AC-3', 'relationship': 'direct'},
            {'control_id': 'IA-2', 'relationship': 'direct'}
        ]
    }


# =============================================================================
# Temporary File/Directory Fixtures
# =============================================================================

@pytest.fixture
def temp_evidence_dir(tmp_path: Path) -> Path:
    """Create and return a temporary evidence directory."""
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    return evidence_dir


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Create and return a temporary output directory."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def sample_python_file(tmp_path: Path) -> Path:
    """Create a sample Python file with security issues for testing."""
    code = '''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def login(username, password):
    # Hardcoded credentials
    if username == "admin" and password == "password123":
        return True
    return False
'''
    file_path = tmp_path / "vulnerable_app.py"
    file_path.write_text(code)
    return file_path


@pytest.fixture
def sample_log_file(tmp_path: Path) -> Path:
    """Create a sample log file with security events for testing."""
    logs = '''
2025-01-01 10:00:00 INFO User john.doe logged in successfully
2025-01-01 10:01:00 WARNING Failed login attempt for user admin from 192.168.1.100
2025-01-01 10:01:05 WARNING Failed login attempt for user admin from 192.168.1.100
2025-01-01 10:01:10 WARNING Failed login attempt for user admin from 192.168.1.100
2025-01-01 10:01:15 WARNING Failed login attempt for user admin from 192.168.1.100
2025-01-01 10:01:20 WARNING Failed login attempt for user admin from 192.168.1.100
2025-01-01 10:02:00 CRITICAL Privilege escalation detected: user guest attempted sudo
2025-01-01 10:03:00 ERROR SQL error: syntax error near 'DROP TABLE'
'''
    file_path = tmp_path / "security.log"
    file_path.write_text(logs)
    return file_path


@pytest.fixture
def sample_config_file(tmp_path: Path) -> Path:
    """Create a sample configuration file for testing."""
    config = '''
database:
  host: localhost
  port: 5432
  username: app_user
  password: supersecret123  # Hardcoded credential
  
api:
  key: sk-1234567890abcdef  # Exposed API key
  
ssl:
  verify: false  # Insecure SSL configuration
'''
    file_path = tmp_path / "config.yaml"
    file_path.write_text(config)
    return file_path


# =============================================================================
# API Testing Fixtures
# =============================================================================

@pytest.fixture
def api_client():
    """Create a FastAPI test client."""
    from fastapi.testclient import TestClient
    from api.routes import app
    return TestClient(app)


@pytest.fixture
def sample_api_audit_request() -> dict[str, Any]:
    """Sample audit request payload for API testing."""
    return {
        "target": "https://test.example.com",
        "frameworks": ["SOC2"],
        "agents": ["vulnerability_scanner", "code_analyzer", "log_analyzer", "compliance_checker"],
        "config": {}
    }


@pytest.fixture
def sample_finding_data() -> dict[str, Any]:
    """Sample finding data for API testing."""
    return {
        "finding_id": "FND-TEST-001",
        "agent_type": "vulnerability_scanner",
        "severity": "high",
        "title": "Test Vulnerability",
        "description": "A test vulnerability for testing purposes",
        "evidence_ids": ["EVD-TEST-001"],
        "control_ids": ["CC6.1"],
        "remediation": "Apply the test fix",
        "discovered_at": datetime.now(timezone.utc).isoformat()
    }


@pytest.fixture
def sample_evidence_data() -> dict[str, Any]:
    """Sample evidence data for API testing."""
    return {
        "evidence_id": "EVD-TEST-001",
        "evidence_type": "scan_result",
        "source": "Test Scanner",
        "summary": "Test scan output",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "content_hash": "sha256:testhash123",
        "related_findings": ["FND-TEST-001"],
        "related_controls": ["CC6.1"]
    }
