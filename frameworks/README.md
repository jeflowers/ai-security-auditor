# AI-Powered Security Auditor - Test Suite

[![Tests](https://img.shields.io/badge/tests-115%2B-brightgreen.svg)](#test-counts)
[![Coverage](https://img.shields.io/badge/coverage-target%2080%25-blue.svg)](#coverage)

Comprehensive test suite for the AI-Powered Security Auditor, covering unit tests, integration tests, and end-to-end workflow validation.

---

## 📁 Directory Structure

```
tests/
├── README.md                    # This file
├── conftest.py                  # Pytest fixtures and configuration
├── pytest.ini                   # Pytest settings (if present)
│
├── unit/                        # Unit tests
│   ├── __init__.py
│   ├── agents/                  # Agent-specific tests
│   │   ├── __init__.py
│   │   ├── test_code_analyzer.py
│   │   ├── test_log_analyzer.py
│   │   ├── test_vulnerability_scanner.py
│   │   └── test_compliance_checker.py
│   │
│   └── frameworks/              # Framework & control tests
│       ├── __init__.py
│       ├── test_framework_loader.py      # YAML loading (12 tests)
│       ├── test_framework_schema.py      # Schema validation (18 tests)
│       ├── test_control_families.py      # Control organization (15 tests)
│       ├── test_assessment_objectives.py # Objective parsing (20 tests)
│       ├── test_mappings.py              # Cross-framework mappings (25 tests)
│       ├── test_ac_controls.py           # Access Control family (28 tests)
│       ├── test_au_controls.py           # Audit family (28 tests)
│       └── test_ra_si_controls.py        # RA & SI families (27 tests)
│
├── integration/                 # Integration tests
│   ├── __init__.py
│   ├── test_rag_pipeline.py
│   ├── test_orchestrator.py
│   ├── test_framework_agent_integration.py
│   ├── test_cross_framework_assessment.py
│   └── test_evidence_requirements.py
│
├── e2e/                         # End-to-end tests
│   ├── __init__.py
│   ├── test_full_audit_workflow.py
│   ├── test_nist_assessment_workflow.py
│   └── test_soc2_nist_dual_assessment.py
│
├── utils/                       # Test utilities
│   ├── __init__.py
│   └── framework_helpers.py     # Helper functions for framework tests
│
├── data/                        # Test data files
│   ├── valid/                   # Valid test inputs
│   │   ├── sample_code/
│   │   ├── sample_logs/
│   │   └── sample_evidence/
│   └── invalid/                 # Invalid inputs for error testing
│       ├── malformed_yaml/
│       └── incomplete_evidence/
│
└── templates/                   # Reusable test patterns
    └── assessment_template.py
```

---

## 🚀 Quick Start

### Prerequisites

```bash
# Ensure you're in the project virtual environment
cd /Users/chitownj/Desktop/development/ai-security-auditor
source venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=agents --cov=rag --cov=collectors --cov-report=html

# Run specific test categories
pytest tests/unit/ -v              # Unit tests only
pytest tests/integration/ -v       # Integration tests only
pytest tests/e2e/ -v               # End-to-end tests only

# Run specific test file
pytest tests/unit/frameworks/test_framework_loader.py -v

# Run tests matching a pattern
pytest tests/ -v -k "test_ac"      # All AC control tests
pytest tests/ -v -k "anti_hallucination"  # Anti-hallucination tests

# Run with verbose output and no capture
pytest tests/ -v -s

# Run fast tests only (skip slow integration tests)
pytest tests/ -v -m "not slow"

# Run in parallel (requires pytest-xdist)
pytest tests/ -v -n auto
```

---

## 📊 Test Categories

### Unit Tests (`tests/unit/`)

Fast, isolated tests for individual components.

#### Agent Tests (`tests/unit/agents/`)

| Test File | Tests | Description |
|-----------|-------|-------------|
| `test_code_analyzer.py` | 40+ | Security pattern detection, AST parsing, CWE mapping |
| `test_log_analyzer.py` | 15+ | Log parsing, event detection, anomaly identification |
| `test_vulnerability_scanner.py` | 10+ | ZAP integration, severity classification |
| `test_compliance_checker.py` | 15+ | RAG retrieval, evidence validation |

#### Framework Tests (`tests/unit/frameworks/`)

| Test File | Tests | Description |
|-----------|-------|-------------|
| `test_framework_loader.py` | 12 | YAML loading, error handling, nested access |
| `test_framework_schema.py` | 18 | Schema validation, data types, required fields |
| `test_control_families.py` | 15 | Family organization, baselines, agent mappings |
| `test_assessment_objectives.py` | 20 | Objective parsing, methods, automation flags |
| `test_mappings.py` | 25 | SOC 2↔NIST, CWE↔controls, bidirectional |
| `test_ac_controls.py` | 28 | Access Control (AC-1 through AC-17) |
| `test_au_controls.py` | 28 | Audit & Accountability (AU-1 through AU-12) |
| `test_ra_si_controls.py` | 27 | Risk Assessment & System Integrity |

### Integration Tests (`tests/integration/`)

Tests for component interactions and data flow.

| Test File | Tests | Description |
|-----------|-------|-------------|
| `test_rag_pipeline.py` | 15 | Document processing, embeddings, retrieval |
| `test_orchestrator.py` | 20 | Phase transitions, agent coordination |
| `test_framework_agent_integration.py` | 20 | Agent↔framework communication |
| `test_cross_framework_assessment.py` | 20 | SOC 2 + NIST dual assessments |
| `test_evidence_requirements.py` | 15 | Provenance, artifacts, gap detection |

### End-to-End Tests (`tests/e2e/`)

Full workflow tests simulating real usage.

| Test File | Tests | Description |
|-----------|-------|-------------|
| `test_full_audit_workflow.py` | 15 | Complete audit lifecycle |
| `test_nist_assessment_workflow.py` | 20 | NIST 800-53A assessment flow |
| `test_soc2_nist_dual_assessment.py` | 15 | Combined framework assessment |

---

## 🔧 Test Utilities

### `tests/utils/framework_helpers.py`

Helper functions for framework-related tests:

```python
from tests.utils.framework_helpers import (
    # YAML utilities
    load_yaml_file,
    validate_yaml_structure,
    get_nested_value,
    
    # Control validation
    extract_control_ids,
    extract_assessment_objectives,
    validate_control_structure,
    validate_assessment_objective,
    
    # Anti-hallucination
    check_for_weasel_words,
    validate_assessment_state,
    validate_evidence_citation,
    validate_provenance,
    
    # Evidence generation
    generate_evidence_id,
    generate_artifact_hash,
    create_evidence_artifact,
    
    # Mapping utilities
    get_soc2_to_nist_mapping,
    get_cwe_to_control_mapping,
    validate_cross_framework_mapping,
    
    # Agent capabilities
    get_agent_capabilities,
    validate_agent_control_coverage,
    
    # Test data
    create_mock_assessment_result,
    create_mock_finding,
)
```

### `tests/conftest.py`

Shared pytest fixtures:

```python
# Path fixtures
@pytest.fixture
def frameworks_path() -> Path
@pytest.fixture
def soc2_path() -> Path

# YAML data fixtures
@pytest.fixture
def framework_yaml() -> dict
@pytest.fixture
def soc2_mapping_yaml() -> dict
@pytest.fixture
def ac_controls_yaml() -> dict
@pytest.fixture
def au_controls_yaml() -> dict
@pytest.fixture
def ra_si_controls_yaml() -> dict

# Mock agent fixtures
@pytest.fixture
def mock_code_analyzer()
@pytest.fixture
def mock_log_analyzer()
@pytest.fixture
def mock_vulnerability_scanner()
@pytest.fixture
def mock_compliance_checker()

# Evidence fixtures
@pytest.fixture
def sample_evidence_artifact() -> dict
@pytest.fixture
def sample_finding() -> dict

# Anti-hallucination fixtures
@pytest.fixture
def valid_assessment_states() -> list
@pytest.fixture
def forbidden_weasel_words() -> list
@pytest.fixture
def compliant_assessment() -> dict
@pytest.fixture
def non_compliant_assessment() -> dict
```

---

## 🛡️ Anti-Hallucination Test Coverage

Special attention is given to testing the anti-hallucination framework:

### Valid Assessment States
```python
VALID_STATES = [
    "PASS",
    "FAIL", 
    "INSUFFICIENT_EVIDENCE",
    "EVIDENCE_GAP",
    "CONFLICTING_EVIDENCE",
    "NEEDS_MANUAL_REVIEW"
]
```

### Forbidden Weasel Words
```python
FORBIDDEN_PHRASES = [
    "likely", "probably", "possibly",
    "appears to be", "seems to", "suggests",
    "may indicate", "could be", "might"
]
```

### Test Examples
```python
def test_rejects_weasel_words():
    """Ensure assessments with weasel words are rejected."""
    invalid = "The system likely has proper controls"
    assert check_for_weasel_words(invalid) is True

def test_requires_evidence_citation():
    """Ensure claims require evidence artifact IDs."""
    assessment = {"status": "PASS", "evidence": []}
    assert validate_evidence_citation(assessment) is False
    
def test_valid_assessment_state():
    """Ensure only valid states are accepted."""
    assert validate_assessment_state("PASS") is True
    assert validate_assessment_state("MAYBE") is False
```

---

## 📈 Test Counts

| Category | Existing | New (NIST) | Total |
|----------|----------|------------|-------|
| Unit - Agents | 70+ | - | 70+ |
| Unit - Frameworks | - | 173 | 173 |
| Integration | 10 | 55 | 65 |
| E2E | 5 | 35 | 40 |
| **Total** | **85+** | **263** | **348+** |

### Current Progress

```
Phase 1 (Unit - Frameworks): ████████░░░░░░░░ 45/173 (26%)
Phase 2 (Integration):       ░░░░░░░░░░░░░░░░  0/55  (0%)
Phase 3 (E2E):               ░░░░░░░░░░░░░░░░  0/35  (0%)
───────────────────────────────────────────────────────
Overall NIST Tests:          ███░░░░░░░░░░░░░ 45/263 (17%)
```

---

## 🏃 Continuous Integration

### GitHub Actions (Recommended)

```yaml
# .github/workflows/tests.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: pip install -e ".[dev]"
      - name: Run tests
        run: pytest tests/ -v --cov=agents --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
pytest tests/unit/ -v --tb=short -q
```

---

## 📝 Writing New Tests

### Test Naming Convention

```python
# Pattern: test_<action>_<condition>_<expected_result>

def test_load_framework_yaml_returns_dict():
    """Loading framework.yaml should return a dictionary."""
    
def test_validate_control_with_missing_title_fails():
    """Controls without titles should fail validation."""
    
def test_assessment_with_weasel_words_is_rejected():
    """Assessments containing weasel words must be rejected."""
```

### Test Structure (AAA Pattern)

```python
def test_example():
    """Description of what is being tested."""
    # Arrange - Set up test data
    control = {"id": "AC-2", "title": "Account Management"}
    
    # Act - Execute the code under test
    result = validate_control_structure(control)
    
    # Assert - Verify the results
    assert result is True
```

### Using Fixtures

```python
def test_ac_controls_structure(ac_controls_yaml):
    """Test AC controls have correct structure."""
    controls = ac_controls_yaml.get("controls", {})
    assert "AC-2" in controls
    assert "title" in controls["AC-2"]

def test_anti_hallucination_compliance(compliant_assessment, forbidden_weasel_words):
    """Test that compliant assessments pass validation."""
    for word in forbidden_weasel_words:
        assert word not in compliant_assessment["justification"]
```

### Parametrized Tests

```python
import pytest

@pytest.mark.parametrize("control_id,expected_family", [
    ("AC-2", "AC"),
    ("AU-6", "AU"),
    ("RA-5", "RA"),
    ("SI-4", "SI"),
])
def test_control_family_extraction(control_id, expected_family):
    """Test extracting family from control ID."""
    family = control_id.split("-")[0]
    assert family == expected_family
```

---

## 🐛 Debugging Tests

### Verbose Output

```bash
# Show print statements
pytest tests/ -v -s

# Show local variables on failure
pytest tests/ -v --tb=long

# Stop on first failure
pytest tests/ -v -x

# Run last failed tests
pytest tests/ -v --lf
```

### Using pytest-pdb

```bash
# Drop into debugger on failure
pytest tests/ -v --pdb

# Drop into debugger at start
pytest tests/ -v --pdb --pdbcls=IPython.terminal.debugger:Pdb
```

---

## 📊 Coverage

### Generate Coverage Report

```bash
# Terminal report
pytest tests/ --cov=agents --cov=rag --cov=collectors --cov-report=term-missing

# HTML report (opens in browser)
pytest tests/ --cov=agents --cov-report=html
open htmlcov/index.html

# XML report (for CI)
pytest tests/ --cov=agents --cov-report=xml
```

### Coverage Targets

| Component | Target | Current |
|-----------|--------|---------|
| `agents/code_analyzer/` | 90% | ~85% |
| `agents/log_analyzer/` | 85% | ~80% |
| `agents/compliance_checker/` | 85% | ~75% |
| `rag/` | 80% | ~70% |
| `collectors/` | 80% | ~75% |
| **Overall** | **80%** | **~75%** |

---

## 🔗 Related Documentation

- [Main README](../README.md) - Project overview
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development guidelines
- [CHANGELOG.md](../CHANGELOG.md) - Version history
- [Anti-Hallucination Framework](../docs/anti-hallucination.md) - Validation rules

---

## ❓ Troubleshooting

### Common Issues

**Tests not found:**
```bash
# Ensure __init__.py exists in all test directories
find tests -type d -exec touch {}/__init__.py \;
```

**Import errors:**
```bash
# Install package in development mode
pip install -e ".[dev]"

# Verify PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

**Fixture not found:**
```bash
# Check conftest.py is in tests/ directory
# Fixtures are auto-discovered from conftest.py files
```

**Slow tests:**
```bash
# Skip slow tests
pytest tests/ -v -m "not slow"

# Run in parallel
pip install pytest-xdist
pytest tests/ -v -n auto
```

---

*Last updated: December 31, 2024*
