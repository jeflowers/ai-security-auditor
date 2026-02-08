# HIPAA Security Rule Framework

## AI-Powered Security Auditor - HIPAA Compliance Module

This framework module provides HIPAA Security Rule (45 CFR Part 164 Subpart C) compliance assessment capabilities for the AI-Powered Security Auditor.

---

## 📁 Files

| File | Description |
|------|-------------|
| `controls.yaml` | HIPAA control definitions with evidence requirements |
| `scoring_rubric.yaml` | Anti-hallucination rules and assessment criteria |
| `__init__.py` | Python module for programmatic access |

---

## 🏥 HIPAA Control Categories

The framework implements all HIPAA Security Rule categories:

| Category | CFR Reference | Controls |
|----------|---------------|----------|
| **Administrative Safeguards** | §164.308 | 10 controls |
| **Physical Safeguards** | §164.310 | 4 controls |
| **Technical Safeguards** | §164.312 | 5 controls |
| **Organizational Requirements** | §164.314 | 1 control |
| **Policies and Procedures** | §164.316 | 2 controls |
| **Breach Notification** | §164.400-414 | 3 controls |

---

## 🔑 Key Features

### Required vs Addressable Specifications

HIPAA distinguishes between:
- **Required**: Must be implemented
- **Addressable**: Must implement OR document why not reasonable/appropriate

The framework handles both correctly with appropriate assessment logic.

### Anti-Hallucination Framework

Inherits all anti-hallucination rules from the core system:
- Evidence citation required
- No inference from missing evidence
- Six valid assessment states
- Prohibited "weasel words"
- PHI/ePHI sensitivity recognition

### Comprehensive Mappings

- **CWE → HIPAA**: Map vulnerability types to relevant controls
- **OWASP → HIPAA**: Map OWASP Top 10 to HIPAA requirements

---

## 🚀 Usage

### Loading the Framework

```python
from frameworks.hipaa import HIPAAFramework

framework = HIPAAFramework()

# Get all controls
controls = framework.get_all_controls()

# Get by category
tech_controls = framework.get_controls_by_category("Technical Safeguards")

# Get specific control
access_control = framework.get_control("HIPAA-TS-312.a1")
```

### Mapping Findings

```python
# Map CWE to HIPAA controls
controls = framework.map_cwe_to_controls(311)  # Missing Encryption
# Returns: ['HIPAA-TS-312.a1', 'HIPAA-TS-312.e1']

# Map OWASP to HIPAA controls
controls = framework.map_owasp_to_controls("A02:2021-Cryptographic Failures")
# Returns: ['HIPAA-TS-312.a1', 'HIPAA-TS-312.e1', 'HIPAA-PS-310.d1']
```

### Creating Assessments

```python
from frameworks.hipaa import HIPAAFramework, AssessmentState

framework = HIPAAFramework()

assessment = framework.create_assessment(
    control_id="HIPAA-TS-312.a1",
    state=AssessmentState.PASS,
    evidence_ids=["HIPAA-TS-312.a1-E4-encryption-config.json"],
    findings=[
        "Evidence [HIPAA-TS-312.a1-E4-encryption-config.json] dated 2024-12-15 "
        "confirms AES-256 encryption for all ePHI at rest."
    ],
    recommendations=[]
)
```

### Validating Assessment Text

```python
# Check for prohibited phrases
is_valid, violations = framework.validate_assessment_text(
    "The system likely has encryption implemented."
)
# Returns: (False, ['likely'])

# Check for evidence citation
has_citation = framework.validate_evidence_citation(
    "Evidence [HIPAA-TS-312.a1-E4-config.json] shows encryption is enabled."
)
# Returns: True
```

---

## 📋 Assessment States

| State | Description |
|-------|-------------|
| `PASS` | Evidence demonstrates compliance |
| `FAIL` | Evidence demonstrates non-compliance |
| `INSUFFICIENT_EVIDENCE` | Evidence exists but incomplete |
| `EVIDENCE_GAP` | Required evidence not collected |
| `CONFLICTING_EVIDENCE` | Sources disagree |
| `NEEDS_MANUAL_REVIEW` | Human judgment required |
| `NOT_APPLICABLE` | Control doesn't apply to scope |

---

## 🔒 PHI Sensitivity Considerations

The framework recognizes that Protected Health Information (PHI) requires heightened protection:

- All 18 HIPAA identifiers considered
- Encryption safe harbor assessment
- Breach notification threshold evaluation
- Minimum necessary standard application

---

## 📊 Evidence Requirements

Each control defines specific evidence requirements:

```yaml
evidence_requirements:
  - id: "HIPAA-TS-312.a1-E4"
    description: "Encryption implementation"
    artifact_types:
      - "Encryption at rest configuration"
      - "Encryption key management"
      - "Encryption standards documentation"
    required: true
```

---

## 🔄 Integration with Security Auditor

The HIPAA framework integrates with the main orchestrator:

```python
from agents.orchestrator import SecurityAuditOrchestrator

orchestrator = SecurityAuditOrchestrator()
state = await orchestrator.run_audit(
    audit_id="AUDIT-2025-001",
    framework="HIPAA",  # Use HIPAA instead of SOC2
    scope={"systems": ["ehr-system"]},
    target_path="./healthcare-app",
)
```

---

## 📚 References

- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [45 CFR Part 164 Subpart C](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C)
- [NIST HIPAA Security Toolkit](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/HIPAA)
- [HHS Breach Portal](https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf)

---

## 📝 License

Part of the AI-Powered Security Auditor project. MIT License.
