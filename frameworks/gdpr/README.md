# GDPR Compliance Framework

## Overview

This framework enables automated GDPR compliance assessment for the AI-Powered Security Auditor. It maps GDPR articles to evidence requirements and implements anti-hallucination safeguards to ensure all compliance claims are verifiable.

## Framework Structure

```
frameworks/gdpr/
├── controls.yaml       # 31 GDPR article definitions with evidence requirements
├── scoring_rubric.yaml # Assessment rules and anti-hallucination framework
└── README.md          # This file
```

## Key Features

### 📋 31 GDPR Controls Mapped

| Chapter | Articles Covered | Focus Areas |
|---------|-----------------|-------------|
| **II - Principles** | 5(1)(a-f), 5(2), 6, 7 | Lawfulness, fairness, transparency, purpose limitation, minimisation, accuracy, storage limitation, security, accountability |
| **III - Rights** | 12-22 | Access, rectification, erasure, restriction, portability, objection, automated decisions |
| **IV - Controller/Processor** | 24, 25, 28, 30, 32-35, 37 | Responsibility, privacy by design, processors, ROPA, security, breach notification, DPIA, DPO |
| **V - Transfers** | 44, 46 | International transfer safeguards |

### 🛡️ Anti-Hallucination Framework

The framework enforces five fundamental rules:

1. **Evidence Required** - Every claim must cite specific evidence
2. **No Inference from Missing Evidence** - Missing evidence → EVIDENCE_GAP
3. **Explicit Mapping** - Finding ↔ Evidence ↔ Article
4. **Bounded States** - Only 6 valid assessment states
5. **Provenance Required** - Full metadata for all evidence

### 📊 Assessment States

| State | Description |
|-------|-------------|
| `PASS` | Evidence demonstrates compliance |
| `FAIL` | Evidence demonstrates non-compliance |
| `INSUFFICIENT_EVIDENCE` | Evidence exists but incomplete |
| `EVIDENCE_GAP` | Required evidence not collected |
| `CONFLICTING_EVIDENCE` | Sources disagree |
| `NEEDS_MANUAL_REVIEW` | Human judgment required |

## Evidence Requirements

Each control specifies required and optional evidence types:

```yaml
evidence_requirements:
  - id: "ART32-E2"
    description: "Encryption implementation (at rest and in transit)"
    artifact_types: ["configuration", "technical_spec"]
    required: true
```

### Evidence Artifact Types

- `policy_document` - Formal policies and procedures
- `configuration` - System configurations and settings
- `technical_spec` - Technical specifications and architecture
- `audit_log` - System and access logs
- `assessment_document` - Risk assessments, DPIAs
- `contract` / `dpa` - Contracts and DPAs
- `training_records` - Staff training documentation
- `system_screenshot` - UI/system evidence
- `scan_results` - Security scan outputs

## Severity Distribution

| Severity | Count | Example Articles |
|----------|-------|------------------|
| **Critical** | 6 | ART5.1f, ART6, ART28, ART32, ART33, ART44, ART46 |
| **High** | 17 | ART5.1a, ART7, ART13, ART15, ART17, ART25, ART35 |
| **Medium** | 8 | ART5.1c, ART5.1d, ART12, ART16, ART18, ART20 |

## Integration Guide

### 1. Add Framework to Project

```bash
# Copy to frameworks directory
cp -r gdpr_framework/ ai-security-auditor/frameworks/gdpr/
```

### 2. Load Framework in Compliance Checker

```python
from agents.compliance_checker.agent import ComplianceChecker

checker = ComplianceChecker(framework="GDPR")
result = checker.assess(evidence_path="./evidence")
```

### 3. Run GDPR Audit

```bash
security-auditor audit ./my-project \
    --framework gdpr \
    --output ./gdpr-audit-results
```

## Forbidden Phrases

The scoring rubric defines "weasel words" that trigger assessment rejection:

```yaml
forbidden_phrases:
  - "likely", "probably", "possibly"
  - "appears to be", "seems to"
  - "suggests", "implies", "may indicate"
  - "presumably", "typically", "generally"
```

## Scoring Methodology

### Article Weights

- **Critical** (×3): Core security and legal basis requirements
- **High** (×2): Essential compliance requirements
- **Standard** (×1): Supporting requirements

### Overall Thresholds

| Score | Status |
|-------|--------|
| ≥85 | Compliant |
| ≥70 | Substantially Compliant |
| ≥50 | Partially Compliant |
| <50 | Non-Compliant |

**Note:** Any critical article with FAIL triggers overall NON-COMPLIANT regardless of score.

## Example Assessment Output

```json
{
  "finding_id": "GDPR-F-001",
  "gdpr_article": "ART32",
  "title": "Missing Encryption at Rest",
  "description": "Database storage lacks encryption configuration",
  "assessment_state": "FAIL",
  "evidence_ids": ["ART32-E2-CONFIG-db-settings.yaml"],
  "justification": "Evidence [ART32-E2-CONFIG-db-settings.yaml] shows encryption_at_rest: false",
  "risk_rating": "critical",
  "recommendation": "Enable AES-256 encryption for all database storage",
  "remediation_timeframe": "30 days"
}
```

## Evidence Freshness Requirements

| Evidence Type | Max Age | Review Cycle |
|--------------|---------|--------------|
| Security scans | 3 months | Monthly |
| Configurations | 6 months | Quarterly |
| Risk assessments | 12 months | Annually |
| Policies | 24 months | Annually |
| DPIAs | 36 months | Annually + on change |

## GDPR-Specific Rules

### Legal Basis (Article 6)
- Each processing activity needs exactly ONE legal basis
- If consent is the basis, must meet Article 7 conditions
- Legal basis must be determined BEFORE processing

### Data Subject Rights (Articles 15-22)
- Each right requires both procedure AND technical capability
- Response times must be documented
- Erasure requires verification and third-party notification

### International Transfers (Articles 44, 46)
- All transfers must be documented in inventory
- Valid transfer mechanism required
- Post-Schrems II: SCCs may need supplementary measures

## Related SOC 2 Mappings

| GDPR Article | SOC 2 Control |
|--------------|---------------|
| ART5.1f (Security) | CC6.6, CC6.7 |
| ART32 (Security of Processing) | CC6.1, CC6.6, CC7.1 |
| ART33 (Breach Notification) | CC7.3 |
| ART25 (Privacy by Design) | CC8.1 |
| ART28 (Processors) | CC9.1 |

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-01-01 | Initial release with 31 controls |

## References

- [GDPR Full Text](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [EDPB Guidelines](https://edpb.europa.eu/our-work-tools/general-guidance/guidelines_en)
- [ICO Guidance](https://ico.org.uk/for-organisations/guide-to-data-protection/)
