# AI-Powered Security Auditor

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-70%2B%20passing-brightgreen.svg)](#testing)

**Multi-agent system for automated compliance auditing with verifiable evidence and anti-hallucination safeguards.**

> **"If you can't prove it, you can't claim it"**

Built as a demonstration of NVIDIA-ready AI/ML engineering skills, this project implements a production-grade agentic AI system using LangChain, LangGraph, and RAG architecture.

---

## 🌐 Platform Vision

This project is the **proof-of-concept engine** for a unified compliance platform — not a single-framework tool. The current four-agent system proves that evidence-based AI compliance assessment works. The architecture is designed to extend across the full spectrum of regulatory and security domains.

### Layer 1 — Current PoC (What's Built)

Four specialized agents performing automated compliance assessment across **SOC 2, GDPR, HIPAA, and NIST 800-53A**. The core innovations are:

- **Anti-hallucination framework** — Every claim requires cited evidence with provenance
- **RAG-based compliance pipeline** — Evidence retrieval against regulatory control libraries
- **Multi-agent orchestration** — LangGraph state machine coordinating specialized agents
- **Evidence-based assessment** — Six valid states, no weasel words, no inference from missing data

### Layer 2 — Complete Vision (What It Becomes)

A unified platform spanning:

| Domain | Frameworks & Standards |
|--------|----------------------|
| **Cybersecurity GRC** | SOC 2, GDPR, HIPAA, NIST 800-53A |
| **AI Governance** | ISO/IEC 42001, NIST AI RMF |
| **OT/ICS Security** | IEC 62443 (Industrial Control Systems) |
| **Cyber Risk Quantification** | NIST CSF 2.0/RMF, FAIR |
| **Blockchain & Cryptocurrency** | BSA/AML, FinCEN Travel Rule, FATF Rec. 16 |
| **Cross-Border Payments** | ISO 20022, ISO 20023 |

### Layer 3 — XRP/XRPL Proof-of-Concept Use Cases

Two blockchain compliance use cases demonstrate how the agent architecture extends to financial services:

#### AuditPack — Automated Compliance Reporting

Automated compliance reporting and audit package generation for companies using XRP/XRPL rails — payment processors, remittance startups, and corporate treasury operations.

**How the existing agents extend:**

| Agent | AuditPack Function |
|-------|-------------------|
| **Compliance Checker** | Validates BSA/AML and FinCEN Travel Rule adherence against XRPL transaction records |
| **Log Analyzer** | Monitors XRPL transaction streams for suspicious patterns, velocity anomalies, and sanctions-list matches |
| **Code Analyzer** | Audits smart contract hooks and payment channel logic for compliance-gate integrity |

**Core deliverables:**
- Monthly compliance packages with transaction-level evidence citations
- Sanctions screening results with OFAC/SDN match provenance
- Travel Rule compliance reports (originator/beneficiary data completeness)
- Evidence vault integration — all artifacts hashed (SHA-256) and timestamped per the anti-hallucination framework's provenance chain

**Regulatory framework mappings:** BSA/AML, FinCEN Travel Rule (31 CFR 1010.410), FATF Recommendation 16, state MSB licensing requirements.

#### ContractorPay — Escrow-Based International Payouts

International contractor payout platform using XRPL escrow with compliance gates. Every payout passes through a seven-stage gate sequence before funds release:

```
KYC/KYB Verification → Sanctions Screening → Risk Scoring →
Escrow Hold (XRPL EscrowCreate) → Approval Release (EscrowFinish) →
Post-Transfer Monitoring → Evidence Archival
```

**How the existing agents extend:**

| Agent | ContractorPay Function |
|-------|----------------------|
| **Compliance Checker** | Validates each gate's evidence completeness before advancing to the next stage |
| **Log Analyzer** | Monitors escrow lifecycle events, detects anomalous release patterns, tracks settlement timing |
| **Vulnerability Scanner** | Assesses API endpoints handling KYC data and payment instructions for OWASP Top 10 vulnerabilities |

**Gate sequence detail:**

1. **KYC/KYB** — Identity verification with document-level evidence (government ID, corporate registry, UBO declarations)
2. **Sanctions Screening** — Real-time OFAC/SDN/EU sanctions list checks with match provenance
3. **Risk Scoring** — Composite risk score from jurisdiction risk, transaction velocity, counterparty history
4. **Escrow Hold** — XRPL `EscrowCreate` with cryptographic condition; funds locked on-ledger
5. **Approval Release** — Multi-signature or compliance-officer approval triggers `EscrowFinish`
6. **Post-Transfer Monitoring** — 30/60/90-day lookback for suspicious downstream activity
7. **Evidence Archival** — Complete gate evidence package sealed to the evidence vault with SHA-256 hashing and freshness scoring

**Regulatory framework mappings:** BSA/AML, FinCEN Travel Rule, FATF Recommendation 16, OFAC compliance, IRS 1099 reporting (for US contractors), state MSB licensing.

> **Evidence Vault alignment:** Both AuditPack and ContractorPay use the same evidence provenance infrastructure as the core Security Auditor — every compliance claim cites specific artifacts with source, timestamp, collector, scope, and cryptographic hash. The anti-hallucination framework's CITE_OR_ABSTAIN rule applies identically to blockchain compliance findings.

---

## 🎯 Key Features

- **Four Specialized Agents** orchestrated via LangGraph workflow
- **Anti-Hallucination Framework** — Every claim requires cited evidence
- **Multi-Framework Compliance** — SOC 2, GDPR, HIPAA, NIST 800-53A
- **Evidence-Based Assessment** — Provenance tracking for audit trails
- **Production CLI** — Beautiful Rich-based command-line interface
- **70+ Tests** — Comprehensive test coverage

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SECURITY AUDITOR ORCHESTRATOR                        │
│                   (LangGraph State Machine Workflow)                    │
└────────────────────────────────────┬────────────────────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Vulnerability  │     │     Code        │     │      Log        │
│    Scanner      │     │   Analyzer      │     │    Analyzer     │
│  ───────────    │     │  ───────────    │     │  ───────────    │
│  OWASP ZAP      │     │  OWASP Top 10   │     │  Anomaly        │
│  Integration    │     │  Static Scan    │     │  Detection      │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │   Compliance Checker  │
                     │  ─────────────────    │
                     │  RAG Pipeline         │
                     │  Evidence Retrieval   │
                     │  Gap Analysis         │
                     └───────────┬───────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │    Final Report       │
                     │  ─────────────────    │
                     │  Cited Evidence       │
                     │  Compliance Controls  │
                     │  Remediation Guide    │
                     └───────────────────────┘
```

---

## 🤖 Four Specialized Agents

| Agent | Function | Key Technologies |
|-------|----------|------------------|
| **Vulnerability Scanner** | Detect web security threats | OWASP ZAP, threat modeling |
| **Code Security Analyzer** | OWASP Top 10 compliance | AST parsing, 30+ vulnerability patterns |
| **Log Analyzer** | Anomaly detection | Pattern recognition, event correlation |
| **Compliance Checker** | Framework validation | RAG pipeline, ChromaDB |

---

## 🛡️ Anti-Hallucination Framework

The system enforces five fundamental rules to prevent AI hallucination in compliance assessments:

### Rule 1: Evidence Required
Every claim **MUST** cite specific evidence with artifact ID.
```
❌ "Based on general practices, likely compliant"
✅ "Evidence [CC6.1-E1-001.pdf] dated 2024-03-15 shows approved policy"
```

### Rule 2: No Inference from Missing Evidence
Missing evidence ≠ control doesn't exist.
```
❌ "No firewall config provided, so controls don't exist"
✅ "EVIDENCE_GAP: Firewall config (CC6.6-E1) not collected"
```

### Rule 3: Six Valid Assessment States
- `PASS` — Evidence satisfies requirements
- `FAIL` — Evidence shows non-compliance
- `INSUFFICIENT_EVIDENCE` — Evidence exists but incomplete
- `EVIDENCE_GAP` — Required evidence not collected
- `CONFLICTING_EVIDENCE` — Sources disagree
- `NEEDS_MANUAL_REVIEW` — Human judgment required

### Rule 4: Forbidden "Weasel Words"
These phrases are **prohibited** in assessments:
- "likely", "probably", "appears to be", "seems to"
- "suggests", "implies", "may indicate"

### Rule 5: Provenance Required
Every evidence artifact must have metadata: source, timestamp, collector, scope, hash.

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/jeflowers/ai-security-auditor.git
cd ai-security-auditor

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install package
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Check system status
security-auditor status

# Analyze source code for vulnerabilities
security-auditor analyze-code ./src

# Analyze logs for security events
security-auditor analyze-logs ./logs

# Run full security audit
security-auditor audit ./my-project --output ./reports
```

### Programmatic Usage

```python
from agents.orchestrator import run_audit_sync

# Run a complete audit
report = run_audit_sync(
    audit_id="AUDIT-2025-001",
    framework="SOC2",
    scope={
        "systems": ["app-server-01", "db-server-01"],
        "period_start": "2024-10-01",
        "period_end": "2024-12-31",
    },
    target_path="./my-project",
)

print(f"Status: {report['overall_status']}")
print(f"Findings: {report['summary']['total_findings']}")
print(f"Evidence Gaps: {len(report['evidence_gaps'])}")
```

---

## 📊 CLI Commands

| Command | Description |
|---------|-------------|
| `security-auditor status` | Show agent availability and dependencies |
| `security-auditor analyze-code <path>` | Static code analysis for OWASP Top 10 |
| `security-auditor analyze-logs <path>` | Security event detection in logs |
| `security-auditor scan --target <url>` | OWASP ZAP vulnerability scan |
| `security-auditor compliance <evidence>` | RAG-based compliance assessment |
| `security-auditor audit <project>` | Full 4-phase security audit |

### Example Output

```
┌─────────────────────────────────────────────────────────┐
│ 🛡️ Full Security Audit                              │
│                                                     │
│ Audit ID: AUDIT-20251231-001745                     │
│ Target: ./my-project                                │
│ Framework: SOC2                                     │
└─────────────────────────────────────────────────────────┘

Phase 1/4: Code Security Analysis
──────────────────────────────────────────────────────────
┌─ 📊 Summary ───────────────────────────────────────────┐
│ CRITICAL: 2  HIGH: 2  MEDIUM: 0  LOW: 0  │ Total: 4│
└────────────────────────────────────────────────────────┘
✓ Evidence saved: CC6.6-E4-ANALYSIS-9627e4c43b28
```

---

## 📁 Project Structure

```
ai-security-auditor/
├── agents/
│   ├── code_analyzer/          # Static code analysis agent
│   │   ├── agent.py            # Main CodeSecurityAnalyzerAgent
│   │   ├── models.py           # Finding, Location, Severity models
│   │   ├── parsers.py          # AST parsers (Python, JS, TS, Java)
│   │   └── security_patterns.py # 30+ vulnerability patterns
│   ├── compliance_checker/     # RAG-based compliance agent
│   │   ├── agent.py            # ComplianceChecker with RAG
│   │   └── anti_hallucination.py # Validation rules
│   ├── log_analyzer/           # Log analysis agent
│   │   ├── agent.py            # LogAnalyzerAgent
│   │   └── models.py           # Event types, severity models
│   ├── vulnerability_scanner/  # OWASP ZAP integration
│   │   ├── agent.py            # VulnerabilityScannerAgent
│   │   └── zap_client.py       # ZAP API client
│   └── orchestrator.py         # LangGraph workflow coordinator
├── cli/
│   └── main.py                 # Typer CLI with Rich output
├── collectors/
│   └── evidence_collector.py   # Evidence with provenance tracking
├── frameworks/
│   └── soc2/
│       ├── controls.yaml       # 12 SOC 2 control definitions
│       └── scoring_rubric.yaml # Anti-hallucination rules
├── rag/
│   ├── pipeline.py             # RAG orchestrator
│   ├── document_processor.py   # Control-aware chunking
│   ├── embeddings.py           # Embedding service (OpenAI/local)
│   └── vector_store.py         # ChromaDB integration
├── tests/
│   ├── test_code_analyzer.py   # 40+ code analyzer tests
│   ├── test_log_analyzer.py    # Log analyzer tests
│   ├── test_compliance_checker.py # Compliance tests
│   └── test_rag_pipeline.py    # RAG pipeline tests
└── pyproject.toml              # Package configuration
```

---

## 🔬 Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_code_analyzer.py -v

# Run with coverage
pytest tests/ --cov=agents --cov-report=html
```

**Test Coverage:**
- 70+ tests across all agents
- Unit tests for vulnerability patterns
- Integration tests for CLI commands
- RAG pipeline tests

---

## 🎯 SOC 2 Controls Implemented

| Control | Title | Focus |
|---------|-------|-------|
| CC6.1 | Logical Access Security | Access control policy, MFA |
| CC6.2 | User Registration | Provisioning procedures |
| CC6.3 | User Access Removal | Termination procedures |
| CC6.6 | External Threat Protection | Firewalls, vulnerability scans |
| CC6.7 | Information Transmission | Encryption, DLP |
| CC7.1 | Security Event Detection | SIEM, monitoring |
| CC7.2 | System Monitoring | Log aggregation |
| CC7.3 | Security Event Evaluation | Incident response |
| CC8.1 | Change Management | Change approval process |
| CC9.1 | Risk Assessment | Risk register, reviews |

---

## 🖥️ NVIDIA Edge-Core Architecture (Future)

This project is designed for deployment on NVIDIA's edge-core architecture:

```
Edge (Jetson Orin)          Core (NIM/DGX)
─────────────────           ──────────────
• Agent Orchestrator        • LLM Chat Service
• Local Cache               • Embedding Service
• Document Preprocessor     • Reranking Service
• Web UI                    • Code Analysis Model
```

**Pluggable Model Provider Pattern** enables seamless switching between:
- Cloud APIs (OpenAI) for development
- NIM endpoints for testing
- Local Jetson inference for edge deployment

---

## 🗺️ Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| **Phase 1** | SOC 2, GDPR, HIPAA, NIST 800-53A compliance | ✅ Complete |
| **Phase 2** | XRP/XRPL PoC — AuditPack & ContractorPay | 🔄 In Progress |
| **Phase 3** | AI Governance — ISO/IEC 42001, NIST AI RMF | 📋 Planned |
| **Phase 4** | OT/ICS Security — IEC 62443 | 📋 Planned |
| **Phase 5** | Cyber Risk Quantification — NIST CSF 2.0, FAIR | 📋 Planned |
| **Phase 6** | Cross-Border Payments — ISO 20022/23 | 📋 Planned |

---

## 🎓 Technologies Demonstrated

| Category | Technologies |
|----------|--------------|
| **Agent Frameworks** | LangChain, LangGraph |
| **RAG Pipeline** | ChromaDB, OpenAI Embeddings |
| **Static Analysis** | AST parsing, regex patterns |
| **CLI** | Typer, Rich |
| **Testing** | pytest, pytest-asyncio |
| **Package Management** | pyproject.toml, setuptools |

---

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Chaniyk** - AI/ML Engineer

This project was developed as a capstone demonstration for NVIDIA ML/AI interview preparation, showcasing:
- Multi-agent system design and orchestration
- Production-grade RAG implementation
- Anti-hallucination safeguards for AI reliability
- Edge-to-core deployment architecture understanding
- Evidence-based compliance across cybersecurity, AI governance, and financial services

---

## 🔗 Related Documentation

- [NVIDIA Agentic AI Study Plan](./docs/NVIDIA_Agentic_AI_Study_Plan.md)
- [Edge-Core Architecture Design](./docs/Jetson_NIM_Edge_Core_Architecture.md)
- [OWASP Top 10 Mapping](./docs/owasp_mapping.md)
