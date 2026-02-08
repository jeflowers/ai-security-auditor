# AI-Powered Security Auditor

**Automated compliance assessment with verifiable evidence and anti-hallucination safeguards.**

A proof-of-concept multi-agent AI system demonstrating automated SOC 2, GDPR, HIPAA, and NIST 800-53A compliance assessments — built on the principle that **if you can't prove it, you can't claim it**.

---

## Vision: Unified GRC + AI Governance Platform

> This project is the **proof-of-concept starting point** for a comprehensive Cybersecurity, Governance, Risk & Compliance platform. The current four-framework implementation demonstrates the core architecture; the complete solution extends across the full compliance landscape.

### Platform Roadmap

| Domain | Frameworks / Standards | Status |
|--------|----------------------|--------|
| **IT Compliance** | SOC 2 Type II, GDPR, HIPAA, NIST 800-53A | ✅ Proof of Concept |
| **Cybersecurity GRC** | Governance, Risk & Compliance platform | 🔄 Architecture Phase |
| **AI Governance** | ISO/IEC 42001, NIST AI RMF | 📋 Planned |
| **OT/ICS Security** | IEC 62443 (Operational Technology) | 📋 Planned |
| **Cyber Risk Frameworks** | NIST CSF 2.0/RMF, FAIR | 📋 Planned |
| **Blockchain & Cryptocurrency** | Crypto compliance & audit | 📋 Planned |
| **Cross-Border Payments** | ISO 20022/23 | 📋 Planned |

The architecture is designed from the ground up to support **pluggable compliance frameworks** — adding new standards requires only framework definition files and control mappings, not architectural changes.

---

## Why This Exists

Compliance auditing is broken. Organizations spend hundreds of thousands of dollars on manual assessments that take months, rely on subjective judgment, and produce inconsistent results. Meanwhile, AI tools that claim to "automate" compliance often hallucinate findings — generating plausible-sounding assessments with no evidentiary basis.

This system solves both problems:

- **Speed**: Automated evidence collection and assessment across multiple compliance frameworks
- **Accuracy**: Every claim must cite specific evidence artifacts — no exceptions
- **Transparency**: Complete provenance chain from raw evidence to final assessment
- **Reliability**: Six valid assessment states replace the false binary of "pass/fail"
- **Extensibility**: Pluggable framework architecture supports any compliance standard

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATOR                              │
│              LangGraph Multi-Agent Coordinator                   │
│         (Conditional routing based on severity findings)         │
└──────────────────────────┬───────────────────────────────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
       ▼                   ▼                   ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ Vulnerability│   │    Code      │   │     Log      │
│   Scanner    │   │  Analyzer    │   │   Analyzer   │
│ (OWASP ZAP)  │   │(OWASP Top10)│   │  (Anomaly)   │
└──────────────┘   └──────────────┘   └──────────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │    Compliance     │
                 │     Checker      │
                 │  (RAG + Evidence) │
                 └───────────────────┘
                           │
                           ▼
                 ┌───────────────────┐
                 │   Assessment      │
                 │    Report         │
                 │ (Cited Evidence)  │
                 └───────────────────┘
```

### Agent Responsibilities

| Agent | Purpose | Technology |
|-------|---------|------------|
| **Vulnerability Scanner** | Network and application threat detection | OWASP ZAP, CWE→OWASP→SOC2 mapping |
| **Code Security Analyzer** | Static code analysis against OWASP Top 10 | AST parsing, pattern matching |
| **Log Analyzer** | Anomaly detection in system and access logs | Pattern recognition, statistical analysis |
| **Compliance Checker** | Framework-specific control validation | RAG pipeline, ChromaDB, evidence scoring |

---

## Anti-Hallucination Framework

The core differentiator. While other AI tools generate plausible compliance assessments, this system **cannot** make a claim without evidence.

### Five Validation Rules

| Rule | Enforcement | Example |
|------|------------|---------|
| **CITE_OR_ABSTAIN** | Every claim requires evidence citation | ❌ "Likely compliant" → ✅ "Evidence CC6.1-E1-001 shows approved policy" |
| **CONFIDENCE_SCORING** | Valid scores 0.0–1.0 only | No qualitative hand-waving |
| **NO_WEASEL_WORDS** | Forbidden: "likely", "probably", "appears to", "seems to" | Hard validation at assessment time |
| **SCOPE_BOUNDARY** | Findings must stay within evidence scope | Cannot infer control B from control A |
| **PROVENANCE_CHAIN** | Full evidence lineage: source → hash → timestamp → collector | SHA256 integrity verification |

### Six Valid Assessment States

```
PASS                    Evidence satisfies all requirements
FAIL                    Evidence demonstrates non-compliance
INSUFFICIENT_EVIDENCE   Evidence exists but is incomplete
EVIDENCE_GAP            Required evidence not yet collected
CONFLICTING_EVIDENCE    Multiple sources disagree
NEEDS_MANUAL_REVIEW     Human judgment required
```

There is no "probably compliant." If the system cannot prove it, it says so explicitly.

---

## Supported Frameworks (Proof of Concept)

| Framework | Controls | Status |
|-----------|----------|--------|
| **SOC 2 Type II** | 10 Trust Service Criteria controls | ✅ Full implementation |
| **GDPR** | Data protection controls | ✅ Framework defined |
| **HIPAA** | Healthcare security controls | ✅ Framework defined |
| **NIST 800-53A** | Federal security assessment controls | ✅ Framework defined |

---

## Tech Stack

### Backend
- **Python 3.10+** — Core runtime
- **FastAPI** — REST API with WebSocket support for real-time audit progress
- **LangChain / LangGraph** — Agent orchestration and workflow management
- **ChromaDB** — Vector database for RAG-based compliance reasoning
- **OWASP ZAP** — Vulnerability scanning engine

### Frontend
- **Next.js 14** — React framework with TypeScript
- **Tailwind CSS + shadcn/ui** — Component library
- **Recharts** — Data visualization
- **Zustand** — State management

### AI/ML Pipeline
- **RAG Pipeline** — Control-aware document chunking, hybrid semantic + keyword search
- **Evidence Scoring** — Freshness windows (within 30d=1.0, 60d=0.7, 90d=0.3, 180d+=0.0)
- **Pluggable Model Providers** — OpenAI API, NVIDIA NIM microservices, local inference

---

## Project Structure

```
ai-security-auditor/
├── agents/                        # Multi-agent system
│   ├── orchestrator.py            #   LangGraph workflow coordinator
│   ├── compliance_checker/        #   RAG-based compliance evaluation
│   ├── vulnerability_scanner/     #   OWASP ZAP integration
│   ├── code_analyzer/             #   Static code analysis
│   └── log_analyzer/              #   Anomaly detection
├── api/                           # FastAPI backend
│   ├── routes.py                  #   REST + WebSocket endpoints
│   └── models.py                  #   Pydantic request/response models
├── collectors/                    # Evidence collection framework
├── dashboard/                     # Next.js frontend
│   └── src/
│       ├── app/                   #   App router pages
│       ├── components/            #   UI components
│       ├── hooks/                 #   Custom React hooks
│       └── types/                 #   TypeScript definitions
├── frameworks/                    # Compliance framework definitions
│   ├── soc2/                      #   SOC 2 controls + scoring rubric
│   ├── gdpr/                      #   GDPR controls
│   ├── hipaa/                     #   HIPAA controls
│   └── nist800-53a/               #   NIST 800-53A controls
├── rag/                           # RAG pipeline
├── tests/                         # Comprehensive test suite
├── cli/                           # Command-line interface
├── utils/                         # Shared utilities
└── scripts/                       # Demo and setup scripts
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+ (for dashboard)
- OWASP ZAP (optional — mock client available for testing)

### Backend Setup

```bash
git clone https://github.com/lc29337/ai-security-auditor.git
cd ai-security-auditor

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: Set up API keys
cp .env.example .env
# Edit .env with your keys (OpenAI for embeddings, etc.)
```

### Dashboard Setup

```bash
cd dashboard
npm install
npm run dev
# Dashboard available at http://localhost:3000
```

### Start the API Server

```bash
uvicorn api.routes:app --reload --port 8000
```

### Run Tests

```bash
# All tests
pytest tests/ -v

# Specific agent tests
pytest tests/test_compliance_checker.py -v
pytest tests/test_vulnerability_scanner.py -v
pytest tests/test_code_analyzer.py -v
pytest tests/test_log_analyzer.py -v

# Anti-hallucination validation tests
pytest tests/test_anti_hallucination.py -v
```

---

## Quick Demo

```python
from agents.vulnerability_scanner import VulnerabilityScannerAgent

# Use mock client (no ZAP instance needed)
agent = VulnerabilityScannerAgent(mock=True)

async with agent.zap:
    evidence = await agent.scan("https://example.com")
    summary = agent.generate_summary(evidence)
    print(f"Findings: {summary['total_findings']}")
    print(f"By severity: {summary['by_severity']}")
```

```python
from rag import ComplianceRAGPipeline
from agents.compliance_checker.rag_agent import RAGComplianceChecker
from pathlib import Path

# Initialize RAG pipeline
pipeline = ComplianceRAGPipeline(persist_dir=Path("rag_data"))
await pipeline.index_all(frameworks_dir=Path("frameworks"))

# Run compliance assessment
checker = RAGComplianceChecker(
    rag_pipeline=pipeline,
    controls_path=Path("frameworks/soc2/controls.yaml")
)
assessment = await checker.assess_control("CC6.1", collected_evidence={})
print(f"Status: {assessment.status}")  # → EVIDENCE_GAP (no evidence provided)
```

---

## Roadmap

### Completed
- ✅ Multi-agent orchestrator with LangGraph workflow
- ✅ Four specialized agents (vulnerability, code, log, compliance)
- ✅ Anti-hallucination framework with five validation rules
- ✅ RAG pipeline with ChromaDB and control-aware chunking
- ✅ Evidence collection framework with SHA256 provenance
- ✅ SOC 2, GDPR, HIPAA, and NIST 800-53A framework definitions
- ✅ Next.js dashboard with real-time WebSocket updates
- ✅ FastAPI backend with REST endpoints
- ✅ Comprehensive test suite

### In Progress
- 🔄 Multi-tenant architecture for scalable deployment
- 🔄 LLM integration for automated compliance reasoning
- 🔄 Cybersecurity GRC platform architecture

### Planned — Platform Expansion
- 📋 AI Governance (ISO/IEC 42001, NIST AI RMF)
- 📋 OT/ICS Security (IEC 62443)
- 📋 NIST CSF 2.0/RMF + FAIR risk quantification
- 📋 Blockchain & Cryptocurrency compliance
- 📋 ISO 20022/23 cross-border payments compliance
- 📋 PDF/HTML report generation
- 📋 External integrations (Okta, Jira, AWS Config)
- 📋 NVIDIA Jetson Orin edge deployment with TensorRT-LLM
- 📋 CI/CD pipeline with automated security scanning

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

---

## License

MIT — see [LICENSE](LICENSE) for details.
