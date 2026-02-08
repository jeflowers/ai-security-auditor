# Contributing to AI-Powered Security Auditor

Thank you for your interest in contributing. This guide covers setup, conventions, and submission guidelines.

## Development Setup

```bash
# Clone and set up
git clone https://github.com/lc29337/ai-security-auditor.git
cd ai-security-auditor

# Python backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e ".[dev]"

# Dashboard
cd dashboard && npm install
```

## Code Standards

### Python (Backend / Agents)
- **Formatter**: Black (line length 88)
- **Linter**: Ruff
- **Type checking**: mypy
- **Tests**: pytest with pytest-asyncio

### TypeScript (Dashboard)
- **Framework**: Next.js 14 with App Router
- **Styling**: Tailwind CSS + shadcn/ui
- **Linting**: ESLint (next config)

## Anti-Hallucination Rules

All compliance-related code **must** follow these rules:

1. **Every claim requires evidence** — No assessment without a cited evidence artifact
2. **No weasel words** — Never use: "likely", "probably", "appears to", "seems to", "might", "could be"
3. **Six valid states only** — `PASS`, `FAIL`, `INSUFFICIENT_EVIDENCE`, `EVIDENCE_GAP`, `CONFLICTING_EVIDENCE`, `NEEDS_MANUAL_REVIEW`
4. **Evidence gaps are explicit** — Missing evidence = `EVIDENCE_GAP`, not assumed compliance
5. **Full provenance** — Every evidence artifact must have: source, timestamp, collector, SHA256 hash

## Running Tests

```bash
# Full suite
pytest tests/ -v

# Specific areas
pytest tests/test_anti_hallucination.py -v  # Core validation rules
pytest tests/test_compliance_checker.py -v  # Compliance engine
pytest tests/test_vulnerability_scanner.py -v  # Scanner agent
pytest tests/test_api_routes.py -v  # API endpoints
```

## Branching Strategy

- `main` — Stable release branch
- `develop` — Integration branch
- `feature/*` — New features
- `fix/*` — Bug fixes

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `develop`
3. Write tests for new functionality
4. Ensure all tests pass
5. Submit a PR with a clear description of changes

## Questions?

Open an issue or reach out to the maintainers.
