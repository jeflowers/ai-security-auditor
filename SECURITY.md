# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

## Reporting a Vulnerability

If you discover a security vulnerability in the AI-Powered Security Auditor, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@example.com** (or open a private advisory via GitHub's Security tab)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Fix Timeline**: Depends on severity, typically within 30 days

## Security Design Principles

This project is built on the principle of **evidence-based security assessment**:

1. **No blind trust** — Every compliance claim requires verifiable evidence
2. **Anti-hallucination by design** — The system cannot fabricate findings
3. **Full provenance** — Every evidence artifact is tracked with SHA256 hashing
4. **Conservative defaults** — Missing evidence = explicit gap, never assumed compliance

## Sensitive Data Handling

- API keys and credentials are never committed (enforced via `.gitignore`)
- Evidence data should be treated as sensitive and is excluded from version control
- The `.env.example` file contains placeholder values only
