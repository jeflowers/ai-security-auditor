"""
AI-Powered Security Auditor Agents

Four specialized agents for comprehensive security assessment:
- Vulnerability Scanner: OWASP ZAP integration
- Code Security Analyzer: OWASP Top 10 compliance
- Log Analyzer: Anomaly detection
- Compliance Checker: RAG-based framework validation
"""

from .code_analyzer.agent import CodeSecurityAnalyzerAgent
from .log_analyzer.agent import LogAnalyzerAgent
from .orchestrator import SecurityAuditOrchestrator

# Lazy imports for optional dependencies
def get_vulnerability_scanner():
    """Get VulnerabilityScannerAgent (requires ZAP client)."""
    from .vulnerability_scanner.agent import VulnerabilityScannerAgent
    return VulnerabilityScannerAgent

def get_compliance_checker():
    """Get ComplianceChecker (requires ChromaDB)."""
    from .compliance_checker.agent import ComplianceChecker
    return ComplianceChecker

__all__ = [
    "CodeSecurityAnalyzerAgent",
    "LogAnalyzerAgent",
    "SecurityAuditOrchestrator",
    "get_vulnerability_scanner",
    "get_compliance_checker",
]
