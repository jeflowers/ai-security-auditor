"""
Data models for Code Security Analyzer.

Defines finding structures, analysis results, and evidence artifacts
that integrate with the SOC 2 compliance framework.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class FindingSeverity(Enum):
    """Severity levels for code security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @classmethod
    def from_score(cls, score: float) -> "FindingSeverity":
        """Convert numeric score (0-10) to severity level."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score >= 1.0:
            return cls.LOW
        return cls.INFO


class FindingConfidence(Enum):
    """Confidence levels for findings."""
    CONFIRMED = "confirmed"    # Definite vulnerability
    HIGH = "high"              # Very likely vulnerability  
    MEDIUM = "medium"          # Possible vulnerability
    LOW = "low"                # Potential false positive
    
    @property
    def numeric_value(self) -> int:
        """Numeric value for comparison."""
        return {
            FindingConfidence.CONFIRMED: 4,
            FindingConfidence.HIGH: 3,
            FindingConfidence.MEDIUM: 2,
            FindingConfidence.LOW: 1,
        }[self]


@dataclass
class CodeLocation:
    """Location of a finding in source code."""
    file_path: str
    line_number: int
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    
    # Context
    code_snippet: str = ""
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "code_snippet": self.code_snippet,
            "function_name": self.function_name,
            "class_name": self.class_name,
        }
    
    def __str__(self) -> str:
        return f"{self.file_path}:{self.line_number}"


@dataclass
class CodeFinding:
    """A security finding from static code analysis."""
    
    # Identification
    finding_id: str
    rule_id: str
    title: str
    
    # Classification
    severity: FindingSeverity
    confidence: FindingConfidence
    cwe_id: int
    owasp_category: str
    
    # Location
    location: CodeLocation
    
    # Details
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)
    
    # SOC 2 mapping
    related_controls: list[str] = field(default_factory=list)
    
    # Metadata
    scanner: str = "code_analyzer"
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Optional: raw pattern match info
    match_text: str = ""
    data_flow: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "location": self.location.to_dict(),
            "description": self.description,
            "remediation": self.remediation,
            "references": self.references,
            "related_controls": self.related_controls,
            "scanner": self.scanner,
            "detected_at": self.detected_at.isoformat(),
            "match_text": self.match_text,
            "data_flow": self.data_flow,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "CodeFinding":
        """Create finding from dictionary."""
        location_data = data.get("location", {})
        location = CodeLocation(
            file_path=location_data.get("file_path", ""),
            line_number=location_data.get("line_number", 0),
            column=location_data.get("column", 0),
            end_line=location_data.get("end_line"),
            end_column=location_data.get("end_column"),
            code_snippet=location_data.get("code_snippet", ""),
            function_name=location_data.get("function_name"),
            class_name=location_data.get("class_name"),
        )
        
        return cls(
            finding_id=data["finding_id"],
            rule_id=data["rule_id"],
            title=data["title"],
            severity=FindingSeverity(data["severity"]),
            confidence=FindingConfidence(data["confidence"]),
            cwe_id=data["cwe_id"],
            owasp_category=data["owasp_category"],
            location=location,
            description=data["description"],
            remediation=data["remediation"],
            references=data.get("references", []),
            related_controls=data.get("related_controls", []),
            scanner=data.get("scanner", "code_analyzer"),
            match_text=data.get("match_text", ""),
            data_flow=data.get("data_flow", []),
        )


@dataclass
class AnalysisResult:
    """Result of code analysis scan."""
    
    # Identification
    analysis_id: str
    target_path: str
    
    # Timing
    started_at: datetime
    completed_at: datetime
    
    # Results
    findings: list[CodeFinding] = field(default_factory=list)
    files_scanned: int = 0
    files_with_findings: int = 0
    lines_scanned: int = 0
    
    # Errors during scan
    errors: list[dict] = field(default_factory=list)
    
    # Configuration used
    languages: list[str] = field(default_factory=list)
    rules_applied: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    
    @property
    def total_findings(self) -> int:
        return len(self.findings)
    
    @property
    def findings_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in FindingSeverity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
    
    @property
    def findings_by_owasp(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            cat = finding.owasp_category
            counts[cat] = counts.get(cat, 0) + 1
        return counts
    
    @property
    def affected_controls(self) -> set[str]:
        controls = set()
        for finding in self.findings:
            controls.update(finding.related_controls)
        return controls
    
    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()
    
    def get_findings_by_file(self) -> dict[str, list[CodeFinding]]:
        """Group findings by file path."""
        by_file: dict[str, list[CodeFinding]] = {}
        for finding in self.findings:
            path = finding.location.file_path
            if path not in by_file:
                by_file[path] = []
            by_file[path].append(finding)
        return by_file
    
    def get_findings_by_control(self, control_id: str) -> list[CodeFinding]:
        """Get findings related to a specific SOC 2 control."""
        return [f for f in self.findings if control_id in f.related_controls]
    
    def filter_by_severity(
        self, 
        min_severity: FindingSeverity
    ) -> list[CodeFinding]:
        """Filter findings by minimum severity."""
        severity_order = [
            FindingSeverity.INFO,
            FindingSeverity.LOW,
            FindingSeverity.MEDIUM,
            FindingSeverity.HIGH,
            FindingSeverity.CRITICAL,
        ]
        min_idx = severity_order.index(min_severity)
        return [
            f for f in self.findings 
            if severity_order.index(f.severity) >= min_idx
        ]
    
    def to_dict(self) -> dict:
        return {
            "analysis_id": self.analysis_id,
            "target_path": self.target_path,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "files_scanned": self.files_scanned,
            "files_with_findings": self.files_with_findings,
            "lines_scanned": self.lines_scanned,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_owasp": self.findings_by_owasp,
            "affected_controls": list(self.affected_controls),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "languages": self.languages,
            "rules_applied": self.rules_applied,
            "excluded_paths": self.excluded_paths,
        }


@dataclass 
class AnalysisEvidence:
    """Evidence artifact from code analysis for SOC 2 compliance."""
    
    # Identification
    evidence_id: str
    analysis_id: str
    
    # Source
    target_path: str
    scan_type: str = "static_analysis"
    
    # Timing
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Results summary
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings: list[CodeFinding] = field(default_factory=list)
    
    # Provenance
    scanner_version: str = "1.0.0"
    scan_config: dict = field(default_factory=dict)
    content_hash: str = ""
    
    def compute_hash(self) -> str:
        """Compute content hash for evidence integrity."""
        data = {
            "analysis_id": self.analysis_id,
            "target_path": self.target_path,
            "findings": [f.to_dict() for f in self.findings],
        }
        json_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "analysis_id": self.analysis_id,
            "target_path": self.target_path,
            "scan_type": self.scan_type,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings": [f.to_dict() for f in self.findings],
            "scanner_version": self.scanner_version,
            "scan_config": self.scan_config,
            "content_hash": self.content_hash or self.compute_hash(),
        }
    
    def get_provenance(self) -> dict:
        """Generate provenance sidecar data."""
        return {
            "evidence_id": self.evidence_id,
            "type": "analysis_output",
            "title": f"Code Security Analysis - {self.target_path}",
            "source_system": "Code Security Analyzer",
            "source_type": "static_analysis",
            "collected_at": self.completed_at.isoformat(),
            "collector_id": "code_security_analyzer_agent",
            "scope_systems": [self.target_path],
            "content_hash": self.content_hash or self.compute_hash(),
            "control_ids": ["CC6.6", "CC8.1"],
            "evidence_requirement_ids": ["CC6.6-E4", "CC8.1-E2"],
        }


# CWE to OWASP Top 10 2021 Mapping
CWE_TO_OWASP: dict[int, str] = {
    # A01:2021 – Broken Access Control
    22: "A01:2021",   # Path Traversal
    23: "A01:2021",   # Relative Path Traversal
    284: "A01:2021",  # Improper Access Control
    285: "A01:2021",  # Improper Authorization
    352: "A01:2021",  # CSRF
    359: "A01:2021",  # Privacy Violation
    425: "A01:2021",  # Direct Request
    639: "A01:2021",  # Authorization Bypass
    862: "A01:2021",  # Missing Authorization
    863: "A01:2021",  # Incorrect Authorization
    
    # A02:2021 – Cryptographic Failures
    261: "A02:2021",  # Weak Encoding for Password
    310: "A02:2021",  # Cryptographic Issues
    319: "A02:2021",  # Cleartext Transmission
    326: "A02:2021",  # Inadequate Encryption Strength
    327: "A02:2021",  # Use of Broken Crypto
    328: "A02:2021",  # Reversible One-Way Hash
    330: "A02:2021",  # Insufficient Randomness
    331: "A02:2021",  # Insufficient Entropy
    338: "A02:2021",  # Use of Weak PRNG
    759: "A02:2021",  # Password Without Salt
    760: "A02:2021",  # Predictable Salt
    
    # A03:2021 – Injection
    20: "A03:2021",   # Improper Input Validation
    74: "A03:2021",   # Injection
    77: "A03:2021",   # Command Injection
    78: "A03:2021",   # OS Command Injection
    79: "A03:2021",   # XSS
    80: "A03:2021",   # Basic XSS
    89: "A03:2021",   # SQL Injection
    90: "A03:2021",   # LDAP Injection
    91: "A03:2021",   # XML Injection
    94: "A03:2021",   # Code Injection
    95: "A03:2021",   # Eval Injection
    96: "A03:2021",   # Static Code Injection
    643: "A03:2021",  # XPath Injection
    917: "A03:2021",  # Expression Language Injection
    
    # A04:2021 – Insecure Design
    209: "A04:2021",  # Info Exposure Through Error
    256: "A04:2021",  # Cleartext Storage of Password
    257: "A04:2021",  # Recoverable Password
    311: "A04:2021",  # Missing Encryption
    312: "A04:2021",  # Cleartext Storage of Sensitive
    434: "A04:2021",  # Unrestricted Upload
    501: "A04:2021",  # Trust Boundary Violation
    522: "A04:2021",  # Weak Credentials
    
    # A05:2021 – Security Misconfiguration
    2: "A05:2021",    # Environment
    11: "A05:2021",   # ASP.NET Misconfiguration
    13: "A05:2021",   # PHP Misconfiguration
    260: "A05:2021",  # Password in Configuration
    315: "A05:2021",  # Cleartext in Cookie
    520: "A05:2021",  # .NET Misconfiguration
    611: "A05:2021",  # XXE
    614: "A05:2021",  # Cookie without Secure
    756: "A05:2021",  # Missing Custom Error Page
    
    # A06:2021 – Vulnerable Components
    829: "A06:2021",  # Inclusion of Untrusted Functionality
    1035: "A06:2021", # Vulnerable Third-Party Components
    1104: "A06:2021", # Use of Unmaintained Component
    
    # A07:2021 – Auth Failures
    255: "A07:2021",  # Credentials Management
    259: "A07:2021",  # Hard-coded Password
    287: "A07:2021",  # Improper Authentication
    288: "A07:2021",  # Authentication Bypass
    290: "A07:2021",  # Authentication Bypass by Spoofing
    306: "A07:2021",  # Missing Authentication
    307: "A07:2021",  # Improper Restriction of Auth Attempts
    521: "A07:2021",  # Weak Password Requirements
    613: "A07:2021",  # Insufficient Session Expiration
    798: "A07:2021",  # Hard-coded Credentials
    
    # A08:2021 – Integrity Failures
    345: "A08:2021",  # Insufficient Verification
    353: "A08:2021",  # Missing Integrity Check
    426: "A08:2021",  # Untrusted Search Path
    494: "A08:2021",  # Download Without Integrity Check
    502: "A08:2021",  # Deserialization of Untrusted Data
    829: "A08:2021",  # Inclusion of Untrusted Functionality
    
    # A09:2021 – Logging Failures
    117: "A09:2021",  # Log Injection
    223: "A09:2021",  # Omission of Security-Relevant Info
    532: "A09:2021",  # Log Sensitive Information
    778: "A09:2021",  # Insufficient Logging
    
    # A10:2021 – SSRF
    918: "A10:2021",  # Server-Side Request Forgery
}


# OWASP to SOC 2 Control Mapping
OWASP_TO_SOC2: dict[str, list[str]] = {
    "A01:2021": ["CC6.1", "CC6.2", "CC6.3"],  # Access Control
    "A02:2021": ["CC6.1", "CC6.7"],           # Cryptographic Failures
    "A03:2021": ["CC6.6", "CC6.7"],           # Injection
    "A04:2021": ["CC6.6", "CC8.1"],           # Insecure Design
    "A05:2021": ["CC6.6", "CC6.1"],           # Security Misconfiguration
    "A06:2021": ["CC6.6", "CC7.1"],           # Vulnerable Components
    "A07:2021": ["CC6.1", "CC6.2"],           # Auth Failures
    "A08:2021": ["CC6.6", "CC8.1"],           # Integrity Failures
    "A09:2021": ["CC7.1", "CC7.2", "CC7.3"],  # Logging Failures
    "A10:2021": ["CC6.6"],                     # SSRF
}


def get_owasp_category(cwe_id: int) -> str:
    """Get OWASP Top 10 category from CWE ID."""
    return CWE_TO_OWASP.get(cwe_id, "Unknown")


def get_soc2_controls(owasp_category: str) -> list[str]:
    """Get SOC 2 controls from OWASP category."""
    return OWASP_TO_SOC2.get(owasp_category, ["CC6.6"])


def get_soc2_controls_from_cwe(cwe_id: int) -> list[str]:
    """Get SOC 2 controls directly from CWE ID."""
    owasp = get_owasp_category(cwe_id)
    return get_soc2_controls(owasp)
