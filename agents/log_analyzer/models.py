"""
Data models for the Log Analyzer Agent.

Defines structures for log entries, security events, findings,
and SOC 2 control mappings.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import hashlib
import json


class LogLevel(Enum):
    """Standard log levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    ALERT = "ALERT"
    EMERGENCY = "EMERGENCY"
    
    @classmethod
    def from_string(cls, level: str) -> "LogLevel":
        """Convert string to LogLevel, defaulting to INFO."""
        level_upper = level.upper().strip()
        # Handle common variations
        mappings = {
            "WARN": "WARNING",
            "ERR": "ERROR",
            "CRIT": "CRITICAL",
            "EMERG": "EMERGENCY",
            "FATAL": "CRITICAL",
            "NOTICE": "INFO",
            "TRACE": "DEBUG",
        }
        level_upper = mappings.get(level_upper, level_upper)
        try:
            return cls(level_upper)
        except ValueError:
            return cls.INFO


class SecurityEventType(Enum):
    """Types of security events detected in logs."""
    # Authentication events
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    AUTH_SUCCESS_AFTER_FAILURE = "auth_success_after_failure"
    BRUTE_FORCE = "brute_force"
    ACCOUNT_LOCKOUT = "account_lockout"
    
    # Authorization events
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PERMISSION_DENIED = "permission_denied"
    SUDO_USAGE = "sudo_usage"
    
    # System events
    SERVICE_START = "service_start"
    SERVICE_STOP = "service_stop"
    SERVICE_CRASH = "service_crash"
    CONFIG_CHANGE = "config_change"
    SUSPICIOUS_COMMAND = "suspicious_command"
    PROCESS_ANOMALY = "process_anomaly"
    
    # Network events
    CONNECTION_REFUSED = "connection_refused"
    PORT_SCAN = "port_scan"
    UNUSUAL_OUTBOUND = "unusual_outbound"
    DATA_EXFILTRATION = "data_exfiltration"
    
    # Application events
    ERROR_SPIKE = "error_spike"
    SQL_INJECTION_ATTEMPT = "sql_injection_attempt"
    XSS_ATTEMPT = "xss_attempt"
    PATH_TRAVERSAL_ATTEMPT = "path_traversal_attempt"
    
    # Generic
    ANOMALY = "anomaly"
    SECURITY_ALERT = "security_alert"


class Severity(Enum):
    """Finding severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @property
    def score(self) -> float:
        """Numeric score for severity (0-10 scale)."""
        scores = {
            Severity.LOW: 2.5,
            Severity.MEDIUM: 5.0,
            Severity.HIGH: 7.5,
            Severity.CRITICAL: 10.0,
        }
        return scores[self]
    
    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Convert numeric score to Severity."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        else:
            return cls.LOW


# SOC 2 Control Mappings for Security Events
EVENT_TO_SOC2_CONTROLS: dict[SecurityEventType, list[str]] = {
    # CC7.1: Security events are detected
    SecurityEventType.AUTH_FAILURE: ["CC7.1", "CC7.2"],
    SecurityEventType.AUTH_SUCCESS: ["CC7.1"],
    SecurityEventType.AUTH_SUCCESS_AFTER_FAILURE: ["CC7.1", "CC7.2"],
    SecurityEventType.BRUTE_FORCE: ["CC7.1", "CC7.2", "CC7.3"],
    SecurityEventType.ACCOUNT_LOCKOUT: ["CC7.1", "CC7.2"],
    
    SecurityEventType.PRIVILEGE_ESCALATION: ["CC7.1", "CC7.2", "CC7.3"],
    SecurityEventType.UNAUTHORIZED_ACCESS: ["CC7.1", "CC7.2"],
    SecurityEventType.PERMISSION_DENIED: ["CC7.1", "CC7.2"],
    SecurityEventType.SUDO_USAGE: ["CC7.1", "CC7.2"],
    
    SecurityEventType.SERVICE_START: ["CC7.1"],
    SecurityEventType.SERVICE_STOP: ["CC7.1"],
    SecurityEventType.SERVICE_CRASH: ["CC7.1", "CC7.2"],
    SecurityEventType.CONFIG_CHANGE: ["CC7.1", "CC7.2"],
    SecurityEventType.SUSPICIOUS_COMMAND: ["CC7.1", "CC7.2", "CC7.3"],
    SecurityEventType.PROCESS_ANOMALY: ["CC7.1", "CC7.2"],
    
    SecurityEventType.CONNECTION_REFUSED: ["CC7.1"],
    SecurityEventType.PORT_SCAN: ["CC7.1", "CC7.2", "CC7.3"],
    SecurityEventType.UNUSUAL_OUTBOUND: ["CC7.1", "CC7.2"],
    SecurityEventType.DATA_EXFILTRATION: ["CC7.1", "CC7.2", "CC7.3"],
    
    SecurityEventType.ERROR_SPIKE: ["CC7.1", "CC7.2"],
    SecurityEventType.SQL_INJECTION_ATTEMPT: ["CC7.1", "CC7.2", "CC7.3"],
    SecurityEventType.XSS_ATTEMPT: ["CC7.1", "CC7.2", "CC7.3"],
    SecurityEventType.PATH_TRAVERSAL_ATTEMPT: ["CC7.1", "CC7.2", "CC7.3"],
    
    SecurityEventType.ANOMALY: ["CC7.1", "CC7.2"],
    SecurityEventType.SECURITY_ALERT: ["CC7.1", "CC7.2", "CC7.3"],
}


# Event type to default severity mapping
EVENT_SEVERITY: dict[SecurityEventType, Severity] = {
    SecurityEventType.AUTH_FAILURE: Severity.LOW,
    SecurityEventType.AUTH_SUCCESS: Severity.LOW,
    SecurityEventType.AUTH_SUCCESS_AFTER_FAILURE: Severity.MEDIUM,
    SecurityEventType.BRUTE_FORCE: Severity.HIGH,
    SecurityEventType.ACCOUNT_LOCKOUT: Severity.MEDIUM,
    
    SecurityEventType.PRIVILEGE_ESCALATION: Severity.CRITICAL,
    SecurityEventType.UNAUTHORIZED_ACCESS: Severity.HIGH,
    SecurityEventType.PERMISSION_DENIED: Severity.LOW,
    SecurityEventType.SUDO_USAGE: Severity.MEDIUM,
    
    SecurityEventType.SERVICE_START: Severity.LOW,
    SecurityEventType.SERVICE_STOP: Severity.LOW,
    SecurityEventType.SERVICE_CRASH: Severity.MEDIUM,
    SecurityEventType.CONFIG_CHANGE: Severity.MEDIUM,
    SecurityEventType.SUSPICIOUS_COMMAND: Severity.HIGH,
    SecurityEventType.PROCESS_ANOMALY: Severity.MEDIUM,
    
    SecurityEventType.CONNECTION_REFUSED: Severity.LOW,
    SecurityEventType.PORT_SCAN: Severity.HIGH,
    SecurityEventType.UNUSUAL_OUTBOUND: Severity.MEDIUM,
    SecurityEventType.DATA_EXFILTRATION: Severity.CRITICAL,
    
    SecurityEventType.ERROR_SPIKE: Severity.MEDIUM,
    SecurityEventType.SQL_INJECTION_ATTEMPT: Severity.HIGH,
    SecurityEventType.XSS_ATTEMPT: Severity.HIGH,
    SecurityEventType.PATH_TRAVERSAL_ATTEMPT: Severity.HIGH,
    
    SecurityEventType.ANOMALY: Severity.MEDIUM,
    SecurityEventType.SECURITY_ALERT: Severity.HIGH,
}


@dataclass
class LogEntry:
    """Represents a single log entry."""
    timestamp: Optional[datetime]
    message: str
    level: LogLevel = LogLevel.INFO
    source: str = ""
    hostname: str = ""
    
    # Additional metadata
    raw_line: str = ""
    line_number: int = 0
    file_path: str = ""
    
    # Parsed fields (format-specific)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Ensure raw_line is set."""
        if not self.raw_line:
            self.raw_line = self.message
    
    @property
    def timestamp_str(self) -> str:
        """Get timestamp as ISO string."""
        if self.timestamp:
            return self.timestamp.isoformat()
        return "unknown"
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp_str,
            "message": self.message,
            "level": self.level.value,
            "source": self.source,
            "hostname": self.hostname,
            "line_number": self.line_number,
            "file_path": self.file_path,
            "metadata": self.metadata,
        }


@dataclass
class LogFinding:
    """A security finding from log analysis."""
    event_type: SecurityEventType
    severity: Severity
    message: str
    
    # Evidence
    log_entries: list[LogEntry] = field(default_factory=list)
    
    # Context
    source_file: str = ""
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    
    # Additional details
    details: dict[str, Any] = field(default_factory=dict)
    
    # Identifiers
    finding_id: str = ""
    
    def __post_init__(self):
        """Generate finding ID if not provided."""
        if not self.finding_id:
            self.finding_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique finding ID based on content."""
        content = f"{self.event_type.value}:{self.message}:{self.source_file}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]
    
    @property
    def soc2_controls(self) -> list[str]:
        """Get mapped SOC 2 controls for this finding."""
        return EVENT_TO_SOC2_CONTROLS.get(self.event_type, ["CC7.1"])
    
    @property
    def entry_count(self) -> int:
        """Number of log entries associated with this finding."""
        return len(self.log_entries)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "message": self.message,
            "soc2_controls": self.soc2_controls,
            "source_file": self.source_file,
            "entry_count": self.entry_count,
            "time_range": {
                "start": self.time_range_start.isoformat() if self.time_range_start else None,
                "end": self.time_range_end.isoformat() if self.time_range_end else None,
            },
            "details": self.details,
            "log_entries": [e.to_dict() for e in self.log_entries[:5]],  # Limit for report size
        }


@dataclass
class AnalysisResult:
    """Result of log analysis."""
    findings: list[LogFinding] = field(default_factory=list)
    
    # Statistics
    total_entries_processed: int = 0
    entries_by_level: dict[str, int] = field(default_factory=dict)
    entries_by_source: dict[str, int] = field(default_factory=dict)
    
    # Time range
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    
    # Files analyzed
    files_analyzed: list[str] = field(default_factory=list)
    
    # Errors during analysis
    errors: list[str] = field(default_factory=list)
    
    @property
    def finding_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)
    
    @property
    def findings_by_severity(self) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            severity = finding.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    @property
    def findings_by_type(self) -> dict[str, int]:
        """Count findings by event type."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            event_type = finding.event_type.value
            counts[event_type] = counts.get(event_type, 0) + 1
        return counts
    
    @property
    def critical_findings(self) -> list[LogFinding]:
        """Get critical severity findings."""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]
    
    @property
    def high_findings(self) -> list[LogFinding]:
        """Get high severity findings."""
        return [f for f in self.findings if f.severity == Severity.HIGH]
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "summary": {
                "total_findings": self.finding_count,
                "findings_by_severity": self.findings_by_severity,
                "findings_by_type": self.findings_by_type,
                "total_entries_processed": self.total_entries_processed,
                "files_analyzed": len(self.files_analyzed),
            },
            "time_range": {
                "start": self.time_range_start.isoformat() if self.time_range_start else None,
                "end": self.time_range_end.isoformat() if self.time_range_end else None,
            },
            "entries_by_level": self.entries_by_level,
            "entries_by_source": self.entries_by_source,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


@dataclass
class LogAnalysisEvidence:
    """Evidence artifact for SOC 2 compliance."""
    control_id: str
    control_name: str
    evidence_type: str
    
    # Analysis details
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    findings: list[LogFinding] = field(default_factory=list)
    
    # Summary
    summary: str = ""
    
    def __post_init__(self):
        """Generate summary if not provided."""
        if not self.summary:
            self.summary = self._generate_summary()
    
    def _generate_summary(self) -> str:
        """Generate evidence summary."""
        if not self.findings:
            return f"No security events detected for {self.control_id}"
        
        severity_counts = {}
        for f in self.findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        parts = [f"{count} {sev}" for sev, count in severity_counts.items()]
        return f"{self.control_id}: {len(self.findings)} events detected ({', '.join(parts)})"
    
    @property
    def content_hash(self) -> str:
        """SHA256 hash of evidence content for integrity."""
        content = json.dumps({
            "control_id": self.control_id,
            "findings": [f.to_dict() for f in self.findings],
        }, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "evidence_type": self.evidence_type,
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "content_hash": self.content_hash,
            "summary": self.summary,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


# SOC 2 Control descriptions for log analysis
SOC2_CONTROL_DESCRIPTIONS: dict[str, str] = {
    "CC7.1": "The entity detects and monitors security events",
    "CC7.2": "The entity analyzes detected security events and anomalies",
    "CC7.3": "The entity responds to identified security incidents",
}
