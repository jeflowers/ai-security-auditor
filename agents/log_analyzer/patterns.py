"""
Security Event Patterns for Log Analysis.

Defines regex patterns and rules for detecting security-relevant events
in log entries.
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Any

from .models import SecurityEventType, Severity, LogEntry


@dataclass
class SecurityPattern:
    """A pattern for detecting security events."""
    name: str
    event_type: SecurityEventType
    severity: Severity
    description: str
    
    # Detection
    regex: Optional[re.Pattern] = None
    keywords: list[str] = field(default_factory=list)
    
    # Conditions
    log_levels: list[str] = field(default_factory=list)  # Restrict to certain levels
    sources: list[str] = field(default_factory=list)  # Restrict to certain sources
    
    # Context
    recommendation: str = ""
    
    def matches(self, entry: LogEntry) -> bool:
        """Check if entry matches this pattern."""
        # Check log level filter
        if self.log_levels and entry.level.value not in self.log_levels:
            return False
        
        # Check source filter
        if self.sources:
            source_match = any(s.lower() in entry.source.lower() for s in self.sources)
            if not source_match:
                return False
        
        message = entry.message.lower()
        
        # Check regex
        if self.regex:
            if self.regex.search(entry.message):
                return True
        
        # Check keywords
        if self.keywords:
            for keyword in self.keywords:
                if keyword.lower() in message:
                    return True
        
        return False


# =============================================================================
# Authentication Patterns
# =============================================================================

AUTH_PATTERNS = [
    SecurityPattern(
        name="failed_password",
        event_type=SecurityEventType.AUTH_FAILURE,
        severity=Severity.LOW,
        description="Failed password authentication attempt",
        regex=re.compile(r'failed\s+password\s+for\s+(\S+)', re.IGNORECASE),
        keywords=["authentication failure", "login failed", "invalid password"],
        sources=["sshd", "auth", "pam", "sudo", "login"],
        recommendation="Monitor for brute force patterns. Consider implementing account lockout.",
    ),
    SecurityPattern(
        name="invalid_user",
        event_type=SecurityEventType.AUTH_FAILURE,
        severity=Severity.MEDIUM,
        description="Authentication attempt for non-existent user",
        regex=re.compile(r'invalid\s+user\s+(\S+)', re.IGNORECASE),
        keywords=["unknown user", "no such user", "user not found"],
        sources=["sshd", "auth", "pam"],
        recommendation="Block IPs attempting to authenticate as unknown users.",
    ),
    SecurityPattern(
        name="auth_success_root",
        event_type=SecurityEventType.AUTH_SUCCESS,
        severity=Severity.MEDIUM,
        description="Successful root/admin authentication",
        regex=re.compile(r'accepted\s+\S+\s+for\s+(root|admin|administrator)', re.IGNORECASE),
        keywords=[],
        sources=["sshd", "auth"],
        recommendation="Audit all root login sessions. Consider disabling direct root login.",
    ),
    SecurityPattern(
        name="multiple_failures",
        event_type=SecurityEventType.BRUTE_FORCE,
        severity=Severity.HIGH,
        description="Multiple authentication failures detected",
        regex=re.compile(r'(\d+)\s+authentication\s+failures?', re.IGNORECASE),
        keywords=["too many authentication failures", "maximum authentication attempts"],
        sources=["sshd", "auth", "pam"],
        recommendation="Implement fail2ban or similar intrusion prevention.",
    ),
    SecurityPattern(
        name="account_locked",
        event_type=SecurityEventType.ACCOUNT_LOCKOUT,
        severity=Severity.MEDIUM,
        description="Account has been locked due to failed attempts",
        regex=re.compile(r'account\s+(locked|disabled)', re.IGNORECASE),
        keywords=["user locked out", "account locked", "too many failures"],
        recommendation="Review if lockout is due to attack or user error.",
    ),
]

# =============================================================================
# Authorization Patterns
# =============================================================================

AUTHZ_PATTERNS = [
    SecurityPattern(
        name="sudo_usage",
        event_type=SecurityEventType.SUDO_USAGE,
        severity=Severity.LOW,
        description="User executed command with sudo",
        regex=re.compile(r'(\S+)\s*:\s*.*COMMAND=(.+)$', re.IGNORECASE),
        keywords=["sudo:", "executed as root"],
        sources=["sudo"],
        recommendation="Ensure sudo usage aligns with user responsibilities.",
    ),
    SecurityPattern(
        name="sudo_failure",
        event_type=SecurityEventType.UNAUTHORIZED_ACCESS,
        severity=Severity.HIGH,
        description="Failed sudo attempt - unauthorized privilege escalation",
        regex=re.compile(r'user\s+NOT\s+in\s+sudoers', re.IGNORECASE),
        keywords=["not in sudoers", "sudo: authentication failure", "permission denied"],
        sources=["sudo", "auth"],
        recommendation="Investigate unauthorized privilege escalation attempts.",
    ),
    SecurityPattern(
        name="permission_denied",
        event_type=SecurityEventType.PERMISSION_DENIED,
        severity=Severity.LOW,
        description="Access denied to resource",
        regex=re.compile(r'permission\s+denied|access\s+denied|forbidden', re.IGNORECASE),
        keywords=["403 forbidden", "unauthorized access", "not authorized"],
        recommendation="Review if access denial is expected or indicates misconfiguration.",
    ),
    SecurityPattern(
        name="privilege_escalation",
        event_type=SecurityEventType.PRIVILEGE_ESCALATION,
        severity=Severity.CRITICAL,
        description="Potential privilege escalation detected",
        regex=re.compile(r'privilege\s+escalat|setuid|setgid|capability\s+change', re.IGNORECASE),
        keywords=["became root", "changed user to root", "uid=0"],
        recommendation="Immediately investigate privilege escalation events.",
    ),
]

# =============================================================================
# System Patterns
# =============================================================================

SYSTEM_PATTERNS = [
    SecurityPattern(
        name="service_start",
        event_type=SecurityEventType.SERVICE_START,
        severity=Severity.LOW,
        description="System service started",
        regex=re.compile(r'(started|starting)\s+(\S+)\s*service', re.IGNORECASE),
        keywords=["service started", "daemon started", "process started"],
        sources=["systemd", "init", "kernel"],
        recommendation="Verify service start was expected.",
    ),
    SecurityPattern(
        name="service_stop",
        event_type=SecurityEventType.SERVICE_STOP,
        severity=Severity.LOW,
        description="System service stopped",
        regex=re.compile(r'(stopped|stopping)\s+(\S+)\s*service', re.IGNORECASE),
        keywords=["service stopped", "daemon stopped", "process terminated"],
        sources=["systemd", "init", "kernel"],
        recommendation="Verify service stop was expected.",
    ),
    SecurityPattern(
        name="service_crash",
        event_type=SecurityEventType.SERVICE_CRASH,
        severity=Severity.MEDIUM,
        description="Service crashed or failed unexpectedly",
        regex=re.compile(r'(segfault|core\s+dump|crashed|failed\s+to\s+start|service\s+failed)', re.IGNORECASE),
        keywords=["segmentation fault", "abnormal termination", "killed by signal"],
        log_levels=["ERROR", "CRITICAL", "ALERT", "EMERGENCY"],
        recommendation="Investigate crash cause. Check for exploitation attempts.",
    ),
    SecurityPattern(
        name="config_change",
        event_type=SecurityEventType.CONFIG_CHANGE,
        severity=Severity.MEDIUM,
        description="Configuration file modified",
        regex=re.compile(r'(configuration\s+(changed|modified|updated)|config\s+reload)', re.IGNORECASE),
        keywords=["config changed", "settings updated", "reloading configuration"],
        recommendation="Audit configuration changes for unauthorized modifications.",
    ),
    SecurityPattern(
        name="suspicious_command",
        event_type=SecurityEventType.SUSPICIOUS_COMMAND,
        severity=Severity.HIGH,
        description="Potentially suspicious command executed",
        regex=re.compile(
            r'(wget|curl|nc|netcat|nmap|masscan|hydra|john|hashcat|'
            r'base64\s+-d|eval\s*\(|python\s+-c|perl\s+-e|'
            r'/etc/passwd|/etc/shadow|\.bash_history|'
            r'chmod\s+777|chmod\s+\+s)',
            re.IGNORECASE
        ),
        keywords=[],
        recommendation="Investigate suspicious command usage immediately.",
    ),
    SecurityPattern(
        name="kernel_error",
        event_type=SecurityEventType.PROCESS_ANOMALY,
        severity=Severity.MEDIUM,
        description="Kernel-level error or warning",
        regex=re.compile(r'kernel:\s*.*(error|warning|panic|oops)', re.IGNORECASE),
        keywords=["kernel panic", "kernel oops", "hardware error"],
        sources=["kernel"],
        log_levels=["ERROR", "CRITICAL", "ALERT", "EMERGENCY"],
        recommendation="Review kernel errors for security implications.",
    ),
]

# =============================================================================
# Network Patterns
# =============================================================================

NETWORK_PATTERNS = [
    SecurityPattern(
        name="connection_refused",
        event_type=SecurityEventType.CONNECTION_REFUSED,
        severity=Severity.LOW,
        description="Network connection was refused",
        regex=re.compile(r'connection\s+refused|ECONNREFUSED', re.IGNORECASE),
        keywords=["refused connect", "port closed"],
        recommendation="Check if service is running on target port.",
    ),
    SecurityPattern(
        name="port_scan_indicator",
        event_type=SecurityEventType.PORT_SCAN,
        severity=Severity.HIGH,
        description="Potential port scanning activity detected",
        regex=re.compile(
            r'(port\s+scan|SYN\s+flood|possible\s+attack|'
            r'connection\s+from\s+\S+\s+port\s+\d+.*denied)',
            re.IGNORECASE
        ),
        keywords=["nmap", "masscan", "port scanner detected"],
        recommendation="Block scanning IP. Review firewall rules.",
    ),
    SecurityPattern(
        name="firewall_block",
        event_type=SecurityEventType.CONNECTION_REFUSED,
        severity=Severity.LOW,
        description="Firewall blocked connection",
        regex=re.compile(r'(iptables|firewall|nft|ufw).*(block|drop|reject)', re.IGNORECASE),
        keywords=["blocked by firewall", "dropped packet"],
        sources=["kernel", "iptables", "firewalld", "ufw"],
        recommendation="Review if blocked traffic is expected.",
    ),
    SecurityPattern(
        name="unusual_outbound",
        event_type=SecurityEventType.UNUSUAL_OUTBOUND,
        severity=Severity.MEDIUM,
        description="Unusual outbound connection detected",
        regex=re.compile(
            r'(outbound|egress).*(unusual|suspicious|blocked)|'
            r'connection\s+to\s+(external|unknown)',
            re.IGNORECASE
        ),
        keywords=["data transfer to external", "unusual destination"],
        recommendation="Investigate outbound traffic for data exfiltration.",
    ),
    SecurityPattern(
        name="data_exfiltration",
        event_type=SecurityEventType.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        description="Potential data exfiltration indicators",
        regex=re.compile(
            r'(large\s+data\s+transfer|exfiltrat|'
            r'unusual\s+upload|sensitive\s+data\s+access)',
            re.IGNORECASE
        ),
        keywords=["bulk download", "mass data transfer"],
        recommendation="Immediately investigate potential data breach.",
    ),
]

# =============================================================================
# Application Security Patterns
# =============================================================================

APPLICATION_PATTERNS = [
    SecurityPattern(
        name="sql_injection_attempt",
        event_type=SecurityEventType.SQL_INJECTION_ATTEMPT,
        severity=Severity.HIGH,
        description="SQL injection attempt in request",
        regex=re.compile(
            r"(union\s+select|select\s+.*\s+from|"
            r"'\s*or\s+'1'\s*=\s*'1|"
            r";\s*drop\s+table|"
            r"--\s*$|"
            r"1\s*=\s*1|"
            r"'\s*;\s*--)",
            re.IGNORECASE
        ),
        keywords=["sql syntax error", "mysql error", "postgres error", "sqlite error"],
        recommendation="Review and sanitize input handling. Implement WAF rules.",
    ),
    SecurityPattern(
        name="xss_attempt",
        event_type=SecurityEventType.XSS_ATTEMPT,
        severity=Severity.HIGH,
        description="Cross-site scripting attempt in request",
        regex=re.compile(
            r'(<script|javascript:|onerror\s*=|onload\s*=|'
            r'<img[^>]+onerror|<svg[^>]+onload)',
            re.IGNORECASE
        ),
        keywords=["xss detected", "script injection"],
        recommendation="Implement content security policy. Sanitize output.",
    ),
    SecurityPattern(
        name="path_traversal_attempt",
        event_type=SecurityEventType.PATH_TRAVERSAL_ATTEMPT,
        severity=Severity.HIGH,
        description="Path traversal attempt in request",
        regex=re.compile(r'(\.\./|\.\.\%2f|\.\.\\|%2e%2e)', re.IGNORECASE),
        keywords=["directory traversal", "path traversal detected"],
        recommendation="Validate and sanitize file paths. Implement chroot.",
    ),
    SecurityPattern(
        name="error_spike",
        event_type=SecurityEventType.ERROR_SPIKE,
        severity=Severity.MEDIUM,
        description="Unusual spike in application errors",
        regex=re.compile(r'(exception|error|failure|crash)', re.IGNORECASE),
        log_levels=["ERROR", "CRITICAL"],
        recommendation="Investigate error patterns for attack indicators.",
    ),
    SecurityPattern(
        name="http_error_4xx",
        event_type=SecurityEventType.UNAUTHORIZED_ACCESS,
        severity=Severity.LOW,
        description="HTTP 4xx client error",
        regex=re.compile(r'\s(401|403|404|405)\s'),
        keywords=["unauthorized", "forbidden", "not found"],
        recommendation="Review access control configuration.",
    ),
    SecurityPattern(
        name="http_error_5xx",
        event_type=SecurityEventType.ERROR_SPIKE,
        severity=Severity.MEDIUM,
        description="HTTP 5xx server error",
        regex=re.compile(r'\s(500|502|503|504)\s'),
        keywords=["internal server error", "bad gateway", "service unavailable"],
        log_levels=["ERROR", "CRITICAL"],
        recommendation="Investigate server errors for stability issues.",
    ),
]


# =============================================================================
# Pattern Registry
# =============================================================================

ALL_PATTERNS: list[SecurityPattern] = (
    AUTH_PATTERNS +
    AUTHZ_PATTERNS +
    SYSTEM_PATTERNS +
    NETWORK_PATTERNS +
    APPLICATION_PATTERNS
)


def get_patterns_by_event_type(event_type: SecurityEventType) -> list[SecurityPattern]:
    """Get all patterns for a specific event type."""
    return [p for p in ALL_PATTERNS if p.event_type == event_type]


def get_patterns_by_severity(min_severity: Severity) -> list[SecurityPattern]:
    """Get patterns with severity >= min_severity."""
    severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_index = severity_order.index(min_severity)
    return [p for p in ALL_PATTERNS if severity_order.index(p.severity) >= min_index]


def get_patterns_by_source(source: str) -> list[SecurityPattern]:
    """Get patterns that apply to a specific log source."""
    result = []
    for pattern in ALL_PATTERNS:
        if not pattern.sources:  # No source restriction
            result.append(pattern)
        elif any(s.lower() in source.lower() for s in pattern.sources):
            result.append(pattern)
    return result


def match_entry(entry: LogEntry) -> list[SecurityPattern]:
    """Find all patterns that match a log entry."""
    return [p for p in ALL_PATTERNS if p.matches(entry)]


def get_pattern_stats() -> dict[str, Any]:
    """Get statistics about available patterns."""
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    
    for pattern in ALL_PATTERNS:
        event_type = pattern.event_type.value
        by_type[event_type] = by_type.get(event_type, 0) + 1
        
        severity = pattern.severity.value
        by_severity[severity] = by_severity.get(severity, 0) + 1
    
    return {
        "total_patterns": len(ALL_PATTERNS),
        "by_event_type": by_type,
        "by_severity": by_severity,
    }
