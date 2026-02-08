"""
Log Analyzer Agent package.

Provides security event detection and anomaly analysis for system
and application logs.
"""

from .models import (
    AnalysisResult,
    LogAnalysisEvidence,
    LogEntry,
    LogFinding,
    LogLevel,
    SecurityEventType,
    Severity,
    EVENT_TO_SOC2_CONTROLS,
    EVENT_SEVERITY,
    SOC2_CONTROL_DESCRIPTIONS,
)

from .parser import (
    LogParser,
    LogParserFactory,
    ParseResult,
    SyslogParser,
    JSONLogParser,
    ApacheAccessLogParser,
    GenericLogParser,
)

from .patterns import (
    SecurityPattern,
    ALL_PATTERNS,
    AUTH_PATTERNS,
    AUTHZ_PATTERNS,
    SYSTEM_PATTERNS,
    NETWORK_PATTERNS,
    APPLICATION_PATTERNS,
    match_entry,
    get_patterns_by_event_type,
    get_patterns_by_severity,
    get_patterns_by_source,
    get_pattern_stats,
)

from .agent import (
    LogAnalyzerAgent,
    AnalyzerConfig,
)


__all__ = [
    # Models
    "AnalysisResult",
    "LogAnalysisEvidence",
    "LogEntry",
    "LogFinding",
    "LogLevel",
    "SecurityEventType",
    "Severity",
    "EVENT_TO_SOC2_CONTROLS",
    "EVENT_SEVERITY",
    "SOC2_CONTROL_DESCRIPTIONS",
    
    # Parser
    "LogParser",
    "LogParserFactory",
    "ParseResult",
    "SyslogParser",
    "JSONLogParser",
    "ApacheAccessLogParser",
    "GenericLogParser",
    
    # Patterns
    "SecurityPattern",
    "ALL_PATTERNS",
    "AUTH_PATTERNS",
    "AUTHZ_PATTERNS",
    "SYSTEM_PATTERNS",
    "NETWORK_PATTERNS",
    "APPLICATION_PATTERNS",
    "match_entry",
    "get_patterns_by_event_type",
    "get_patterns_by_severity",
    "get_patterns_by_source",
    "get_pattern_stats",
    
    # Agent
    "LogAnalyzerAgent",
    "AnalyzerConfig",
]
