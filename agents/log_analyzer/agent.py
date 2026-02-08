"""
Log Analyzer Agent for Security Event Detection.

Analyzes system and application logs to detect security events,
anomalies, and compliance-relevant activities.
"""

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, Optional

from .models import (
    AnalysisResult,
    LogAnalysisEvidence,
    LogEntry,
    LogFinding,
    SecurityEventType,
    Severity,
    EVENT_TO_SOC2_CONTROLS,
    EVENT_SEVERITY,
    SOC2_CONTROL_DESCRIPTIONS,
)
from .parser import LogParser, LogParserFactory, ParseResult
from .patterns import (
    ALL_PATTERNS,
    SecurityPattern,
    match_entry,
    get_patterns_by_severity,
)


@dataclass
class AnalyzerConfig:
    """Configuration for the Log Analyzer Agent."""
    # Severity filtering
    min_severity: Severity = Severity.LOW
    
    # Anomaly detection thresholds
    brute_force_threshold: int = 5  # Failed logins before flagging
    brute_force_window_minutes: int = 10
    error_spike_threshold: int = 10  # Errors per minute
    
    # Time-based anomaly detection
    unusual_hour_start: int = 22  # 10 PM
    unusual_hour_end: int = 6  # 6 AM
    
    # File handling
    max_file_size_mb: int = 100
    max_entries_per_file: int = 1_000_000
    
    # Pattern filtering
    exclude_sources: list[str] = field(default_factory=list)
    include_sources: list[str] = field(default_factory=list)
    
    # Deduplication
    deduplicate_window_seconds: int = 60


class LogAnalyzerAgent:
    """
    Agent for analyzing logs and detecting security events.
    
    Supports:
    - Pattern-based detection (auth failures, privilege escalation, etc.)
    - Anomaly detection (brute force, error spikes)
    - Time-based anomaly detection (unusual hours)
    - SOC 2 compliance evidence generation
    """
    
    def __init__(self, config: Optional[AnalyzerConfig] = None):
        """Initialize the agent with optional configuration."""
        self.config = config or AnalyzerConfig()
        self._findings: list[LogFinding] = []
        self._entry_stats: dict[str, int] = defaultdict(int)
        
        # For anomaly detection
        self._auth_failures: dict[str, list[datetime]] = defaultdict(list)
        self._error_counts: dict[str, list[datetime]] = defaultdict(list)
    
    def analyze_logs(
        self,
        entries: list[LogEntry],
        source_file: str = "",
    ) -> list[LogFinding]:
        """
        Analyze log entries and return security findings.
        
        Args:
            entries: List of log entries to analyze
            source_file: Source file path for context
            
        Returns:
            List of security findings
        """
        findings: list[LogFinding] = []
        
        for entry in entries:
            # Skip entries from excluded sources
            if self._should_skip_entry(entry):
                continue
            
            # Update statistics
            self._entry_stats[entry.level.value] += 1
            if entry.source:
                self._entry_stats[f"source:{entry.source}"] += 1
            
            # Pattern matching
            matched_patterns = match_entry(entry)
            for pattern in matched_patterns:
                if pattern.severity.score >= self.config.min_severity.score:
                    finding = self._create_finding_from_pattern(
                        pattern, entry, source_file
                    )
                    findings.append(finding)
            
            # Anomaly detection
            anomaly_findings = self._check_anomalies(entry, source_file)
            findings.extend(anomaly_findings)
        
        # Deduplicate findings
        findings = self._deduplicate_findings(findings)
        
        return findings
    
    def analyze_file(
        self,
        file_path: str | Path,
        format_hint: Optional[str] = None,
    ) -> AnalysisResult:
        """
        Analyze a single log file.
        
        Args:
            file_path: Path to the log file
            format_hint: Optional hint for log format (e.g., 'syslog', 'json')
            
        Returns:
            AnalysisResult with findings and statistics
        """
        path = Path(file_path)
        result = AnalysisResult(files_analyzed=[str(path)])
        
        # Check file size
        try:
            size_mb = path.stat().st_size / (1024 * 1024)
            if size_mb > self.config.max_file_size_mb:
                result.errors.append(
                    f"File too large: {size_mb:.1f}MB > {self.config.max_file_size_mb}MB limit"
                )
                return result
        except OSError as e:
            result.errors.append(f"Cannot access file: {e}")
            return result
        
        # Get parser
        if format_hint:
            parser = LogParserFactory.get_parser(format_hint)
        else:
            parser = LogParserFactory.detect_format(path)
        
        # Parse file
        parse_result = parser.parse_file(path)
        result.errors.extend(parse_result.errors)
        
        # Limit entries if needed
        entries = parse_result.entries
        if len(entries) > self.config.max_entries_per_file:
            entries = entries[:self.config.max_entries_per_file]
            result.errors.append(
                f"Truncated to {self.config.max_entries_per_file} entries"
            )
        
        # Analyze entries
        findings = self.analyze_logs(entries, str(path))
        result.findings = findings
        
        # Update statistics
        result.total_entries_processed = len(entries)
        result.entries_by_level = dict(self._get_level_stats(entries))
        result.entries_by_source = dict(self._get_source_stats(entries))
        
        # Set time range
        if entries:
            timestamps = [e.timestamp for e in entries if e.timestamp]
            if timestamps:
                result.time_range_start = min(timestamps)
                result.time_range_end = max(timestamps)
        
        return result
    
    def analyze_directory(
        self,
        dir_path: str | Path,
        pattern: str = "*.log",
        recursive: bool = False,
    ) -> AnalysisResult:
        """
        Analyze all log files in a directory.
        
        Args:
            dir_path: Path to the directory
            pattern: Glob pattern for matching log files
            recursive: Whether to search subdirectories
            
        Returns:
            Combined AnalysisResult for all files
        """
        path = Path(dir_path)
        if not path.is_dir():
            result = AnalysisResult()
            result.errors.append(f"Not a directory: {dir_path}")
            return result
        
        # Find log files
        if recursive:
            log_files = list(path.rglob(pattern))
        else:
            log_files = list(path.glob(pattern))
        
        # Also try common log extensions
        for ext in ['*.log', '*.txt', '*.json']:
            if ext != pattern:
                if recursive:
                    log_files.extend(path.rglob(ext))
                else:
                    log_files.extend(path.glob(ext))
        
        # Remove duplicates
        log_files = list(set(log_files))
        
        combined_result = AnalysisResult()
        
        for log_file in sorted(log_files):
            result = self.analyze_file(log_file)
            
            # Merge results
            combined_result.findings.extend(result.findings)
            combined_result.files_analyzed.extend(result.files_analyzed)
            combined_result.errors.extend(result.errors)
            combined_result.total_entries_processed += result.total_entries_processed
            
            # Merge level stats
            for level, count in result.entries_by_level.items():
                combined_result.entries_by_level[level] = (
                    combined_result.entries_by_level.get(level, 0) + count
                )
            
            # Merge source stats
            for source, count in result.entries_by_source.items():
                combined_result.entries_by_source[source] = (
                    combined_result.entries_by_source.get(source, 0) + count
                )
            
            # Update time range
            if result.time_range_start:
                if not combined_result.time_range_start or result.time_range_start < combined_result.time_range_start:
                    combined_result.time_range_start = result.time_range_start
            if result.time_range_end:
                if not combined_result.time_range_end or result.time_range_end > combined_result.time_range_end:
                    combined_result.time_range_end = result.time_range_end
        
        # Deduplicate combined findings
        combined_result.findings = self._deduplicate_findings(combined_result.findings)
        
        return combined_result
    
    def analyze_string(
        self,
        content: str,
        format_hint: Optional[str] = None,
    ) -> AnalysisResult:
        """
        Analyze log content from a string.
        
        Args:
            content: Log content as a string
            format_hint: Optional hint for log format
            
        Returns:
            AnalysisResult with findings
        """
        lines = content.splitlines()
        
        # Detect format
        if format_hint:
            parser = LogParserFactory.get_parser(format_hint)
        else:
            parser = LogParserFactory.detect_format_from_content(lines[:20])
        
        # Parse content
        parse_result = parser.parse_string(content)
        
        # Analyze
        findings = self.analyze_logs(parse_result.entries, "<string>")
        
        result = AnalysisResult(
            findings=findings,
            total_entries_processed=parse_result.parsed_lines,
            entries_by_level=dict(self._get_level_stats(parse_result.entries)),
            entries_by_source=dict(self._get_source_stats(parse_result.entries)),
            errors=parse_result.errors,
        )
        
        # Set time range
        entries = parse_result.entries
        if entries:
            timestamps = [e.timestamp for e in entries if e.timestamp]
            if timestamps:
                result.time_range_start = min(timestamps)
                result.time_range_end = max(timestamps)
        
        return result
    
    def _should_skip_entry(self, entry: LogEntry) -> bool:
        """Check if entry should be skipped based on config."""
        # Check exclude list
        if self.config.exclude_sources:
            for excluded in self.config.exclude_sources:
                if excluded.lower() in entry.source.lower():
                    return True
        
        # Check include list (if specified, only include matching)
        if self.config.include_sources:
            for included in self.config.include_sources:
                if included.lower() in entry.source.lower():
                    return False
            return True
        
        return False
    
    def _create_finding_from_pattern(
        self,
        pattern: SecurityPattern,
        entry: LogEntry,
        source_file: str,
    ) -> LogFinding:
        """Create a finding from a matched pattern."""
        return LogFinding(
            event_type=pattern.event_type,
            severity=pattern.severity,
            message=f"{pattern.name}: {pattern.description}",
            log_entries=[entry],
            source_file=source_file,
            time_range_start=entry.timestamp,
            time_range_end=entry.timestamp,
            details={
                "pattern_name": pattern.name,
                "recommendation": pattern.recommendation,
                "matched_message": entry.message[:500],
            },
        )
    
    def _check_anomalies(
        self,
        entry: LogEntry,
        source_file: str,
    ) -> list[LogFinding]:
        """Check for anomalies in the log entry."""
        findings: list[LogFinding] = []
        
        # Track auth failures for brute force detection
        if "failed" in entry.message.lower() and any(
            kw in entry.message.lower()
            for kw in ["password", "auth", "login"]
        ):
            key = entry.metadata.get("ip", entry.hostname or "unknown")
            now = entry.timestamp or datetime.now()
            self._auth_failures[key].append(now)
            
            # Check for brute force
            window = timedelta(minutes=self.config.brute_force_window_minutes)
            recent = [
                t for t in self._auth_failures[key]
                if now - t < window
            ]
            self._auth_failures[key] = recent
            
            if len(recent) >= self.config.brute_force_threshold:
                findings.append(LogFinding(
                    event_type=SecurityEventType.BRUTE_FORCE,
                    severity=Severity.HIGH,
                    message=f"Brute force attack detected: {len(recent)} failures from {key}",
                    log_entries=[entry],
                    source_file=source_file,
                    time_range_start=min(recent),
                    time_range_end=max(recent),
                    details={
                        "source": key,
                        "failure_count": len(recent),
                        "window_minutes": self.config.brute_force_window_minutes,
                    },
                ))
        
        # Check for unusual hours
        if entry.timestamp:
            hour = entry.timestamp.hour
            if (
                hour >= self.config.unusual_hour_start or
                hour < self.config.unusual_hour_end
            ):
                # Only flag high-severity events during unusual hours
                matched_patterns = match_entry(entry)
                high_severity = [
                    p for p in matched_patterns
                    if p.severity in [Severity.HIGH, Severity.CRITICAL]
                ]
                if high_severity:
                    findings.append(LogFinding(
                        event_type=SecurityEventType.ANOMALY,
                        severity=Severity.MEDIUM,
                        message=f"Security event during unusual hours ({hour}:00)",
                        log_entries=[entry],
                        source_file=source_file,
                        time_range_start=entry.timestamp,
                        time_range_end=entry.timestamp,
                        details={
                            "hour": hour,
                            "related_patterns": [p.name for p in high_severity],
                        },
                    ))
        
        return findings
    
    def _deduplicate_findings(
        self,
        findings: list[LogFinding],
    ) -> list[LogFinding]:
        """Remove duplicate findings within the deduplication window."""
        if not findings:
            return []
        
        seen: dict[str, LogFinding] = {}
        window = timedelta(seconds=self.config.deduplicate_window_seconds)
        
        for finding in findings:
            # Create deduplication key
            key = f"{finding.event_type.value}:{finding.message}"
            
            if key in seen:
                existing = seen[key]
                # Check time window
                if finding.time_range_start and existing.time_range_end:
                    if finding.time_range_start - existing.time_range_end < window:
                        # Merge findings
                        existing.log_entries.extend(finding.log_entries)
                        if finding.time_range_end:
                            existing.time_range_end = max(
                                existing.time_range_end or finding.time_range_end,
                                finding.time_range_end
                            )
                        continue
            
            seen[key] = finding
        
        return list(seen.values())
    
    def _get_level_stats(self, entries: list[LogEntry]) -> dict[str, int]:
        """Get entry counts by log level."""
        stats: dict[str, int] = defaultdict(int)
        for entry in entries:
            stats[entry.level.value] += 1
        return dict(stats)
    
    def _get_source_stats(self, entries: list[LogEntry]) -> dict[str, int]:
        """Get entry counts by source."""
        stats: dict[str, int] = defaultdict(int)
        for entry in entries:
            source = entry.source or "unknown"
            stats[source] += 1
        return dict(stats)
    
    # =========================================================================
    # SOC 2 Compliance Methods
    # =========================================================================
    
    def generate_evidence(
        self,
        result: AnalysisResult,
        control_id: str,
    ) -> LogAnalysisEvidence:
        """
        Generate evidence artifact for a specific SOC 2 control.
        
        Args:
            result: Analysis result containing findings
            control_id: SOC 2 control ID (e.g., "CC7.1")
            
        Returns:
            Evidence artifact for the control
        """
        # Get findings relevant to this control
        relevant_findings = [
            f for f in result.findings
            if control_id in f.soc2_controls
        ]
        
        control_name = SOC2_CONTROL_DESCRIPTIONS.get(control_id, control_id)
        
        return LogAnalysisEvidence(
            control_id=control_id,
            control_name=control_name,
            evidence_type="log_analysis",
            findings=relevant_findings,
        )
    
    def get_control_evidence(
        self,
        result: AnalysisResult,
    ) -> dict[str, LogAnalysisEvidence]:
        """
        Generate evidence for all relevant SOC 2 controls.
        
        Args:
            result: Analysis result containing findings
            
        Returns:
            Dictionary mapping control IDs to evidence artifacts
        """
        evidence: dict[str, LogAnalysisEvidence] = {}
        
        # CC7.x controls are relevant for log analysis
        for control_id in ["CC7.1", "CC7.2", "CC7.3"]:
            evidence[control_id] = self.generate_evidence(result, control_id)
        
        return evidence
    
    def generate_soc2_report(
        self,
        result: AnalysisResult,
    ) -> dict[str, Any]:
        """
        Generate a comprehensive SOC 2 compliance report.
        
        Args:
            result: Analysis result containing findings
            
        Returns:
            Report dictionary suitable for JSON serialization
        """
        evidence = self.get_control_evidence(result)
        
        # Calculate compliance status
        def get_status(e: LogAnalysisEvidence) -> str:
            critical = [f for f in e.findings if f.severity == Severity.CRITICAL]
            high = [f for f in e.findings if f.severity == Severity.HIGH]
            if critical:
                return "non_compliant"
            elif high:
                return "needs_attention"
            else:
                return "compliant"
        
        return {
            "report_type": "soc2_log_analysis",
            "generated_at": datetime.now().isoformat(),
            "analysis_summary": {
                "files_analyzed": len(result.files_analyzed),
                "entries_processed": result.total_entries_processed,
                "total_findings": result.finding_count,
                "findings_by_severity": result.findings_by_severity,
                "time_range": {
                    "start": result.time_range_start.isoformat() if result.time_range_start else None,
                    "end": result.time_range_end.isoformat() if result.time_range_end else None,
                },
            },
            "controls": {
                control_id: {
                    "name": ev.control_name,
                    "status": get_status(ev),
                    "finding_count": len(ev.findings),
                    "content_hash": ev.content_hash,
                    "summary": ev.summary,
                }
                for control_id, ev in evidence.items()
            },
            "findings": [f.to_dict() for f in result.findings],
            "recommendations": self._generate_recommendations(result),
        }
    
    def _generate_recommendations(
        self,
        result: AnalysisResult,
    ) -> list[dict[str, str]]:
        """Generate recommendations based on findings."""
        recommendations: list[dict[str, str]] = []
        seen_types: set[str] = set()
        
        for finding in result.findings:
            event_type = finding.event_type.value
            if event_type in seen_types:
                continue
            seen_types.add(event_type)
            
            rec = finding.details.get("recommendation", "")
            if rec:
                recommendations.append({
                    "event_type": event_type,
                    "severity": finding.severity.value,
                    "recommendation": rec,
                })
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(key=lambda r: severity_order.get(r["severity"], 4))
        
        return recommendations
    
    def generate_summary(self, result: AnalysisResult) -> str:
        """Generate a human-readable summary of the analysis."""
        lines = [
            "=" * 60,
            "LOG ANALYSIS SUMMARY",
            "=" * 60,
            "",
            f"Files analyzed: {len(result.files_analyzed)}",
            f"Entries processed: {result.total_entries_processed:,}",
            f"Total findings: {result.finding_count}",
            "",
        ]
        
        # Severity breakdown
        if result.findings_by_severity:
            lines.append("Findings by Severity:")
            for severity in ["critical", "high", "medium", "low"]:
                count = result.findings_by_severity.get(severity, 0)
                if count:
                    lines.append(f"  {severity.upper()}: {count}")
            lines.append("")
        
        # Event type breakdown
        if result.findings_by_type:
            lines.append("Findings by Type:")
            for event_type, count in sorted(
                result.findings_by_type.items(),
                key=lambda x: -x[1]
            )[:10]:
                lines.append(f"  {event_type}: {count}")
            lines.append("")
        
        # Time range
        if result.time_range_start and result.time_range_end:
            lines.append(f"Time range: {result.time_range_start} to {result.time_range_end}")
            lines.append("")
        
        # Critical findings
        critical = result.critical_findings
        if critical:
            lines.append("⚠️  CRITICAL FINDINGS:")
            for finding in critical[:5]:
                lines.append(f"  - {finding.message}")
            lines.append("")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
