"""
Tests for the Log Analyzer Agent.

Covers models, parsers, patterns, and main agent functionality.
"""

import pytest
import tempfile
import json
from datetime import datetime, timedelta
from pathlib import Path

from agents.log_analyzer.models import (
    LogEntry,
    LogFinding,
    LogLevel,
    SecurityEventType,
    Severity,
    AnalysisResult,
    LogAnalysisEvidence,
    EVENT_TO_SOC2_CONTROLS,
)
from agents.log_analyzer.parser import (
    SyslogParser,
    JSONLogParser,
    ApacheAccessLogParser,
    GenericLogParser,
    LogParserFactory,
)
from agents.log_analyzer.patterns import (
    ALL_PATTERNS,
    SecurityPattern,
    match_entry,
    get_patterns_by_event_type,
    get_patterns_by_severity,
    get_pattern_stats,
)
from agents.log_analyzer.agent import (
    LogAnalyzerAgent,
    AnalyzerConfig,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def sample_syslog_content():
    """Sample syslog entries."""
    return '''Dec 31 10:30:45 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 31 10:30:46 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 31 10:30:47 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 31 10:30:48 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 31 10:30:49 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 31 10:30:50 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Dec 31 10:31:00 myhost sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2
Dec 31 10:31:15 myhost sudo: admin : user NOT in sudoers
Dec 31 10:31:30 myhost kernel: segfault at 0 ip 00007f1234567890
'''


@pytest.fixture
def sample_json_logs():
    """Sample JSON log entries."""
    return '''{"timestamp": "2024-12-31T10:30:45Z", "level": "ERROR", "message": "Failed password for user admin", "source": "auth"}
{"timestamp": "2024-12-31T10:30:50Z", "level": "WARNING", "message": "Permission denied for /etc/shadow", "source": "security"}
{"timestamp": "2024-12-31T10:31:00Z", "level": "INFO", "message": "User admin logged in successfully", "source": "auth"}
{"timestamp": "2024-12-31T10:31:15Z", "level": "ERROR", "message": "SQL syntax error: SELECT * FROM users WHERE id = 1 OR 1=1", "source": "app"}
'''


@pytest.fixture
def sample_apache_logs():
    """Sample Apache access log entries."""
    return '''192.168.1.100 - - [31/Dec/2024:10:30:45 +0000] "GET /admin HTTP/1.1" 403 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [31/Dec/2024:10:30:46 +0000] "GET /../../etc/passwd HTTP/1.1" 400 567 "-" "curl/7.68.0"
192.168.1.100 - - [31/Dec/2024:10:30:47 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 890 "-" "Mozilla/5.0"
192.168.1.100 - - [31/Dec/2024:10:30:48 +0000] "POST /login HTTP/1.1" 500 234 "-" "Mozilla/5.0"
'''


@pytest.fixture
def analyzer():
    """Create a LogAnalyzerAgent instance."""
    return LogAnalyzerAgent()


@pytest.fixture
def syslog_parser():
    """Create a SyslogParser instance."""
    return SyslogParser()


@pytest.fixture
def json_parser():
    """Create a JSONLogParser instance."""
    return JSONLogParser()


@pytest.fixture
def apache_parser():
    """Create an ApacheAccessLogParser instance."""
    return ApacheAccessLogParser()


# =============================================================================
# Model Tests
# =============================================================================

class TestModels:
    """Tests for data models."""
    
    def test_log_level_from_string(self):
        """Test LogLevel.from_string conversion."""
        assert LogLevel.from_string("ERROR") == LogLevel.ERROR
        assert LogLevel.from_string("error") == LogLevel.ERROR
        assert LogLevel.from_string("WARN") == LogLevel.WARNING
        assert LogLevel.from_string("FATAL") == LogLevel.CRITICAL
        assert LogLevel.from_string("unknown") == LogLevel.INFO
    
    def test_severity_score(self):
        """Test Severity score property."""
        assert Severity.LOW.score == 2.5
        assert Severity.MEDIUM.score == 5.0
        assert Severity.HIGH.score == 7.5
        assert Severity.CRITICAL.score == 10.0
    
    def test_severity_from_score(self):
        """Test Severity.from_score conversion."""
        assert Severity.from_score(2.0) == Severity.LOW
        assert Severity.from_score(5.0) == Severity.MEDIUM
        assert Severity.from_score(8.0) == Severity.HIGH
        assert Severity.from_score(10.0) == Severity.CRITICAL
    
    def test_log_entry_creation(self):
        """Test LogEntry creation."""
        entry = LogEntry(
            timestamp=datetime(2024, 12, 31, 10, 30, 45),
            message="Test message",
            level=LogLevel.ERROR,
            source="test",
            hostname="myhost",
            line_number=1,
        )
        
        assert entry.message == "Test message"
        assert entry.level == LogLevel.ERROR
        assert entry.source == "test"
        assert entry.timestamp_str == "2024-12-31T10:30:45"
    
    def test_log_entry_to_dict(self):
        """Test LogEntry serialization."""
        entry = LogEntry(
            timestamp=datetime(2024, 12, 31, 10, 30, 45),
            message="Test message",
            level=LogLevel.ERROR,
            source="test",
        )
        
        d = entry.to_dict()
        assert d["message"] == "Test message"
        assert d["level"] == "ERROR"
        assert d["source"] == "test"
    
    def test_log_finding_creation(self):
        """Test LogFinding creation."""
        finding = LogFinding(
            event_type=SecurityEventType.AUTH_FAILURE,
            severity=Severity.MEDIUM,
            message="Failed authentication",
        )
        
        assert finding.event_type == SecurityEventType.AUTH_FAILURE
        assert finding.severity == Severity.MEDIUM
        assert len(finding.finding_id) == 12
    
    def test_log_finding_soc2_controls(self):
        """Test LogFinding SOC 2 control mapping."""
        finding = LogFinding(
            event_type=SecurityEventType.BRUTE_FORCE,
            severity=Severity.HIGH,
            message="Brute force detected",
        )
        
        assert "CC7.1" in finding.soc2_controls
        assert "CC7.2" in finding.soc2_controls
        assert "CC7.3" in finding.soc2_controls
    
    def test_analysis_result_properties(self):
        """Test AnalysisResult computed properties."""
        findings = [
            LogFinding(
                event_type=SecurityEventType.AUTH_FAILURE,
                severity=Severity.LOW,
                message="Failed login",
            ),
            LogFinding(
                event_type=SecurityEventType.AUTH_FAILURE,
                severity=Severity.LOW,
                message="Failed login 2",
            ),
            LogFinding(
                event_type=SecurityEventType.BRUTE_FORCE,
                severity=Severity.HIGH,
                message="Brute force",
            ),
        ]
        
        result = AnalysisResult(findings=findings)
        
        assert result.finding_count == 3
        assert result.findings_by_severity["low"] == 2
        assert result.findings_by_severity["high"] == 1
        assert len(result.high_findings) == 1
    
    def test_event_to_soc2_mapping(self):
        """Test event type to SOC 2 control mapping."""
        assert "CC7.1" in EVENT_TO_SOC2_CONTROLS[SecurityEventType.AUTH_FAILURE]
        assert "CC7.3" in EVENT_TO_SOC2_CONTROLS[SecurityEventType.PRIVILEGE_ESCALATION]


# =============================================================================
# Parser Tests
# =============================================================================

class TestSyslogParser:
    """Tests for syslog parser."""
    
    def test_parse_rfc3164(self, syslog_parser):
        """Test parsing RFC 3164 syslog format."""
        line = "Dec 31 10:30:45 myhost sshd[1234]: Failed password for admin"
        entry = syslog_parser.parse_line(line, 1)
        
        assert entry is not None
        assert entry.hostname == "myhost"
        assert entry.source == "sshd"
        assert "Failed password" in entry.message
        assert entry.metadata.get("pid") == "1234"
    
    def test_parse_syslog_with_priority(self, syslog_parser):
        """Test parsing syslog with priority."""
        line = "<34>Dec 31 10:30:45 myhost sshd: Test message"
        entry = syslog_parser.parse_line(line, 1)
        
        assert entry is not None
        assert entry.level == LogLevel.CRITICAL  # 34 % 8 = 2 = CRITICAL
    
    def test_can_parse_detection(self, syslog_parser):
        """Test format detection for syslog."""
        lines = [
            "Dec 31 10:30:45 myhost sshd[1234]: Test message",
            "Dec 31 10:30:46 myhost kernel: Another message",
        ]
        assert syslog_parser.can_parse(lines) is True
    
    def test_parse_file(self, syslog_parser, sample_syslog_content, tmp_path):
        """Test parsing syslog file."""
        log_file = tmp_path / "test.log"
        log_file.write_text(sample_syslog_content)
        
        result = syslog_parser.parse_file(log_file)
        
        assert result.parsed_lines > 0
        assert result.format_detected == "SyslogParser"


class TestJSONLogParser:
    """Tests for JSON log parser."""
    
    def test_parse_json_line(self, json_parser):
        """Test parsing JSON log line."""
        line = '{"timestamp": "2024-12-31T10:30:45Z", "level": "ERROR", "message": "Test error"}'
        entry = json_parser.parse_line(line, 1)
        
        assert entry is not None
        assert entry.message == "Test error"
        assert entry.level == LogLevel.ERROR
    
    def test_parse_json_with_different_field_names(self, json_parser):
        """Test parsing JSON with non-standard field names."""
        line = '{"time": "2024-12-31T10:30:45Z", "severity": "WARN", "msg": "Warning message"}'
        entry = json_parser.parse_line(line, 1)
        
        assert entry is not None
        assert entry.message == "Warning message"
        assert entry.level == LogLevel.WARNING
    
    def test_parse_json_unix_timestamp(self, json_parser):
        """Test parsing JSON with Unix timestamp."""
        line = '{"timestamp": 1735644645, "message": "Test"}'
        entry = json_parser.parse_line(line, 1)
        
        assert entry is not None
        assert entry.timestamp is not None
    
    def test_can_parse_detection(self, json_parser):
        """Test format detection for JSON."""
        lines = [
            '{"timestamp": "2024-12-31T10:30:45Z", "message": "Test"}',
            '{"timestamp": "2024-12-31T10:30:46Z", "message": "Test2"}',
        ]
        assert json_parser.can_parse(lines) is True
    
    def test_invalid_json(self, json_parser):
        """Test handling of invalid JSON."""
        line = "not valid json"
        entry = json_parser.parse_line(line, 1)
        assert entry is None


class TestApacheAccessLogParser:
    """Tests for Apache access log parser."""
    
    def test_parse_combined_log(self, apache_parser):
        """Test parsing combined log format."""
        line = '192.168.1.100 - - [31/Dec/2024:10:30:45 +0000] "GET /page HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        entry = apache_parser.parse_line(line, 1)
        
        assert entry is not None
        assert entry.metadata["ip"] == "192.168.1.100"
        assert entry.metadata["status_code"] == 200
        assert "GET /page" in entry.message
    
    def test_parse_error_status(self, apache_parser):
        """Test log level from HTTP status code."""
        line = '192.168.1.100 - - [31/Dec/2024:10:30:45 +0000] "GET /page HTTP/1.1" 500 1234 "-" "Mozilla/5.0"'
        entry = apache_parser.parse_line(line, 1)
        
        assert entry is not None
        assert entry.level == LogLevel.ERROR
    
    def test_can_parse_detection(self, apache_parser):
        """Test format detection for Apache logs."""
        lines = [
            '192.168.1.100 - - [31/Dec/2024:10:30:45 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla"',
        ]
        assert apache_parser.can_parse(lines) is True


class TestGenericLogParser:
    """Tests for generic log parser."""
    
    def test_parse_generic_with_timestamp(self):
        """Test parsing generic log with ISO timestamp."""
        parser = GenericLogParser()
        line = "2024-12-31 10:30:45 ERROR This is an error message"
        entry = parser.parse_line(line, 1)
        
        assert entry is not None
        assert entry.level == LogLevel.ERROR
        assert entry.timestamp is not None
    
    def test_can_parse_always_true(self):
        """Test that generic parser can always parse."""
        parser = GenericLogParser()
        assert parser.can_parse(["anything"]) is True


class TestLogParserFactory:
    """Tests for parser factory."""
    
    def test_detect_json_format(self):
        """Test detecting JSON format."""
        lines = ['{"message": "test"}'] * 5
        parser = LogParserFactory.detect_format_from_content(lines)
        assert isinstance(parser, JSONLogParser)
    
    def test_detect_syslog_format(self):
        """Test detecting syslog format."""
        lines = ["Dec 31 10:30:45 myhost sshd: test"] * 5
        parser = LogParserFactory.detect_format_from_content(lines)
        assert isinstance(parser, SyslogParser)
    
    def test_get_parser_by_name(self):
        """Test getting parser by name."""
        parser = LogParserFactory.get_parser("json")
        assert isinstance(parser, JSONLogParser)
        
        parser = LogParserFactory.get_parser("syslog")
        assert isinstance(parser, SyslogParser)


# =============================================================================
# Pattern Tests
# =============================================================================

class TestPatterns:
    """Tests for security patterns."""
    
    def test_pattern_count(self):
        """Test that patterns are loaded."""
        assert len(ALL_PATTERNS) > 0
    
    def test_auth_failure_pattern_matches(self):
        """Test authentication failure pattern."""
        entry = LogEntry(
            timestamp=datetime.now(),
            message="Failed password for admin from 192.168.1.100",
            source="sshd",
        )
        
        matches = match_entry(entry)
        event_types = [m.event_type for m in matches]
        assert SecurityEventType.AUTH_FAILURE in event_types
    
    def test_sudo_failure_pattern(self):
        """Test sudo failure pattern."""
        entry = LogEntry(
            timestamp=datetime.now(),
            message="user NOT in sudoers",
            source="sudo",
        )
        
        matches = match_entry(entry)
        event_types = [m.event_type for m in matches]
        assert SecurityEventType.UNAUTHORIZED_ACCESS in event_types
    
    def test_sql_injection_pattern(self):
        """Test SQL injection detection in logs."""
        entry = LogEntry(
            timestamp=datetime.now(),
            message="SELECT * FROM users WHERE id = 1 OR 1=1",
            source="app",
        )
        
        matches = match_entry(entry)
        event_types = [m.event_type for m in matches]
        assert SecurityEventType.SQL_INJECTION_ATTEMPT in event_types
    
    def test_xss_pattern(self):
        """Test XSS detection in logs."""
        entry = LogEntry(
            timestamp=datetime.now(),
            message="Request contains <script>alert(1)</script>",
            source="web",
        )
        
        matches = match_entry(entry)
        event_types = [m.event_type for m in matches]
        assert SecurityEventType.XSS_ATTEMPT in event_types
    
    def test_path_traversal_pattern(self):
        """Test path traversal detection."""
        entry = LogEntry(
            timestamp=datetime.now(),
            message="Request: GET /../../etc/passwd",
            source="web",
        )
        
        matches = match_entry(entry)
        event_types = [m.event_type for m in matches]
        assert SecurityEventType.PATH_TRAVERSAL_ATTEMPT in event_types
    
    def test_get_patterns_by_event_type(self):
        """Test filtering patterns by event type."""
        auth_patterns = get_patterns_by_event_type(SecurityEventType.AUTH_FAILURE)
        assert len(auth_patterns) > 0
        assert all(p.event_type == SecurityEventType.AUTH_FAILURE for p in auth_patterns)
    
    def test_get_patterns_by_severity(self):
        """Test filtering patterns by minimum severity."""
        high_patterns = get_patterns_by_severity(Severity.HIGH)
        assert len(high_patterns) > 0
        assert all(p.severity.score >= Severity.HIGH.score for p in high_patterns)
    
    def test_pattern_stats(self):
        """Test pattern statistics."""
        stats = get_pattern_stats()
        assert stats["total_patterns"] > 0
        assert "by_event_type" in stats
        assert "by_severity" in stats


# =============================================================================
# Agent Tests
# =============================================================================

class TestLogAnalyzerAgent:
    """Tests for the main agent."""
    
    def test_analyze_syslog(self, analyzer, sample_syslog_content):
        """Test analyzing syslog content."""
        result = analyzer.analyze_string(sample_syslog_content)
        
        assert result.total_entries_processed > 0
        assert result.finding_count > 0
    
    def test_analyze_json_logs(self, analyzer, sample_json_logs):
        """Test analyzing JSON logs."""
        result = analyzer.analyze_string(sample_json_logs, format_hint="json")
        
        assert result.total_entries_processed > 0
    
    def test_analyze_apache_logs(self, analyzer, sample_apache_logs):
        """Test analyzing Apache access logs."""
        result = analyzer.analyze_string(sample_apache_logs, format_hint="apache")
        
        assert result.total_entries_processed > 0
        # Should detect path traversal and XSS attempts
        event_types = [f.event_type for f in result.findings]
        assert SecurityEventType.PATH_TRAVERSAL_ATTEMPT in event_types or SecurityEventType.XSS_ATTEMPT in event_types
    
    def test_brute_force_detection(self, analyzer):
        """Test brute force detection."""
        # Configure low threshold for testing
        config = AnalyzerConfig(brute_force_threshold=3)
        agent = LogAnalyzerAgent(config)
        
        # Generate multiple failed logins
        entries = []
        now = datetime.now()
        for i in range(5):
            entries.append(LogEntry(
                timestamp=now + timedelta(seconds=i),
                message="Failed password for admin from 192.168.1.100",
                source="sshd",
            ))
        
        findings = agent.analyze_logs(entries)
        
        # Should detect brute force
        event_types = [f.event_type for f in findings]
        assert SecurityEventType.BRUTE_FORCE in event_types
    
    def test_analyze_file(self, analyzer, sample_syslog_content, tmp_path):
        """Test analyzing a log file."""
        log_file = tmp_path / "test.log"
        log_file.write_text(sample_syslog_content)
        
        result = analyzer.analyze_file(log_file)
        
        assert result.total_entries_processed > 0
        assert str(log_file) in result.files_analyzed
    
    def test_analyze_directory(self, analyzer, sample_syslog_content, tmp_path):
        """Test analyzing a directory of logs."""
        # Create multiple log files
        for i in range(3):
            log_file = tmp_path / f"test{i}.log"
            log_file.write_text(sample_syslog_content)
        
        result = analyzer.analyze_directory(tmp_path)
        
        assert len(result.files_analyzed) >= 3
    
    def test_severity_filter(self, analyzer, sample_syslog_content):
        """Test filtering by minimum severity."""
        config = AnalyzerConfig(min_severity=Severity.HIGH)
        agent = LogAnalyzerAgent(config)
        
        result = agent.analyze_string(sample_syslog_content)
        
        # All findings should be HIGH or CRITICAL
        for finding in result.findings:
            assert finding.severity.score >= Severity.HIGH.score
    
    def test_source_exclusion(self, analyzer):
        """Test excluding sources from analysis."""
        config = AnalyzerConfig(exclude_sources=["kernel"])
        agent = LogAnalyzerAgent(config)
        
        entries = [
            LogEntry(timestamp=datetime.now(), message="Test error", source="kernel"),
            LogEntry(timestamp=datetime.now(), message="Failed password", source="sshd"),
        ]
        
        findings = agent.analyze_logs(entries)
        
        # Should not include kernel-sourced findings
        for finding in findings:
            assert all(e.source != "kernel" for e in finding.log_entries)
    
    def test_generate_summary(self, analyzer, sample_syslog_content):
        """Test summary generation."""
        result = analyzer.analyze_string(sample_syslog_content)
        summary = analyzer.generate_summary(result)
        
        assert "LOG ANALYSIS SUMMARY" in summary
        assert "Entries processed:" in summary
    
    def test_generate_soc2_report(self, analyzer, sample_syslog_content):
        """Test SOC 2 report generation."""
        result = analyzer.analyze_string(sample_syslog_content)
        report = analyzer.generate_soc2_report(result)
        
        assert report["report_type"] == "soc2_log_analysis"
        assert "controls" in report
        assert "CC7.1" in report["controls"]
        assert "CC7.2" in report["controls"]
        assert "CC7.3" in report["controls"]
    
    def test_get_control_evidence(self, analyzer, sample_syslog_content):
        """Test control evidence generation."""
        result = analyzer.analyze_string(sample_syslog_content)
        evidence = analyzer.get_control_evidence(result)
        
        assert "CC7.1" in evidence
        assert evidence["CC7.1"].control_id == "CC7.1"
        assert evidence["CC7.1"].evidence_type == "log_analysis"
    
    def test_finding_deduplication(self, analyzer):
        """Test that duplicate findings are merged."""
        # Create entries that would produce duplicate findings
        entries = []
        now = datetime.now()
        for i in range(5):
            entries.append(LogEntry(
                timestamp=now + timedelta(seconds=i),
                message="Permission denied for /etc/shadow",
                source="security",
            ))
        
        findings = analyzer.analyze_logs(entries)
        
        # Should be deduplicated
        permission_denied = [
            f for f in findings
            if f.event_type == SecurityEventType.PERMISSION_DENIED
        ]
        # Should be 1 or 0 (deduplicated)
        assert len(permission_denied) <= 1


class TestIntegration:
    """Integration tests for end-to-end workflows."""
    
    def test_full_analysis_workflow(self, sample_syslog_content, tmp_path):
        """Test complete analysis workflow."""
        # Create log file
        log_file = tmp_path / "auth.log"
        log_file.write_text(sample_syslog_content)
        
        # Analyze
        agent = LogAnalyzerAgent()
        result = agent.analyze_file(log_file)
        
        # Generate report
        report = agent.generate_soc2_report(result)
        
        # Verify report structure
        assert report["analysis_summary"]["files_analyzed"] == 1
        assert report["analysis_summary"]["total_findings"] >= 0
        
        # Verify JSON serializable
        json_str = json.dumps(report, default=str)
        assert len(json_str) > 0
    
    def test_mixed_format_directory(self, tmp_path):
        """Test analyzing directory with mixed log formats."""
        # Create different log formats
        syslog = tmp_path / "syslog.log"
        syslog.write_text("Dec 31 10:30:45 host sshd: Failed password\n")
        
        json_log = tmp_path / "app.log"
        json_log.write_text('{"message": "Permission denied", "level": "ERROR"}\n')
        
        # Analyze directory
        agent = LogAnalyzerAgent()
        result = agent.analyze_directory(tmp_path)
        
        assert len(result.files_analyzed) >= 2


class TestEdgeCases:
    """Edge case tests."""
    
    def test_empty_log_file(self, tmp_path):
        """Test handling empty log file."""
        log_file = tmp_path / "empty.log"
        log_file.write_text("")
        
        agent = LogAnalyzerAgent()
        result = agent.analyze_file(log_file)
        
        assert result.total_entries_processed == 0
        assert result.finding_count == 0
    
    def test_binary_file_handling(self, tmp_path):
        """Test handling binary file."""
        binary_file = tmp_path / "binary.log"
        binary_file.write_bytes(b'\x00\x01\x02\x03')
        
        agent = LogAnalyzerAgent()
        result = agent.analyze_file(binary_file)
        
        # Should not crash
        assert result is not None
    
    def test_nonexistent_file(self):
        """Test handling nonexistent file."""
        agent = LogAnalyzerAgent()
        result = agent.analyze_file("/nonexistent/path/file.log")
        
        assert len(result.errors) > 0
    
    def test_nonexistent_directory(self):
        """Test handling nonexistent directory."""
        agent = LogAnalyzerAgent()
        result = agent.analyze_directory("/nonexistent/path/")
        
        assert len(result.errors) > 0
    
    def test_malformed_json_lines(self):
        """Test handling malformed JSON in logs."""
        content = '''{"message": "valid"}
not json
{"message": "also valid"}
'''
        agent = LogAnalyzerAgent()
        result = agent.analyze_string(content, format_hint="json")
        
        # Should parse valid lines
        assert result.total_entries_processed >= 2
    
    def test_unicode_in_logs(self):
        """Test handling Unicode characters in logs."""
        content = '''Dec 31 10:30:45 host app: User émoji: 🔐 failed login
Dec 31 10:30:46 host app: 日本語メッセージ
'''
        agent = LogAnalyzerAgent()
        result = agent.analyze_string(content)
        
        assert result.total_entries_processed >= 1
