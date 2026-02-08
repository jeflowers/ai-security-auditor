"""
Tests for Security Auditor CLI

Tests the command-line interface using Typer's testing utilities.
"""

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()


class TestCLIBasics:
    """Test basic CLI functionality."""
    
    def test_version(self):
        """CLI shows version."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "AI-Powered Security Auditor" in result.stdout
    
    def test_help(self):
        """CLI shows help."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "AI-Powered Security Auditor" in result.stdout
        assert "analyze-code" in result.stdout
        assert "analyze-logs" in result.stdout
        assert "scan" in result.stdout
        assert "compliance" in result.stdout
        assert "audit" in result.stdout
    
    def test_status_command(self):
        """Status command shows agent availability."""
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "Agent Status" in result.stdout
        assert "Code Security Analyzer" in result.stdout
        assert "Log Analyzer" in result.stdout


class TestAnalyzeCodeCommand:
    """Test analyze-code command."""
    
    @pytest.fixture
    def sample_code_dir(self, tmp_path):
        """Create a temporary directory with sample code."""
        # Create a Python file with a vulnerability
        py_file = tmp_path / "app.py"
        py_file.write_text('''
import os

def run_command(user_input):
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE id = " + user_input
    os.system("echo " + user_input)  # Command injection
    return query

password = "hardcoded_secret_123"  # Hardcoded secret
''')
        return tmp_path
    
    def test_analyze_code_help(self):
        """analyze-code shows help."""
        result = runner.invoke(app, ["analyze-code", "--help"])
        assert result.exit_code == 0
        assert "Analyze source code" in result.stdout
    
    def test_analyze_code_directory(self, sample_code_dir):
        """analyze-code analyzes a directory."""
        result = runner.invoke(app, ["analyze-code", str(sample_code_dir)])
        assert result.exit_code == 0
        # Should find vulnerabilities
        assert "Summary" in result.stdout or "findings" in result.stdout.lower()
    
    def test_analyze_code_with_output(self, sample_code_dir, tmp_path):
        """analyze-code saves JSON output."""
        output_file = tmp_path / "report.json"
        result = runner.invoke(app, [
            "analyze-code", 
            str(sample_code_dir),
            "-o", str(output_file),
        ])
        assert result.exit_code == 0
        assert output_file.exists()
        
        # Verify JSON structure
        data = json.loads(output_file.read_text())
        assert "total_findings" in data or "findings" in data
    
    def test_analyze_code_json_format(self, sample_code_dir):
        """analyze-code outputs JSON format."""
        result = runner.invoke(app, [
            "analyze-code",
            str(sample_code_dir),
            "--format", "json",
        ])
        assert result.exit_code == 0
        # Should be valid JSON
        output = result.stdout
        assert "{" in output
    
    def test_analyze_code_min_severity(self, sample_code_dir):
        """analyze-code respects min-severity filter."""
        result = runner.invoke(app, [
            "analyze-code",
            str(sample_code_dir),
            "--min-severity", "high",
        ])
        assert result.exit_code == 0
    
    def test_analyze_code_nonexistent_path(self):
        """analyze-code handles nonexistent path."""
        result = runner.invoke(app, ["analyze-code", "/nonexistent/path"])
        assert result.exit_code != 0


class TestAnalyzeLogsCommand:
    """Test analyze-logs command."""
    
    @pytest.fixture
    def sample_log_file(self, tmp_path):
        """Create a temporary log file with security events."""
        log_file = tmp_path / "auth.log"
        log_file.write_text('''
Dec 30 10:15:23 server sshd[1234]: Failed password for root from 192.168.1.100 port 22
Dec 30 10:15:24 server sshd[1234]: Failed password for root from 192.168.1.100 port 22
Dec 30 10:15:25 server sshd[1234]: Failed password for root from 192.168.1.100 port 22
Dec 30 10:15:26 server sshd[1234]: Failed password for root from 192.168.1.100 port 22
Dec 30 10:15:27 server sshd[1234]: Failed password for root from 192.168.1.100 port 22
Dec 30 10:16:00 server sudo[5678]: user1 : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash
''')
        return log_file
    
    def test_analyze_logs_help(self):
        """analyze-logs shows help."""
        result = runner.invoke(app, ["analyze-logs", "--help"])
        assert result.exit_code == 0
        assert "Analyze logs" in result.stdout
    
    def test_analyze_logs_file(self, sample_log_file):
        """analyze-logs analyzes a log file."""
        result = runner.invoke(app, ["analyze-logs", str(sample_log_file)])
        assert result.exit_code == 0
        # Should find security events
        assert "Summary" in result.stdout or "findings" in result.stdout.lower()
    
    def test_analyze_logs_with_output(self, sample_log_file, tmp_path):
        """analyze-logs saves JSON output."""
        output_file = tmp_path / "log_report.json"
        result = runner.invoke(app, [
            "analyze-logs",
            str(sample_log_file),
            "-o", str(output_file),
        ])
        assert result.exit_code == 0
        assert output_file.exists()
    
    def test_analyze_logs_summary_format(self, sample_log_file):
        """analyze-logs outputs summary format."""
        result = runner.invoke(app, [
            "analyze-logs",
            str(sample_log_file),
            "--format", "summary",
        ])
        assert result.exit_code == 0
        assert "Statistics" in result.stdout or "Summary" in result.stdout


class TestScanCommand:
    """Test scan command."""
    
    def test_scan_help(self):
        """scan shows help."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan a web application" in result.stdout
    
    def test_scan_requires_target(self):
        """scan requires target option."""
        result = runner.invoke(app, ["scan"])
        # Should fail without target
        assert result.exit_code != 0


class TestComplianceCommand:
    """Test compliance command."""
    
    def test_compliance_help(self):
        """compliance shows help."""
        result = runner.invoke(app, ["compliance", "--help"])
        assert result.exit_code == 0
        assert "compliance assessment" in result.stdout.lower()
    
    def test_compliance_missing_evidence(self, tmp_path):
        """compliance handles missing evidence directory."""
        result = runner.invoke(app, [
            "compliance",
            str(tmp_path / "nonexistent"),
        ])
        assert result.exit_code != 0


class TestAuditCommand:
    """Test audit command."""
    
    @pytest.fixture
    def sample_project(self, tmp_path):
        """Create a sample project directory."""
        # Create source directory
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        
        # Create a Python file
        (src_dir / "app.py").write_text('''
def hello():
    return "Hello, World!"
''')
        
        return tmp_path
    
    def test_audit_help(self):
        """audit shows help."""
        result = runner.invoke(app, ["audit", "--help"])
        assert result.exit_code == 0
        assert "complete security audit" in result.stdout.lower()
    
    def test_audit_basic(self, sample_project, tmp_path):
        """audit runs all phases."""
        output_dir = tmp_path / "results"
        result = runner.invoke(app, [
            "audit",
            str(sample_project),
            "-o", str(output_dir),
            "--skip-scan",
        ])
        assert result.exit_code == 0
        assert "Audit Complete" in result.stdout
        assert output_dir.exists()
    
    def test_audit_creates_evidence(self, sample_project, tmp_path):
        """audit creates evidence directory."""
        output_dir = tmp_path / "results"
        result = runner.invoke(app, [
            "audit",
            str(sample_project),
            "-o", str(output_dir),
            "--skip-scan",
        ])
        assert result.exit_code == 0
        evidence_dir = output_dir / "evidence"
        assert evidence_dir.exists()


class TestOutputFormats:
    """Test different output formats."""
    
    @pytest.fixture
    def vulnerable_code(self, tmp_path):
        """Create code with vulnerabilities."""
        code_file = tmp_path / "vulnerable.py"
        code_file.write_text('''
import os
os.system(user_input)  # Command injection
eval(user_input)  # Code injection
''')
        return tmp_path
    
    def test_table_format(self, vulnerable_code):
        """Table format displays correctly."""
        result = runner.invoke(app, [
            "analyze-code",
            str(vulnerable_code),
            "--format", "table",
        ])
        assert result.exit_code == 0
        # Rich table should have formatting
        assert "Security Findings" in result.stdout or "Summary" in result.stdout
    
    def test_json_format(self, vulnerable_code):
        """JSON format is valid."""
        result = runner.invoke(app, [
            "analyze-code",
            str(vulnerable_code),
            "--format", "json",
        ])
        assert result.exit_code == 0
        # Extract JSON from output
        output = result.stdout
        # Should contain JSON structure
        assert "findings" in output.lower()
    
    def test_summary_format(self, vulnerable_code):
        """Summary format shows counts."""
        result = runner.invoke(app, [
            "analyze-code",
            str(vulnerable_code),
            "--format", "summary",
        ])
        assert result.exit_code == 0
        assert "Summary" in result.stdout


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_directory(self, tmp_path):
        """Handle empty directory gracefully."""
        result = runner.invoke(app, ["analyze-code", str(tmp_path)])
        assert result.exit_code == 0
        assert "No security issues" in result.stdout or "0" in result.stdout
    
    def test_binary_file_in_directory(self, tmp_path):
        """Skip binary files gracefully."""
        # Create a binary file
        binary_file = tmp_path / "data.bin"
        binary_file.write_bytes(b'\x00\x01\x02\x03')
        
        result = runner.invoke(app, ["analyze-code", str(tmp_path)])
        assert result.exit_code == 0
    
    def test_large_file_handling(self, tmp_path):
        """Handle large files gracefully."""
        # Create a file that would exceed default max size
        # (Using small test for speed)
        large_file = tmp_path / "large.py"
        large_file.write_text("x = 1\n" * 1000)
        
        result = runner.invoke(app, ["analyze-code", str(tmp_path)])
        assert result.exit_code == 0


class TestIntegration:
    """Integration tests for full workflows."""
    
    def test_code_to_compliance_workflow(self, tmp_path):
        """Test code analysis to compliance workflow."""
        # Create source code
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "app.py").write_text('''
def safe_function():
    return "safe"
''')
        
        # Create logs
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        (logs_dir / "app.log").write_text('''
2024-12-30 10:00:00 INFO Application started
2024-12-30 10:00:01 INFO Request processed
''')
        
        # Run full audit
        output_dir = tmp_path / "results"
        result = runner.invoke(app, [
            "audit",
            str(tmp_path),
            "-o", str(output_dir),
            "--skip-scan",
        ])
        
        assert result.exit_code == 0
        assert (output_dir / "evidence").exists()
