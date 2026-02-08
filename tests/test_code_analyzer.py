"""
Tests for Code Security Analyzer Agent.

Comprehensive test coverage for patterns, parser, and agent functionality.
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timezone

from agents.code_analyzer.models import (
    CodeFinding,
    CodeLocation,
    FindingSeverity,
    FindingConfidence,
    AnalysisResult,
    AnalysisEvidence,
    CWE_TO_OWASP,
    OWASP_TO_SOC2,
    get_owasp_category,
    get_soc2_controls,
    get_soc2_controls_from_cwe,
)
from agents.code_analyzer.patterns import (
    SecurityPattern,
    PatternType,
    Language,
    SECURITY_PATTERNS,
    SQL_INJECTION_PATTERNS,
    XSS_PATTERNS,
    COMMAND_INJECTION_PATTERNS,
    HARDCODED_CREDENTIALS_PATTERNS,
    get_patterns_by_cwe,
    get_patterns_by_owasp,
    get_patterns_by_language,
)
from agents.code_analyzer.parser import (
    CodeParser,
    PythonASTParser,
    ParseResult,
    FunctionInfo,
)
from agents.code_analyzer.agent import (
    CodeSecurityAnalyzerAgent,
    AnalysisConfig,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def sample_vulnerable_python():
    """Sample Python code with vulnerabilities."""
    return '''
import os
import pickle
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL Injection - CWE-89 (inline f-string in execute)
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

def run_command(cmd):
    # Command Injection - CWE-78
    os.system(f"echo {cmd}")

def load_data(data):
    # Insecure Deserialization - CWE-502
    return pickle.loads(data)

# Hardcoded credentials - CWE-798
API_KEY = "sk-1234567890abcdef1234567890abcdef"
PASSWORD = "supersecretpassword123"
'''


@pytest.fixture
def sample_safe_python():
    """Sample Python code without vulnerabilities."""
    return '''
import os
import json
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Parameterized query - safe
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

def load_data(data):
    # JSON is safe
    return json.loads(data)

# Environment variable - safe
API_KEY = os.environ.get("API_KEY")
'''


@pytest.fixture
def sample_vulnerable_js():
    """Sample JavaScript code with vulnerabilities."""
    return '''
const { exec } = require('child_process');

function renderUserContent(userInput) {
    // XSS - CWE-79
    document.innerHTML = userInput;
}

function executeCommand(cmd) {
    // Command Injection - CWE-78
    exec(`ls ${cmd}`);
}

// Hardcoded secret - CWE-798
const API_SECRET = "abcdef1234567890abcdef1234567890";
'''


@pytest.fixture
def analyzer():
    """Create analyzer instance."""
    return CodeSecurityAnalyzerAgent()


@pytest.fixture
def parser():
    """Create parser instance."""
    return CodeParser()


# =============================================================================
# Model Tests
# =============================================================================

class TestModels:
    """Tests for data models."""
    
    def test_finding_severity_from_score(self):
        """Test severity level from numeric score."""
        assert FindingSeverity.from_score(9.5) == FindingSeverity.CRITICAL
        assert FindingSeverity.from_score(8.0) == FindingSeverity.HIGH
        assert FindingSeverity.from_score(5.0) == FindingSeverity.MEDIUM
        assert FindingSeverity.from_score(2.0) == FindingSeverity.LOW
        assert FindingSeverity.from_score(0.5) == FindingSeverity.INFO
    
    def test_finding_confidence_numeric_value(self):
        """Test confidence numeric values."""
        assert FindingConfidence.CONFIRMED.numeric_value == 4
        assert FindingConfidence.HIGH.numeric_value == 3
        assert FindingConfidence.MEDIUM.numeric_value == 2
        assert FindingConfidence.LOW.numeric_value == 1
    
    def test_code_location_str(self):
        """Test location string representation."""
        loc = CodeLocation(
            file_path="/test/file.py",
            line_number=42,
        )
        assert str(loc) == "/test/file.py:42"
    
    def test_code_finding_to_dict(self):
        """Test finding serialization."""
        finding = CodeFinding(
            finding_id="TEST-001",
            rule_id="SQL-001",
            title="SQL Injection",
            severity=FindingSeverity.CRITICAL,
            confidence=FindingConfidence.HIGH,
            cwe_id=89,
            owasp_category="A03:2021",
            location=CodeLocation(
                file_path="/test.py",
                line_number=10,
            ),
            description="Test description",
            remediation="Use parameterized queries",
            related_controls=["CC6.6"],
        )
        
        data = finding.to_dict()
        assert data["finding_id"] == "TEST-001"
        assert data["severity"] == "critical"
        assert data["cwe_id"] == 89
        assert "CC6.6" in data["related_controls"]
    
    def test_analysis_result_properties(self):
        """Test analysis result computed properties."""
        findings = [
            CodeFinding(
                finding_id="F1",
                rule_id="R1",
                title="Test",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                cwe_id=89,
                owasp_category="A03:2021",
                location=CodeLocation(file_path="test.py", line_number=1),
                description="",
                remediation="",
                related_controls=["CC6.6"],
            ),
            CodeFinding(
                finding_id="F2",
                rule_id="R2",
                title="Test2",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.MEDIUM,
                cwe_id=79,
                owasp_category="A03:2021",
                location=CodeLocation(file_path="test.py", line_number=2),
                description="",
                remediation="",
                related_controls=["CC6.6", "CC6.7"],
            ),
        ]
        
        result = AnalysisResult(
            analysis_id="TEST",
            target_path="/test",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            findings=findings,
        )
        
        assert result.total_findings == 2
        assert result.findings_by_severity["high"] == 1
        assert result.findings_by_severity["medium"] == 1
        assert "CC6.6" in result.affected_controls
        assert "CC6.7" in result.affected_controls
    
    def test_cwe_to_owasp_mapping(self):
        """Test CWE to OWASP category mapping."""
        assert get_owasp_category(89) == "A03:2021"  # SQL Injection
        assert get_owasp_category(79) == "A03:2021"  # XSS
        assert get_owasp_category(798) == "A07:2021"  # Hardcoded creds
        assert get_owasp_category(918) == "A10:2021"  # SSRF
        assert get_owasp_category(99999) == "Unknown"  # Unknown
    
    def test_owasp_to_soc2_mapping(self):
        """Test OWASP to SOC 2 control mapping."""
        controls = get_soc2_controls("A03:2021")  # Injection
        assert "CC6.6" in controls
        
        controls = get_soc2_controls("A07:2021")  # Auth failures
        assert "CC6.1" in controls
        assert "CC6.2" in controls


# =============================================================================
# Pattern Tests
# =============================================================================

class TestPatterns:
    """Tests for security patterns."""
    
    def test_sql_injection_pattern_matches(self):
        """Test SQL injection pattern detection."""
        vulnerable_code = '''cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'''
        
        pattern = SQL_INJECTION_PATTERNS[1]  # f-string pattern
        matches = pattern.matches(vulnerable_code)
        
        assert len(matches) > 0
        assert "execute" in matches[0]["match_text"].lower()
    
    def test_sql_injection_pattern_safe_code(self):
        """Test SQL injection pattern doesn't match safe code."""
        safe_code = '''cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'''
        
        pattern = SQL_INJECTION_PATTERNS[1]  # f-string pattern
        matches = pattern.matches(safe_code)
        
        assert len(matches) == 0
    
    def test_xss_pattern_matches(self):
        """Test XSS pattern detection."""
        vulnerable_code = '''document.innerHTML = userInput'''
        
        pattern = XSS_PATTERNS[0]  # innerHTML pattern
        matches = pattern.matches(vulnerable_code)
        
        assert len(matches) > 0
    
    def test_command_injection_pattern_matches(self):
        """Test command injection pattern detection."""
        vulnerable_code = '''os.system(f"echo {cmd}")'''
        
        pattern = COMMAND_INJECTION_PATTERNS[1]  # os.system pattern
        matches = pattern.matches(vulnerable_code)
        
        assert len(matches) > 0
    
    def test_hardcoded_credentials_pattern(self):
        """Test hardcoded credentials detection."""
        vulnerable_code = '''API_KEY = "sk-1234567890abcdef1234567890abcdef"'''
        
        pattern = HARDCODED_CREDENTIALS_PATTERNS[0]
        matches = pattern.matches(vulnerable_code)
        
        assert len(matches) > 0
    
    def test_hardcoded_credentials_exclusions(self):
        """Test that placeholder values are excluded."""
        safe_codes = [
            'password = "your_password_here"',
            'api_key = "example_key"',
            'secret = "test_secret"',
        ]
        
        pattern = HARDCODED_CREDENTIALS_PATTERNS[0]
        for code in safe_codes:
            matches = pattern.matches(code)
            # Should be excluded by exclusion patterns
            assert len(matches) == 0
    
    def test_get_patterns_by_cwe(self):
        """Test filtering patterns by CWE."""
        sql_patterns = get_patterns_by_cwe(89)
        assert all(p.cwe_id == 89 for p in sql_patterns)
        assert len(sql_patterns) > 0
    
    def test_get_patterns_by_owasp(self):
        """Test filtering patterns by OWASP category."""
        injection_patterns = get_patterns_by_owasp("A03:2021")
        assert len(injection_patterns) > 0
    
    def test_get_patterns_by_language(self):
        """Test filtering patterns by language."""
        python_patterns = get_patterns_by_language(Language.PYTHON)
        assert len(python_patterns) > 0
        
        # All Python patterns should include PYTHON or GENERIC
        for p in python_patterns:
            assert Language.PYTHON in p.languages or Language.GENERIC in p.languages
    
    def test_pattern_has_required_fields(self):
        """Test all patterns have required fields."""
        for pattern in SECURITY_PATTERNS:
            assert pattern.pattern_id is not None
            assert pattern.name is not None
            assert pattern.cwe_id > 0
            assert pattern.severity is not None
            assert pattern.confidence is not None
            assert len(pattern.description) > 0
            assert len(pattern.remediation) > 0


# =============================================================================
# Parser Tests
# =============================================================================

class TestParser:
    """Tests for code parser."""
    
    def test_python_parser_functions(self, parser):
        """Test Python function extraction."""
        code = '''
def foo(x, y):
    return x + y

async def bar(z):
    return z * 2

class MyClass:
    def method(self):
        pass
'''
        result = parser.parse(code, "test.py", "python")
        
        assert len(result.functions) == 3
        func_names = [f.name for f in result.functions]
        assert "foo" in func_names
        assert "bar" in func_names
        assert "method" in func_names
    
    def test_python_parser_imports(self, parser):
        """Test Python import extraction."""
        code = '''
import os
import sys
from pathlib import Path
from typing import List, Dict
'''
        result = parser.parse(code, "test.py", "python")
        
        assert len(result.imports) == 4
        modules = [i.module for i in result.imports]
        assert "os" in modules
        assert "pathlib" in modules
    
    def test_python_parser_syntax_error(self, parser):
        """Test parser handles syntax errors gracefully."""
        code = '''
def broken(
    # Missing closing paren
'''
        result = parser.parse(code, "test.py", "python")
        
        assert len(result.errors) > 0
        assert "Syntax error" in result.errors[0]
    
    def test_detect_language(self, parser):
        """Test language detection from extension."""
        assert parser.detect_language("test.py") == "python"
        assert parser.detect_language("test.js") == "javascript"
        assert parser.detect_language("test.ts") == "typescript"
        assert parser.detect_language("test.java") == "java"
        assert parser.detect_language("test.unknown") == "unknown"
    
    def test_get_code_context(self, parser):
        """Test code context extraction."""
        code = "line1\nline2\nline3\nline4\nline5"
        context = parser.get_code_context(code, 3, context_lines=1)
        
        assert "line2" in context
        assert "line3" in context
        assert "line4" in context
        assert ">>>" in context  # Marker for target line
    
    def test_find_function_at_line(self, parser):
        """Test finding function containing a line."""
        code = '''
def foo():
    x = 1
    y = 2
    return x + y

def bar():
    pass
'''
        result = parser.parse(code, "test.py", "python")
        
        func = parser.find_function_at_line(result, 3)
        assert func is not None
        assert func.name == "foo"
        
        func = parser.find_function_at_line(result, 8)
        assert func is not None
        assert func.name == "bar"


# =============================================================================
# Agent Tests
# =============================================================================

class TestCodeSecurityAnalyzerAgent:
    """Tests for the main agent."""
    
    def test_analyze_vulnerable_python(
        self, 
        analyzer, 
        sample_vulnerable_python
    ):
        """Test analyzing vulnerable Python code."""
        findings = analyzer.analyze_code(
            sample_vulnerable_python, 
            language="python"
        )
        
        assert len(findings) > 0
        
        # Check for SQL injection
        sql_findings = [f for f in findings if f.cwe_id == 89]
        assert len(sql_findings) > 0
        
        # Check for command injection
        cmd_findings = [f for f in findings if f.cwe_id == 78]
        assert len(cmd_findings) > 0
        
        # Check for hardcoded credentials
        cred_findings = [f for f in findings if f.cwe_id == 798]
        assert len(cred_findings) > 0
    
    def test_analyze_safe_python(self, analyzer, sample_safe_python):
        """Test analyzing safe Python code - should have minimal findings."""
        findings = analyzer.analyze_code(
            sample_safe_python, 
            language="python"
        )
        
        # Should not find SQL injection (parameterized query)
        sql_findings = [f for f in findings if f.cwe_id == 89]
        assert len(sql_findings) == 0
        
        # Should not find hardcoded creds (uses env var)
        cred_findings = [f for f in findings if f.cwe_id == 798]
        assert len(cred_findings) == 0
    
    def test_analyze_vulnerable_js(self, analyzer, sample_vulnerable_js):
        """Test analyzing vulnerable JavaScript code."""
        findings = analyzer.analyze_code(
            sample_vulnerable_js, 
            language="javascript"
        )
        
        assert len(findings) > 0
        
        # Check CWE categories present
        cwes = {f.cwe_id for f in findings}
        assert 79 in cwes or 78 in cwes or 798 in cwes
    
    def test_analyze_file(self, analyzer):
        """Test analyzing a file from disk."""
        with tempfile.NamedTemporaryFile(
            mode='w', 
            suffix='.py', 
            delete=False
        ) as f:
            f.write('password = "secret123456789"\n')
            f.flush()
            
            findings = analyzer.analyze_file(f.name)
            
            # Should find hardcoded password
            assert len(findings) > 0
            
            Path(f.name).unlink()
    
    def test_analyze_directory(self, analyzer):
        """Test analyzing a directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            (Path(tmpdir) / "vuln.py").write_text(
                'os.system(f"rm {user_input}")\n'
            )
            (Path(tmpdir) / "safe.py").write_text(
                'x = 1 + 2\n'
            )
            
            result = analyzer.analyze_directory(tmpdir)
            
            assert result.files_scanned == 2
            assert result.total_findings >= 1
    
    def test_config_severity_filter(self):
        """Test severity filtering in config."""
        config = AnalysisConfig(min_severity=FindingSeverity.HIGH)
        analyzer = CodeSecurityAnalyzerAgent(config=config)
        
        # All loaded patterns should be HIGH or CRITICAL
        for pattern in analyzer._patterns:
            assert pattern.severity in (
                FindingSeverity.HIGH, 
                FindingSeverity.CRITICAL
            )
    
    def test_config_exclude_patterns(self, analyzer):
        """Test path exclusion."""
        # node_modules should be excluded by default
        assert analyzer._should_exclude(Path("project/node_modules/pkg/file.js"))
        assert analyzer._should_exclude(Path("project/__pycache__/file.pyc"))
        assert not analyzer._should_exclude(Path("project/src/file.py"))
    
    def test_generate_evidence(self, analyzer, sample_vulnerable_python):
        """Test evidence generation."""
        findings = analyzer.analyze_code(
            sample_vulnerable_python, 
            language="python",
            file_path="test.py"
        )
        
        result = AnalysisResult(
            analysis_id="TEST-001",
            target_path="test.py",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            findings=findings,
            files_scanned=1,
        )
        
        evidence = analyzer.generate_evidence(result)
        
        assert evidence.evidence_id.startswith("CC6.6-E4")
        assert evidence.total_findings == len(findings)
        assert evidence.content_hash is not None
        assert len(evidence.content_hash) == 64  # SHA256
    
    def test_generate_summary(self, analyzer, sample_vulnerable_python):
        """Test summary generation."""
        findings = analyzer.analyze_code(
            sample_vulnerable_python, 
            language="python",
            file_path="test.py"
        )
        
        result = AnalysisResult(
            analysis_id="TEST-001",
            target_path="test.py",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            findings=findings,
            files_scanned=1,
        )
        
        summary = analyzer.generate_summary(result)
        
        assert "total_findings" in summary
        assert "findings_by_severity" in summary
        assert "affected_controls" in summary
    
    def test_get_control_evidence(self, analyzer, sample_vulnerable_python):
        """Test control-specific evidence extraction."""
        findings = analyzer.analyze_code(
            sample_vulnerable_python, 
            language="python",
            file_path="test.py"
        )
        
        result = AnalysisResult(
            analysis_id="TEST-001",
            target_path="test.py",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            findings=findings,
            files_scanned=1,
        )
        
        evidence = analyzer.get_control_evidence(result, "CC6.6")
        
        assert evidence["control_ids"] == ["CC6.6"]
        assert "data" in evidence
        assert "validations" in evidence
    
    def test_generate_soc2_report(self, analyzer, sample_vulnerable_python):
        """Test SOC 2 report generation."""
        findings = analyzer.analyze_code(
            sample_vulnerable_python, 
            language="python",
            file_path="test.py"
        )
        
        result = AnalysisResult(
            analysis_id="TEST-001",
            target_path="test.py",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            findings=findings,
            files_scanned=1,
        )
        
        report = analyzer.generate_soc2_report(result)
        
        assert "title" in report
        assert "controls" in report
        assert "summary" in report
    
    def test_finding_deduplication(self, analyzer):
        """Test that duplicate findings are removed."""
        code = '''
password = "secret123456789"
password = "secret123456789"  # Same line pattern
'''
        findings = analyzer.analyze_code(code, language="python")
        
        # Check no exact duplicates (same rule, file, line)
        seen = set()
        for f in findings:
            key = (f.rule_id, f.location.file_path, f.location.line_number)
            assert key not in seen, f"Duplicate finding: {key}"
            seen.add(key)


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for end-to-end workflows."""
    
    def test_full_analysis_workflow(self, analyzer, sample_vulnerable_python):
        """Test complete analysis workflow."""
        # 1. Analyze code
        findings = analyzer.analyze_code(
            sample_vulnerable_python,
            language="python",
            file_path="test_app.py"
        )
        
        assert len(findings) > 0
        
        # 2. Create result
        result = AnalysisResult(
            analysis_id="WORKFLOW-001",
            target_path="test_app.py",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            findings=findings,
            files_scanned=1,
            files_with_findings=1,
            lines_scanned=len(sample_vulnerable_python.splitlines()),
        )
        
        # 3. Generate evidence
        evidence = analyzer.generate_evidence(result)
        assert evidence.evidence_id is not None
        
        # 4. Generate summary
        summary = analyzer.generate_summary(result)
        assert summary["total_findings"] > 0
        
        # 5. Generate SOC 2 report
        report = analyzer.generate_soc2_report(result)
        assert len(report["controls"]) > 0
        
        # 6. Get control evidence
        control_evidence = analyzer.get_control_evidence(result, "CC6.6")
        assert control_evidence["type"] == "analysis_output"
    
    def test_directory_analysis_workflow(self, analyzer):
        """Test directory analysis workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create file structure
            src_dir = Path(tmpdir) / "src"
            src_dir.mkdir()
            
            (src_dir / "app.py").write_text('''
import os
def run(cmd):
    os.system(f"echo {cmd}")
''')
            (src_dir / "utils.py").write_text('''
def safe_func():
    return 42
''')
            
            # Create excluded directory
            node_modules = Path(tmpdir) / "node_modules"
            node_modules.mkdir()
            (node_modules / "pkg.js").write_text('''
// Should be excluded
document.innerHTML = evil;
''')
            
            # Analyze
            result = analyzer.analyze_directory(tmpdir)
            
            # Should only scan 2 Python files
            assert result.files_scanned == 2
            
            # Should find command injection
            assert result.total_findings >= 1
            
            # node_modules should be excluded
            for finding in result.findings:
                assert "node_modules" not in finding.location.file_path


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_empty_code(self, analyzer):
        """Test analyzing empty code."""
        findings = analyzer.analyze_code("", language="python")
        assert len(findings) == 0
    
    def test_binary_file_handling(self, analyzer):
        """Test handling of binary files."""
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as f:
            f.write(b'\x00\x01\x02\x03')  # Binary content
            f.flush()
            
            # Should handle gracefully
            findings = analyzer.analyze_file(f.name)
            # May have findings or not, but shouldn't crash
            
            Path(f.name).unlink()
    
    def test_large_file_limit(self, analyzer):
        """Test file size limit enforcement."""
        with tempfile.NamedTemporaryFile(
            mode='w', 
            suffix='.py', 
            delete=False
        ) as f:
            # Write large content
            f.write("x = 1\n" * 1_000_000)
            f.flush()
            
            # File should be skipped due to size
            assert not analyzer._should_analyze(Path(f.name))
            
            Path(f.name).unlink()
    
    def test_nonexistent_file(self, analyzer):
        """Test handling of nonexistent file."""
        findings = analyzer.analyze_file("/nonexistent/path/file.py")
        assert len(findings) == 0
    
    def test_nonexistent_directory(self, analyzer):
        """Test handling of nonexistent directory."""
        result = analyzer.analyze_directory("/nonexistent/path")
        assert len(result.errors) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
