"""
Code Security Analyzer Agent

Main agent that orchestrates static code analysis for security vulnerabilities.
Integrates with the SOC 2 compliance framework.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Iterator
import fnmatch

from .models import (
    CodeFinding,
    CodeLocation,
    FindingSeverity,
    FindingConfidence,
    AnalysisResult,
    AnalysisEvidence,
    get_owasp_category,
    get_soc2_controls_from_cwe,
)
from .patterns import (
    SecurityPattern,
    SECURITY_PATTERNS,
    Language,
    get_patterns_by_language,
)
from .parser import CodeParser, ParseResult


@dataclass
class AnalysisConfig:
    """Configuration for code analysis."""
    
    # Languages to analyze
    languages: list[str] = field(default_factory=lambda: [
        "python", "javascript", "typescript", "java"
    ])
    
    # Severity threshold
    min_severity: FindingSeverity = FindingSeverity.LOW
    
    # Paths to exclude (glob patterns)
    exclude_patterns: list[str] = field(default_factory=lambda: [
        "**/node_modules/**",
        "**/__pycache__/**",
        "**/venv/**",
        "**/.venv/**",
        "**/env/**",
        "**/.git/**",
        "**/dist/**",
        "**/build/**",
        "**/*.min.js",
        "**/vendor/**",
        "**/third_party/**",
    ])
    
    # File extensions to analyze
    extensions: list[str] = field(default_factory=lambda: [
        ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx",
        ".ts", ".tsx", ".java"
    ])
    
    # Maximum file size (bytes)
    max_file_size: int = 1_000_000  # 1MB
    
    # CWEs to check (empty = all)
    cwe_filter: list[int] = field(default_factory=list)
    
    # OWASP categories to check (empty = all)
    owasp_filter: list[str] = field(default_factory=list)


class CodeSecurityAnalyzerAgent:
    """
    Code Security Analyzer Agent for the Security Auditor system.
    
    Performs static analysis to:
    1. Detect security vulnerabilities in source code
    2. Map findings to OWASP Top 10 categories
    3. Map findings to SOC 2 controls
    4. Generate evidence for compliance assessment
    """
    
    def __init__(
        self,
        config: Optional[AnalysisConfig] = None,
        evidence_dir: Optional[Path] = None,
    ):
        self.config = config or AnalysisConfig()
        self.evidence_dir = evidence_dir
        self.parser = CodeParser()
        self._patterns = self._load_patterns()
    
    def _load_patterns(self) -> list[SecurityPattern]:
        """Load and filter security patterns based on config."""
        patterns = SECURITY_PATTERNS.copy()
        
        # Filter by CWE if specified
        if self.config.cwe_filter:
            patterns = [p for p in patterns if p.cwe_id in self.config.cwe_filter]
        
        # Filter by OWASP if specified
        if self.config.owasp_filter:
            patterns = [p for p in patterns if p.owasp_category in self.config.owasp_filter]
        
        # Filter by severity
        severity_order = [
            FindingSeverity.INFO,
            FindingSeverity.LOW,
            FindingSeverity.MEDIUM,
            FindingSeverity.HIGH,
            FindingSeverity.CRITICAL,
        ]
        min_idx = severity_order.index(self.config.min_severity)
        patterns = [
            p for p in patterns
            if severity_order.index(p.severity) >= min_idx
        ]
        
        return patterns
    
    def _should_exclude(self, path: Path) -> bool:
    	"""Check if path should be excluded from analysis."""
    	path_str = str(path)
    
    	# Quick check for common exclusion directories
    	excluded_dirs = [
	    '/venv/', '/.venv/', '/env/', '/node_modules/', 
            '/__pycache__/', '/.git/', '/dist/', '/build/',
            '/vendor/', '/third_party/', '/.pytest_cache/',
            '/site-packages/',
    	]	
    	for excluded in excluded_dirs:
            if excluded in path_str:
                return True
    
    	# Check if path starts with these (relative paths)
    	path_lower = path_str.lower()
    	if any(path_lower.startswith(d.strip('/')) for d in excluded_dirs):
            return True
    
    	# Use Path.match for glob patterns (supports **)
    	for pattern in self.config.exclude_patterns:
            try:
            	if path.match(pattern):
                    return True
            except ValueError:
            	continue
    
    	return False

    def _should_analyze(self, path: Path) -> bool:
        """Check if file should be analyzed."""
        if self._should_exclude(path):
            return False
        
        if path.suffix.lower() not in self.config.extensions:
            return False
        
        if path.stat().st_size > self.config.max_file_size:
            return False
        
        return True
    
    def _get_applicable_patterns(self, language: str) -> list[SecurityPattern]:
        """Get patterns applicable to a specific language."""
        lang_enum = {
            "python": Language.PYTHON,
            "javascript": Language.JAVASCRIPT,
            "typescript": Language.TYPESCRIPT,
            "java": Language.JAVA,
        }.get(language, Language.GENERIC)
        
        return [
            p for p in self._patterns
            if lang_enum in p.languages or Language.GENERIC in p.languages
        ]
    
    def _create_finding(
        self,
        pattern: SecurityPattern,
        match: dict,
        file_path: str,
        code: str,
        parse_result: ParseResult,
    ) -> CodeFinding:
        """Create a finding from a pattern match."""
        line_number = match["line"]
        
        # Get code context
        code_snippet = self.parser.get_code_context(code, line_number, context_lines=2)
        
        # Find containing function
        func_info = self.parser.find_function_at_line(parse_result, line_number)
        
        # Generate finding ID
        finding_id = f"CODE-{pattern.pattern_id}-{uuid.uuid4().hex[:8]}"
        
        location = CodeLocation(
            file_path=file_path,
            line_number=line_number,
            column=match.get("start", 0) - code.rfind('\n', 0, match.get("start", 0)) - 1,
            code_snippet=code_snippet,
            function_name=func_info.name if func_info else None,
            class_name=func_info.class_name if func_info else None,
        )
        
        return CodeFinding(
            finding_id=finding_id,
            rule_id=pattern.pattern_id,
            title=pattern.name,
            severity=pattern.severity,
            confidence=pattern.confidence,
            cwe_id=pattern.cwe_id,
            owasp_category=pattern.owasp_category,
            location=location,
            description=pattern.description,
            remediation=pattern.remediation,
            references=pattern.references.copy(),
            related_controls=pattern.soc2_controls.copy(),
            match_text=match.get("match_text", ""),
        )
    
    def analyze_code(
        self,
        code: str,
        language: str = "python",
        file_path: str = "<string>",
    ) -> list[CodeFinding]:
        """
        Analyze code string for security vulnerabilities.
        
        Args:
            code: Source code to analyze
            language: Programming language
            file_path: Optional file path for context
        
        Returns:
            List of findings
        """
        findings: list[CodeFinding] = []
        
        # Parse code for context
        parse_result = self.parser.parse(code, file_path, language)
        
        # Get applicable patterns
        patterns = self._get_applicable_patterns(language)
        
        # Check each pattern
        for pattern in patterns:
            matches = pattern.matches(code)
            for match in matches:
                finding = self._create_finding(
                    pattern=pattern,
                    match=match,
                    file_path=file_path,
                    code=code,
                    parse_result=parse_result,
                )
                findings.append(finding)
        
        return findings
    
    def analyze_file(self, file_path: str | Path) -> list[CodeFinding]:
        """
        Analyze a single file for security vulnerabilities.
        
        Args:
            file_path: Path to file to analyze
        
        Returns:
            List of findings
        """
        path = Path(file_path)
        
        if not path.exists():
            return []
        
        if not self._should_analyze(path):
            return []
        
        # Read file content
        try:
            code = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                code = path.read_text(encoding="latin-1")
            except Exception:
                return []
        
        # Detect language
        language = self.parser.detect_language(str(path))
        
        return self.analyze_code(code, language, str(path))
    
    def analyze_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
        progress_callback: Optional[callable] = None,
    ) -> AnalysisResult:
        """
        Analyze all files in a directory.
        
        Args:
            directory: Directory to analyze
            recursive: Whether to scan recursively
            progress_callback: Optional callback(current, total, file_path)
        
        Returns:
            AnalysisResult with all findings
        """
        start_time = datetime.now(timezone.utc)
        analysis_id = f"ANALYSIS-{uuid.uuid4().hex[:12]}"
        
        dir_path = Path(directory)
        if not dir_path.exists():
            return AnalysisResult(
                analysis_id=analysis_id,
                target_path=str(directory),
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
                errors=[{"error": f"Directory not found: {directory}"}],
            )
        
        # Collect files to analyze
        files_to_analyze: list[Path] = []
        if recursive:
            for ext in self.config.extensions:
                files_to_analyze.extend(dir_path.rglob(f"*{ext}"))
        else:
            for ext in self.config.extensions:
                files_to_analyze.extend(dir_path.glob(f"*{ext}"))
        
        # Filter files
        files_to_analyze = [f for f in files_to_analyze if self._should_analyze(f)]
        
        total_files = len(files_to_analyze)
        all_findings: list[CodeFinding] = []
        files_scanned = 0
        files_with_findings = 0
        total_lines = 0
        errors: list[dict] = []
        
        # Analyze each file
        for i, file_path in enumerate(files_to_analyze):
            if progress_callback:
                progress_callback(i + 1, total_files, str(file_path))
            
            try:
                # Count lines
                code = file_path.read_text(encoding="utf-8", errors="replace")
                total_lines += len(code.splitlines())
                
                # Analyze
                findings = self.analyze_file(file_path)
                
                if findings:
                    files_with_findings += 1
                    all_findings.extend(findings)
                
                files_scanned += 1
                
            except Exception as e:
                errors.append({
                    "file": str(file_path),
                    "error": str(e),
                })
        
        # Deduplicate findings
        all_findings = self._deduplicate_findings(all_findings)
        
        return AnalysisResult(
            analysis_id=analysis_id,
            target_path=str(directory),
            started_at=start_time,
            completed_at=datetime.now(timezone.utc),
            findings=all_findings,
            files_scanned=files_scanned,
            files_with_findings=files_with_findings,
            lines_scanned=total_lines,
            errors=errors,
            languages=self.config.languages,
            rules_applied=[p.pattern_id for p in self._patterns],
            excluded_paths=self.config.exclude_patterns,
        )
    
    def _deduplicate_findings(
        self, 
        findings: list[CodeFinding]
    ) -> list[CodeFinding]:
        """Remove duplicate findings based on location and rule."""
        seen = set()
        deduplicated = []
        
        for finding in findings:
            key = (
                finding.rule_id,
                finding.location.file_path,
                finding.location.line_number,
            )
            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)
        
        return deduplicated
    
    def generate_evidence(self, result: AnalysisResult) -> AnalysisEvidence:
        """Generate SOC 2 evidence artifact from analysis result."""
        evidence_id = f"CC6.6-E4-{result.analysis_id}"
        
        evidence = AnalysisEvidence(
            evidence_id=evidence_id,
            analysis_id=result.analysis_id,
            target_path=result.target_path,
            started_at=result.started_at,
            completed_at=result.completed_at,
            total_findings=result.total_findings,
            findings_by_severity=result.findings_by_severity,
            findings=result.findings,
            scan_config={
                "languages": result.languages,
                "rules_applied": result.rules_applied,
                "excluded_paths": result.excluded_paths,
            },
        )
        
        evidence.content_hash = evidence.compute_hash()
        
        # Save if evidence directory specified
        if self.evidence_dir:
            self._save_evidence(evidence)
        
        return evidence
    
    def _save_evidence(self, evidence: AnalysisEvidence):
        """Save evidence and provenance to disk."""
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Save main evidence
        evidence_path = self.evidence_dir / f"{evidence.evidence_id}.json"
        with open(evidence_path, 'w') as f:
            json.dump(evidence.to_dict(), f, indent=2)
        
        # Save provenance
        provenance_path = self.evidence_dir / f"{evidence.evidence_id}.provenance.json"
        with open(provenance_path, 'w') as f:
            json.dump(evidence.get_provenance(), f, indent=2)
    
    def generate_summary(self, result: AnalysisResult) -> dict:
        """Generate human-readable summary of analysis results."""
        by_file = result.get_findings_by_file()
        
        return {
            "analysis_id": result.analysis_id,
            "target_path": result.target_path,
            "duration_seconds": result.duration_seconds,
            "files_scanned": result.files_scanned,
            "files_with_findings": result.files_with_findings,
            "lines_scanned": result.lines_scanned,
            "total_findings": result.total_findings,
            "findings_by_severity": result.findings_by_severity,
            "findings_by_owasp": result.findings_by_owasp,
            "affected_controls": list(result.affected_controls),
            "findings_by_file": {
                path: len(findings) 
                for path, findings in by_file.items()
            },
            "critical_findings": [
                f.to_dict() for f in result.findings
                if f.severity == FindingSeverity.CRITICAL
            ],
            "high_findings": [
                f.to_dict() for f in result.findings
                if f.severity == FindingSeverity.HIGH
            ],
        }
    
    def get_control_evidence(
        self,
        result: AnalysisResult,
        control_id: str,
    ) -> dict:
        """
        Get evidence specific to a SOC 2 control.
        
        Returns data formatted for the compliance checker.
        """
        relevant_findings = result.get_findings_by_control(control_id)
        
        return {
            "evidence_id": f"{control_id}-CODE-{result.analysis_id}",
            "type": "analysis_output",
            "source_system": "Code Security Analyzer",
            "collected_at": result.completed_at.isoformat(),
            "control_ids": [control_id],
            "content_hash": hashlib.sha256(
                json.dumps([f.to_dict() for f in relevant_findings], sort_keys=True).encode()
            ).hexdigest(),
            "data": {
                "total_findings": len(relevant_findings),
                "findings_by_severity": {
                    s.value: sum(1 for f in relevant_findings if f.severity == s)
                    for s in FindingSeverity
                },
                "findings": [f.to_dict() for f in relevant_findings],
                "scan_metadata": {
                    "analysis_id": result.analysis_id,
                    "target_path": result.target_path,
                    "scanner": "Code Security Analyzer",
                },
            },
            "validations": {
                "analysis_completed": True,
                "no_critical_findings": all(
                    f.severity != FindingSeverity.CRITICAL
                    for f in relevant_findings
                ),
                "no_high_findings": all(
                    f.severity != FindingSeverity.HIGH
                    for f in relevant_findings
                ),
            },
        }
    
    def generate_soc2_report(self, result: AnalysisResult) -> dict:
        """Generate SOC 2 formatted report grouped by control."""
        report = {
            "title": "Code Security Analysis - SOC 2 Report",
            "analysis_id": result.analysis_id,
            "target": result.target_path,
            "timestamp": result.completed_at.isoformat(),
            "summary": {
                "total_findings": result.total_findings,
                "findings_by_severity": result.findings_by_severity,
                "affected_controls": list(result.affected_controls),
            },
            "controls": {},
        }
        
        # Group findings by control
        for control in result.affected_controls:
            control_findings = result.get_findings_by_control(control)
            report["controls"][control] = {
                "finding_count": len(control_findings),
                "severity_breakdown": {
                    s.value: sum(1 for f in control_findings if f.severity == s)
                    for s in FindingSeverity
                },
                "status": self._determine_control_status(control_findings),
                "findings": [
                    {
                        "id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "location": str(f.location),
                        "cwe": f"CWE-{f.cwe_id}",
                        "owasp": f.owasp_category,
                    }
                    for f in control_findings
                ],
            }
        
        return report
    
    def _determine_control_status(
        self, 
        findings: list[CodeFinding]
    ) -> str:
        """Determine control status based on findings."""
        if not findings:
            return "PASS"
        
        severities = [f.severity for f in findings]
        
        if FindingSeverity.CRITICAL in severities:
            return "FAIL"
        elif FindingSeverity.HIGH in severities:
            return "AT_RISK"
        elif FindingSeverity.MEDIUM in severities:
            return "NEEDS_REVIEW"
        else:
            return "PASS_WITH_FINDINGS"
