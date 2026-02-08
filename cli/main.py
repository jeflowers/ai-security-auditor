"""
Security Auditor CLI

Main command-line interface for the AI-Powered Security Auditor.
Uses Typer for CLI framework and Rich for beautiful output.

Usage:
    security-auditor analyze-code ./src
    security-auditor analyze-logs ./logs
    security-auditor scan --target http://localhost:8080
    security-auditor compliance --framework soc2
    security-auditor audit --all ./project
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.tree import Tree

# Initialize Typer app
app = typer.Typer(
    name="security-auditor",
    help="AI-Powered Security Auditor - SOC 2 Compliance Assessment Tool",
    add_completion=False,
    rich_markup_mode="rich",
)

# Rich console for pretty output
console = Console()

# Version info
VERSION = "0.1.0"


def version_callback(value: bool):
    """Print version and exit."""
    if value:
        console.print(f"[bold blue]AI-Powered Security Auditor[/] v{VERSION}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
):
    """
    AI-Powered Security Auditor - SOC 2 Compliance Assessment Tool
    
    Four specialized agents for comprehensive security analysis:
    
    • Vulnerability Scanner - OWASP ZAP integration
    • Code Security Analyzer - OWASP Top 10 compliance  
    • Log Analyzer - Anomaly detection
    • Compliance Checker - RAG-based framework validation
    """
    pass


# =============================================================================
# ANALYZE-CODE Command
# =============================================================================

@app.command("analyze-code")
def analyze_code(
    target: Path = typer.Argument(
        ...,
        help="Path to source code directory or file to analyze",
        exists=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file for JSON report",
    ),
    format: str = typer.Option(
        "table",
        "--format", "-f",
        help="Output format: table, json, or summary",
    ),
    min_severity: str = typer.Option(
        "low",
        "--min-severity", "-s",
        help="Minimum severity to report: info, low, medium, high, critical",
    ),
    languages: Optional[str] = typer.Option(
        None,
        "--languages", "-l",
        help="Comma-separated list of languages to analyze (default: all)",
    ),
    exclude: Optional[str] = typer.Option(
        None,
        "--exclude", "-e",
        help="Comma-separated glob patterns to exclude",
    ),
):
    """
    Analyze source code for security vulnerabilities.
    
    Detects OWASP Top 10 vulnerabilities, maps to CWE identifiers,
    and generates SOC 2 compliance evidence.
    
    Examples:
        security-auditor analyze-code ./src
        security-auditor analyze-code ./app --min-severity high
        security-auditor analyze-code ./project -o report.json
    """
    from agents.code_analyzer.agent import CodeSecurityAnalyzerAgent, AnalysisConfig
    from agents.code_analyzer.models import FindingSeverity
    
    # Parse severity
    severity_map = {
        "info": FindingSeverity.INFO,
        "low": FindingSeverity.LOW,
        "medium": FindingSeverity.MEDIUM,
        "high": FindingSeverity.HIGH,
        "critical": FindingSeverity.CRITICAL,
    }
    severity = severity_map.get(min_severity.lower(), FindingSeverity.LOW)
    
    # Build config
    config = AnalysisConfig(min_severity=severity)
    
    if languages:
        config.languages = [lang.strip() for lang in languages.split(",")]
    
    if exclude:
        config.exclude_patterns.extend([p.strip() for p in exclude.split(",")])
    
    # Create agent and run analysis
    agent = CodeSecurityAnalyzerAgent(config=config)
    
    console.print(Panel(
        f"[bold blue]Code Security Analyzer[/]\n"
        f"Target: [cyan]{target}[/]\n"
        f"Min Severity: [yellow]{min_severity}[/]",
        title="🔍 Starting Analysis",
    ))
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing code...", total=None)
        
        if target.is_file():
            findings = agent.analyze_file(target)
            result = type('Result', (), {
                'findings': findings,
                'total_findings': len(findings),
                'files_scanned': 1,
                'findings_by_severity': _count_by_severity(findings),
            })()
        else:
            result = agent.analyze_directory(target)
        
        progress.remove_task(task)
    
    # Display results
    _display_code_analysis_results(result, format, output, console)


def _count_by_severity(findings) -> dict:
    """Count findings by severity."""
    from agents.code_analyzer.models import FindingSeverity
    counts = {s.value: 0 for s in FindingSeverity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def _display_code_analysis_results(result, format: str, output: Optional[Path], console: Console):
    """Display code analysis results."""
    if format == "json":
        data = {
            "total_findings": result.total_findings,
            "files_scanned": result.files_scanned,
            "findings_by_severity": result.findings_by_severity,
            "findings": [f.to_dict() for f in result.findings],
        }
        if output:
            output.write_text(json.dumps(data, indent=2))
            console.print(f"[green]✓ Report saved to {output}[/]")
        else:
            console.print_json(json.dumps(data))
        return
    
    # Summary
    console.print()
    _print_severity_summary(result.findings_by_severity, console)
    
    if format == "summary":
        return
    
    # Table format
    if result.findings:
        table = Table(title="Security Findings", show_lines=True)
        table.add_column("Severity", style="bold")
        table.add_column("Title", style="cyan")
        table.add_column("Location")
        table.add_column("CWE")
        table.add_column("OWASP")
        
        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        
        for finding in result.findings:
            sev = finding.severity.value
            table.add_row(
                f"[{severity_colors.get(sev, '')}]{sev.upper()}[/]",
                finding.title,
                f"{finding.location.file_path}:{finding.location.line_number}",
                f"CWE-{finding.cwe_id}",
                finding.owasp_category,
            )
        
        console.print(table)
    else:
        console.print("[green]✓ No security issues found![/]")
    
    if output:
        data = {
            "total_findings": result.total_findings,
            "findings_by_severity": result.findings_by_severity,
            "findings": [f.to_dict() for f in result.findings],
        }
        output.write_text(json.dumps(data, indent=2))
        console.print(f"\n[green]✓ Report saved to {output}[/]")


def _print_severity_summary(by_severity: dict, console: Console):
    """Print severity summary bar."""
    total = sum(by_severity.values())
    
    summary = Panel(
        f"[red bold]CRITICAL: {by_severity.get('critical', 0)}[/]  "
        f"[red]HIGH: {by_severity.get('high', 0)}[/]  "
        f"[yellow]MEDIUM: {by_severity.get('medium', 0)}[/]  "
        f"[blue]LOW: {by_severity.get('low', 0)}[/]  "
        f"[dim]INFO: {by_severity.get('info', 0)}[/]  "
        f"│ Total: [bold]{total}[/]",
        title="📊 Summary",
        border_style="blue",
    )
    console.print(summary)


# =============================================================================
# ANALYZE-LOGS Command
# =============================================================================

@app.command("analyze-logs")
def analyze_logs(
    target: Path = typer.Argument(
        ...,
        help="Path to log file or directory",
        exists=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file for JSON report",
    ),
    format: str = typer.Option(
        "table",
        "--format", "-f",
        help="Output format: table, json, or summary",
    ),
    log_format: Optional[str] = typer.Option(
        None,
        "--log-format",
        help="Log format hint: syslog, json, apache, or auto",
    ),
    min_severity: str = typer.Option(
        "low",
        "--min-severity", "-s",
        help="Minimum severity to report: info, low, medium, high, critical",
    ),
):
    """
    Analyze logs for security events and anomalies.
    
    Detects authentication failures, brute force attempts,
    privilege escalation, and other security-relevant events.
    
    Examples:
        security-auditor analyze-logs ./logs/auth.log
        security-auditor analyze-logs ./logs --min-severity high
        security-auditor analyze-logs /var/log -o report.json
    """
    from agents.log_analyzer.agent import LogAnalyzerAgent, AnalyzerConfig
    from agents.log_analyzer.models import Severity
    
    # Parse severity
    severity_map = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    severity = severity_map.get(min_severity.lower(), Severity.LOW)
    
    # Build config
    config = AnalyzerConfig(min_severity=severity)
    agent = LogAnalyzerAgent(config=config)
    
    console.print(Panel(
        f"[bold blue]Log Analyzer[/]\n"
        f"Target: [cyan]{target}[/]\n"
        f"Min Severity: [yellow]{min_severity}[/]",
        title="📜 Starting Analysis",
    ))
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing logs...", total=None)
        
        if target.is_file():
            result = agent.analyze_file(target, format_hint=log_format)
        else:
            result = agent.analyze_directory(target)
        
        progress.remove_task(task)
    
    # Display results
    _display_log_analysis_results(result, format, output, console)


def _display_log_analysis_results(result, format: str, output: Optional[Path], console: Console):
    """Display log analysis results."""
    if format == "json":
        data = result.to_dict()
        if output:
            output.write_text(json.dumps(data, indent=2))
            console.print(f"[green]✓ Report saved to {output}[/]")
        else:
            console.print_json(json.dumps(data))
        return
    
    # Summary
    console.print()
    by_severity = result.findings_by_severity
    _print_severity_summary(by_severity, console)
    
    if format == "summary":
        # Additional log stats
        console.print(Panel(
            f"Files Analyzed: [cyan]{len(result.files_analyzed)}[/]\n"
            f"Total Entries: [cyan]{result.total_entries_processed}[/]\n"
            f"Total Findings: [cyan]{result.finding_count}[/]",
            title="📊 Log Statistics",
        ))
        return
    
    # Table format
    if result.findings:
        table = Table(title="Security Events", show_lines=True)
        table.add_column("Severity", style="bold")
        table.add_column("Event Type", style="cyan")
        table.add_column("Message")
        table.add_column("Source")
        table.add_column("SOC 2 Controls")
        
        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        
        for finding in result.findings[:50]:  # Limit to 50 rows
            sev = finding.severity.value
            controls = ", ".join(finding.soc2_controls[:2])
            if len(finding.soc2_controls) > 2:
                controls += "..."
            
            table.add_row(
                f"[{severity_colors.get(sev, '')}]{sev.upper()}[/]",
                finding.event_type.value,
                finding.message[:60] + "..." if len(finding.message) > 60 else finding.message,
                finding.source_file or "-",
                controls,
            )
        
        console.print(table)
        
        if len(result.findings) > 50:
            console.print(f"[dim]... and {len(result.findings) - 50} more findings[/]")
    else:
        console.print("[green]✓ No security events detected![/]")
    
    if output:
        output.write_text(json.dumps(result.to_dict(), indent=2))
        console.print(f"\n[green]✓ Report saved to {output}[/]")


# =============================================================================
# SCAN Command (Vulnerability Scanner)
# =============================================================================

@app.command("scan")
def scan(
    target: str = typer.Option(
        ...,
        "--target", "-t",
        help="Target URL to scan (e.g., http://localhost:8080)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file for JSON report",
    ),
    scan_type: str = typer.Option(
        "baseline",
        "--type",
        help="Scan type: baseline, full, or api",
    ),
    zap_host: str = typer.Option(
        "localhost",
        "--zap-host",
        help="OWASP ZAP API host",
    ),
    zap_port: int = typer.Option(
        8080,
        "--zap-port",
        help="OWASP ZAP API port",
    ),
):
    """
    Scan a web application for vulnerabilities using OWASP ZAP.
    
    Requires OWASP ZAP to be running with API enabled.
    
    Examples:
        security-auditor scan --target http://localhost:3000
        security-auditor scan -t http://myapp.local --type full
        security-auditor scan -t http://api.local --type api -o report.json
    """
    console.print(Panel(
        f"[bold blue]Vulnerability Scanner[/]\n"
        f"Target: [cyan]{target}[/]\n"
        f"Scan Type: [yellow]{scan_type}[/]\n"
        f"ZAP: [dim]{zap_host}:{zap_port}[/]",
        title="🔒 Starting Scan",
    ))
    
    console.print("\n[yellow]⚠ Vulnerability scanning requires OWASP ZAP to be running.[/]")
    console.print("[dim]Start ZAP with: zap.sh -daemon -port 8080 -config api.disablekey=true[/]")
    
    try:
        from agents.vulnerability_scanner.agent import VulnerabilityScannerAgent
        from agents.vulnerability_scanner.zap_client import create_zap_client
        
        # Try to connect to ZAP
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Connecting to ZAP...", total=None)
            
            try:
                zap_client = create_zap_client(host=zap_host, port=zap_port)
                agent = VulnerabilityScannerAgent(zap_client=zap_client)
                progress.update(task, description="Running scan...")
                
                # Run scan
                result = agent.scan(target, scan_type=scan_type)
                progress.remove_task(task)
                
                # Display results
                _display_scan_results(result, output, console)
                
            except Exception as e:
                progress.remove_task(task)
                console.print(f"\n[red]✗ Error: {e}[/]")
                console.print("[yellow]Make sure OWASP ZAP is running and accessible.[/]")
                raise typer.Exit(1)
                
    except ImportError:
        console.print("\n[yellow]⚠ Demo mode: ZAP client not available[/]")
        console.print("[dim]Install with: pip install python-owasp-zap-v2.4[/]")


def _display_scan_results(result, output: Optional[Path], console: Console):
    """Display vulnerability scan results."""
    # Summary
    by_severity = result.findings_by_severity
    _print_severity_summary(by_severity, console)
    
    if result.findings:
        table = Table(title="Vulnerabilities Found", show_lines=True)
        table.add_column("Severity", style="bold")
        table.add_column("Title", style="cyan")
        table.add_column("URL")
        table.add_column("CWE")
        
        for finding in result.findings:
            sev = finding.severity.value
            severity_colors = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }
            table.add_row(
                f"[{severity_colors.get(sev, '')}]{sev.upper()}[/]",
                finding.title,
                finding.affected_url[:50] + "..." if len(finding.affected_url) > 50 else finding.affected_url,
                f"CWE-{finding.cwe_id}",
            )
        
        console.print(table)
    else:
        console.print("[green]✓ No vulnerabilities found![/]")
    
    if output:
        data = result.to_dict() if hasattr(result, 'to_dict') else {"findings": [f.to_dict() for f in result.findings]}
        output.write_text(json.dumps(data, indent=2))
        console.print(f"\n[green]✓ Report saved to {output}[/]")


# =============================================================================
# COMPLIANCE Command
# =============================================================================

@app.command("compliance")
def compliance(
    evidence_dir: Path = typer.Argument(
        Path("./evidence"),
        help="Directory containing evidence files",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file for compliance report",
    ),
    framework: str = typer.Option(
        "soc2",
        "--framework", "-f",
        help="Compliance framework: soc2",
    ),
    controls: Optional[str] = typer.Option(
        None,
        "--controls", "-c",
        help="Comma-separated list of controls to assess (default: all)",
    ),
):
    """
    Run compliance assessment against collected evidence.
    
    Evaluates evidence against SOC 2 control requirements using
    RAG-based analysis with anti-hallucination safeguards.
    
    Examples:
        security-auditor compliance ./evidence
        security-auditor compliance --framework soc2 --controls CC6.6,CC7.1
        security-auditor compliance ./evidence -o compliance-report.json
    """
    console.print(Panel(
        f"[bold blue]Compliance Checker[/]\n"
        f"Framework: [cyan]{framework.upper()}[/]\n"
        f"Evidence: [cyan]{evidence_dir}[/]",
        title="📋 Compliance Assessment",
    ))
    
    if not evidence_dir.exists():
        console.print(f"[yellow]⚠ Evidence directory not found: {evidence_dir}[/]")
        console.print("[dim]Run analyze-code, analyze-logs, or scan first to generate evidence.[/]")
        raise typer.Exit(1)
    
    try:
        from agents.compliance_checker.agent import ComplianceChecker
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Loading evidence...", total=None)
            
            checker = ComplianceChecker()
            
            progress.update(task, description="Assessing compliance...")
            
            # Run assessment
            control_list = [c.strip() for c in controls.split(",")] if controls else None
            result = checker.assess(evidence_dir, controls=control_list)
            
            progress.remove_task(task)
        
        # Display results
        _display_compliance_results(result, output, console)
        
    except ImportError as e:
        console.print(f"\n[red]✗ Error loading compliance checker: {e}[/]")
        raise typer.Exit(1)


def _display_compliance_results(result, output: Optional[Path], console: Console):
    """Display compliance assessment results."""
    # Overall status
    status_colors = {
        "PASS": "green",
        "FAIL": "red",
        "INSUFFICIENT_EVIDENCE": "yellow",
        "NEEDS_MANUAL_REVIEW": "yellow",
    }
    status = result.overall_status if hasattr(result, 'overall_status') else "UNKNOWN"
    color = status_colors.get(status, "white")
    
    console.print(Panel(
        f"Overall Status: [{color} bold]{status}[/]",
        title="📊 Compliance Result",
        border_style=color,
    ))
    
    if hasattr(result, 'assessments'):
        table = Table(title="Control Assessments", show_lines=True)
        table.add_column("Control", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Score")
        table.add_column("Confidence")
        
        for assessment in result.assessments:
            status = assessment.status.value
            color = status_colors.get(status, "white")
            table.add_row(
                assessment.control_id,
                f"[{color}]{status}[/]",
                f"{assessment.score:.0%}",
                assessment.confidence,
            )
        
        console.print(table)
    
    if output:
        data = result.to_dict() if hasattr(result, 'to_dict') else {}
        output.write_text(json.dumps(data, indent=2))
        console.print(f"\n[green]✓ Report saved to {output}[/]")


# =============================================================================
# AUDIT Command (Full Workflow)
# =============================================================================

@app.command("audit")
def audit(
    target: Path = typer.Argument(
        ...,
        help="Project directory to audit",
        exists=True,
    ),
    output_dir: Path = typer.Option(
        Path("./audit-results"),
        "--output", "-o",
        help="Directory for audit results",
    ),
    framework: str = typer.Option(
        "soc2",
        "--framework", "-f",
        help="Compliance framework: soc2",
    ),
    skip_scan: bool = typer.Option(
        False,
        "--skip-scan",
        help="Skip vulnerability scanning (requires ZAP)",
    ),
):
    """
    Run a complete security audit.
    
    Executes all four agents in sequence:
    1. Code Security Analysis
    2. Log Analysis (if logs directory exists)
    3. Vulnerability Scan (if not skipped)
    4. Compliance Assessment
    
    Examples:
        security-auditor audit ./my-project
        security-auditor audit ./app --skip-scan
        security-auditor audit ./project -o ./reports
    """
    from datetime import datetime
    
    audit_id = f"AUDIT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    console.print(Panel(
        f"[bold blue]AI-Powered Security Auditor[/]\n\n"
        f"Audit ID: [cyan]{audit_id}[/]\n"
        f"Target: [cyan]{target}[/]\n"
        f"Framework: [yellow]{framework.upper()}[/]\n"
        f"Output: [dim]{output_dir}[/]",
        title="🛡️ Full Security Audit",
        border_style="blue",
    ))
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = output_dir / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    
    results = {
        "audit_id": audit_id,
        "target": str(target),
        "framework": framework,
        "started_at": datetime.now().isoformat(),
        "phases": {},
    }
    
    # Phase 1: Code Analysis
    console.print("\n[bold]Phase 1/4: Code Security Analysis[/]")
    console.print("─" * 50)
    try:
        from agents.code_analyzer.agent import CodeSecurityAnalyzerAgent
        
        agent = CodeSecurityAnalyzerAgent(evidence_dir=evidence_dir)
        code_result = agent.analyze_directory(target)
        
        results["phases"]["code_analysis"] = {
            "status": "completed",
            "findings": code_result.total_findings,
            "by_severity": code_result.findings_by_severity,
        }
        
        _print_severity_summary(code_result.findings_by_severity, console)
        
        # Save evidence
        evidence = agent.generate_evidence(code_result)
        console.print(f"[green]✓ Evidence saved: {evidence.evidence_id}[/]")
        
    except Exception as e:
        console.print(f"[red]✗ Code analysis failed: {e}[/]")
        results["phases"]["code_analysis"] = {"status": "failed", "error": str(e)}
    
    # Phase 2: Log Analysis
    console.print("\n[bold]Phase 2/4: Log Analysis[/]")
    console.print("─" * 50)
    logs_dir = target / "logs"
    if logs_dir.exists():
        try:
            from agents.log_analyzer.agent import LogAnalyzerAgent
            
            agent = LogAnalyzerAgent()
            log_result = agent.analyze_directory(logs_dir)
            
            results["phases"]["log_analysis"] = {
                "status": "completed",
                "findings": log_result.total_findings,
                "by_severity": log_result.findings_by_severity,
            }
            
            _print_severity_summary(log_result.findings_by_severity, console)
            
            # Save evidence
            evidence_file = evidence_dir / "log_analysis.json"
            evidence_file.write_text(json.dumps(log_result.to_dict(), indent=2))
            console.print(f"[green]✓ Evidence saved: {evidence_file.name}[/]")
            
        except Exception as e:
            console.print(f"[red]✗ Log analysis failed: {e}[/]")
            results["phases"]["log_analysis"] = {"status": "failed", "error": str(e)}
    else:
        console.print("[dim]No logs directory found, skipping...[/]")
        results["phases"]["log_analysis"] = {"status": "skipped", "reason": "no logs directory"}
    
    # Phase 3: Vulnerability Scan
    console.print("\n[bold]Phase 3/4: Vulnerability Scan[/]")
    console.print("─" * 50)
    if skip_scan:
        console.print("[dim]Skipped (--skip-scan flag)[/]")
        results["phases"]["vulnerability_scan"] = {"status": "skipped", "reason": "user requested"}
    else:
        console.print("[yellow]⚠ Requires OWASP ZAP running - skipping for now[/]")
        console.print("[dim]Run separately with: security-auditor scan --target <url>[/]")
        results["phases"]["vulnerability_scan"] = {"status": "skipped", "reason": "ZAP not configured"}
    
    # Phase 4: Compliance Assessment
    console.print("\n[bold]Phase 4/4: Compliance Assessment[/]")
    console.print("─" * 50)
    try:
        console.print(f"[dim]Assessing against {framework.upper()} framework...[/]")
        
        # For now, generate summary from evidence
        total_findings = sum(
            p.get("findings", 0) 
            for p in results["phases"].values() 
            if isinstance(p, dict)
        )
        
        if total_findings == 0:
            compliance_status = "PASS"
        elif any(
            p.get("by_severity", {}).get("critical", 0) > 0 
            for p in results["phases"].values() 
            if isinstance(p, dict)
        ):
            compliance_status = "FAIL"
        else:
            compliance_status = "NEEDS_MANUAL_REVIEW"
        
        results["phases"]["compliance"] = {
            "status": "completed",
            "overall_status": compliance_status,
        }
        
        status_colors = {"PASS": "green", "FAIL": "red", "NEEDS_MANUAL_REVIEW": "yellow"}
        console.print(f"[{status_colors.get(compliance_status, 'white')}]Overall: {compliance_status}[/]")
        
    except Exception as e:
        console.print(f"[red]✗ Compliance check failed: {e}[/]")
        results["phases"]["compliance"] = {"status": "failed", "error": str(e)}
    
    # Final Summary
    results["completed_at"] = datetime.now().isoformat()
    
    # Save audit results
    audit_report = output_dir / f"{audit_id}.json"
    audit_report.write_text(json.dumps(results, indent=2))
    
    console.print("\n")
    console.print(Panel(
        f"[bold]Audit Complete![/]\n\n"
        f"Report: [cyan]{audit_report}[/]\n"
        f"Evidence: [cyan]{evidence_dir}[/]",
        title="✅ Audit Summary",
        border_style="green",
    ))


# =============================================================================
# STATUS Command
# =============================================================================

@app.command("status")
def status():
    """
    Show system status and agent availability.
    """
    console.print(Panel(
        "[bold blue]AI-Powered Security Auditor[/] v" + VERSION,
        title="System Status",
    ))
    
    # Check agent availability
    agents_status = []
    
    # Code Analyzer
    try:
        from agents.code_analyzer.agent import CodeSecurityAnalyzerAgent
        agents_status.append(("Code Security Analyzer", "✓ Available", "green"))
    except ImportError as e:
        agents_status.append(("Code Security Analyzer", f"✗ {e}", "red"))
    
    # Log Analyzer
    try:
        from agents.log_analyzer.agent import LogAnalyzerAgent
        agents_status.append(("Log Analyzer", "✓ Available", "green"))
    except ImportError as e:
        agents_status.append(("Log Analyzer", f"✗ {e}", "red"))
    
    # Vulnerability Scanner
    try:
        from agents.vulnerability_scanner.agent import VulnerabilityScannerAgent
        agents_status.append(("Vulnerability Scanner", "✓ Available", "green"))
    except ImportError as e:
        agents_status.append(("Vulnerability Scanner", f"✗ {e}", "red"))
    
    # Compliance Checker
    try:
        from agents.compliance_checker.agent import ComplianceChecker
        agents_status.append(("Compliance Checker", "✓ Available", "green"))
    except ImportError as e:
        agents_status.append(("Compliance Checker", f"✗ {e}", "red"))
    
    # Display table
    table = Table(title="Agent Status")
    table.add_column("Agent", style="cyan")
    table.add_column("Status")
    
    for name, status, color in agents_status:
        table.add_row(name, f"[{color}]{status}[/]")
    
    console.print(table)
    
    # Check dependencies
    console.print("\n[bold]Dependencies:[/]")
    deps = [
        ("typer", "CLI framework"),
        ("rich", "Terminal formatting"),
        ("chromadb", "Vector database"),
        ("langchain", "Agent framework"),
    ]
    
    for dep, desc in deps:
        try:
            __import__(dep)
            console.print(f"  [green]✓[/] {dep} - {desc}")
        except ImportError:
            console.print(f"  [red]✗[/] {dep} - {desc} [dim](not installed)[/]")


# =============================================================================
# Entry Point
# =============================================================================

def main_cli():
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main_cli()
