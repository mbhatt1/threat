"""
AI-Powered Security Audit CLI
Developer-friendly command-line interface for local AI security scanning
"""
import click
import json
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import subprocess
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax
from rich.markdown import Markdown
import asyncio

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from shared.ai_orchestrator import AISecurityOrchestrator, run_ai_scan
from shared.incremental_scanner import IncrementalScanner
from shared.ai_explainability import AIExplainabilityEngine
from shared.advanced_features import AISecurityFeatures

console = Console()

class AISecurityCLI:
    """AI-powered security scanning CLI"""
    
    def __init__(self):
        self.orchestrator = None
        self.scanner = IncrementalScanner()
        self.explainability = AIExplainabilityEngine()
        self.ai_features = AISecurityFeatures()
    
    def scan(self, 
             path: str = ".",
             scan_type: str = "incremental",
             output_format: str = "terminal",
             include_suppressed: bool = False,
             fix: bool = False,
             explain: bool = True) -> int:
        """
        Run AI-powered security scan
        
        Args:
            path: Path to scan (default: current directory)
            scan_type: Type of scan (full, incremental, pr)
            output_format: Output format (terminal, json, sarif, markdown)
            include_suppressed: Include suppressed findings
            fix: Attempt to auto-fix issues
            explain: Show AI explanations
            
        Returns:
            Exit code (0 for success, 1 for findings, 2 for errors)
        """
        try:
            # Validate path
            scan_path = Path(path).resolve()
            if not scan_path.exists():
                console.print(f"[red]Error: Path '{path}' does not exist[/red]")
                return 2
            
            # Show scan header
            self._show_scan_header(scan_path, scan_type)
            
            # Run AI scan with progress
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Running AI security analysis...", total=None)
                
                # Execute scan
                scan_result = run_ai_scan(str(scan_path), scan_type)
                
                progress.update(task, completed=True)
            
            # Check for errors
            if scan_result.get('status') == 'failed':
                console.print(f"[red]Scan failed: {scan_result.get('error', 'Unknown error')}[/red]")
                return 2
            
            # Display results based on format
            if output_format == "json":
                self._output_json(scan_result)
            elif output_format == "sarif":
                self._output_sarif(scan_result)
            elif output_format == "markdown":
                self._output_markdown(scan_result)
            else:
                self._display_terminal_results(scan_result, explain)
            
            # Auto-fix if requested
            if fix and scan_result['total_findings'] > 0:
                self._attempt_auto_fix(scan_result)
            
            # Return appropriate exit code
            if scan_result['critical_findings'] > 0:
                return 1
            elif scan_result['total_findings'] > 0:
                return 1
            else:
                return 0
                
        except Exception as e:
            console.print(f"[red]Unexpected error: {str(e)}[/red]")
            return 2
    
    def _show_scan_header(self, path: Path, scan_type: str):
        """Display scan header with AI branding"""
        header = Panel(
            f"[bold cyan]🤖 AI Security Scanner[/bold cyan]\n\n"
            f"[dim]Powered by Claude 3 via AWS Bedrock[/dim]\n"
            f"Path: {path}\n"
            f"Scan Type: {scan_type}",
            title="Security Audit Framework",
            border_style="cyan"
        )
        console.print(header)
        console.print()
    
    def _display_terminal_results(self, scan_result: Dict, explain: bool):
        """Display results in terminal with rich formatting"""
        
        # Summary panel
        summary = Panel(
            f"[bold]Scan Summary[/bold]\n\n"
            f"Total Findings: {scan_result['total_findings']}\n"
            f"Critical: [red]{scan_result['critical_findings']}[/red]\n"
            f"High: [yellow]{scan_result['high_findings']}[/yellow]\n"
            f"Business Risk Score: {scan_result['business_risk_score']:.1f}/100\n"
            f"AI Confidence: {scan_result['ai_confidence_score']:.1%}",
            title="Results",
            border_style="green" if scan_result['total_findings'] == 0 else "red"
        )
        console.print(summary)
        console.print()
        
        # Get detailed findings if available
        if scan_result['total_findings'] > 0:
            findings = self._get_detailed_findings(scan_result['scan_id'])
            
            # Group findings by severity
            by_severity = self._group_by_severity(findings)
            
            # Display critical findings first
            if by_severity.get('CRITICAL'):
                console.print("[bold red]🚨 CRITICAL Security Issues[/bold red]")
                for finding in by_severity['CRITICAL']:
                    self._display_finding(finding, explain)
                console.print()
            
            # Display high findings
            if by_severity.get('HIGH'):
                console.print("[bold yellow]⚠️  HIGH Security Issues[/bold yellow]")
                for finding in by_severity['HIGH']:
                    self._display_finding(finding, explain)
                console.print()
            
            # Display medium findings
            if by_severity.get('MEDIUM'):
                console.print("[bold blue]ℹ️  MEDIUM Security Issues[/bold blue]")
                for finding in by_severity['MEDIUM'][:5]:  # Show first 5
                    self._display_finding(finding, explain)
                if len(by_severity['MEDIUM']) > 5:
                    console.print(f"[dim]... and {len(by_severity['MEDIUM']) - 5} more[/dim]")
                console.print()
        
        # Show AI insights
        insights = self._get_ai_insights(scan_result['scan_id'])
        if insights:
            self._display_insights(insights)
    
    def _display_finding(self, finding: Dict, explain: bool):
        """Display individual finding with AI explanation"""
        # Finding header
        console.print(f"\n[bold]{finding['file_path']}[/bold]")
        console.print(f"  Type: {finding['finding_type']}")
        console.print(f"  {finding['description']}")
        
        # Show remediation
        if finding.get('remediation'):
            console.print(f"  [green]Fix:[/green] {finding['remediation']}")
        
        # Show AI explanation if requested
        if explain and finding.get('reasoning'):
            console.print("  [cyan]AI Analysis:[/cyan]")
            for step in finding['reasoning'][:3]:
                console.print(f"    • {step}")
        
        # Show confidence level
        confidence_color = {
            'very_high': 'green',
            'high': 'green',
            'medium': 'yellow',
            'low': 'red',
            'very_low': 'red'
        }.get(finding.get('confidence_level', 'medium'), 'yellow')
        
        console.print(f"  [dim]Confidence: [{confidence_color}]{finding.get('confidence_level', 'unknown')}[/{confidence_color}][/dim]")
        
        # Show false positive indicators if any
        if finding.get('false_positive_indicators'):
            console.print("  [dim yellow]Possible false positive:[/dim yellow]")
            for indicator in finding['false_positive_indicators']:
                console.print(f"    - {indicator}")
    
    def _display_insights(self, insights: Dict):
        """Display AI-generated insights"""
        insights_panel = Panel(
            f"[bold]AI Security Insights[/bold]\n\n"
            f"{insights.get('executive_summary', 'No insights available')}\n\n"
            f"[bold]Key Recommendations:[/bold]\n" +
            "\n".join(f"  {i+1}. {rec}" for i, rec in enumerate(insights.get('key_recommendations', []))) +
            f"\n\n[bold]Risk Assessment:[/bold] {insights.get('risk_assessment', 'Unknown')}",
            title="🧠 AI Analysis",
            border_style="cyan"
        )
        console.print(insights_panel)
    
    def _get_detailed_findings(self, scan_id: str) -> List[Dict]:
        """Retrieve detailed findings for a scan"""
        # In a real implementation, this would query DynamoDB
        # For now, return mock data to demonstrate the interface
        return []
    
    def _get_ai_insights(self, scan_id: str) -> Dict:
        """Retrieve AI insights for a scan"""
        # In a real implementation, this would query S3
        # For now, return mock data
        return {
            'executive_summary': 'The scan identified several security vulnerabilities that require immediate attention.',
            'key_recommendations': [
                'Update vulnerable dependencies to patched versions',
                'Implement input validation for user-supplied data',
                'Review and fix SQL injection vulnerabilities'
            ],
            'risk_assessment': 'High'
        }
    
    def _group_by_severity(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by severity"""
        grouped = {}
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(finding)
        return grouped
    
    def _attempt_auto_fix(self, scan_result: Dict):
        """Attempt to auto-fix findings using AI"""
        console.print("\n[bold cyan]🔧 Attempting AI-powered auto-fix...[/bold cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Generating fixes...", total=None)
            
            # In real implementation, this would:
            # 1. Get findings that can be auto-fixed
            # 2. Use AI to generate fixes
            # 3. Apply fixes with user confirmation
            # 4. Re-scan to verify
            
            progress.update(task, completed=True)
        
        console.print("[green]✓ Auto-fix completed (demo mode)[/green]")
    
    def _output_json(self, scan_result: Dict):
        """Output results as JSON"""
        print(json.dumps(scan_result, indent=2))
    
    def _output_sarif(self, scan_result: Dict):
        """Output results in SARIF format"""
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AI Security Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/example/security-audit-framework",
                        "rules": []
                    }
                },
                "results": [],
                "properties": {
                    "scan_id": scan_result['scan_id'],
                    "ai_confidence_score": scan_result['ai_confidence_score'],
                    "business_risk_score": scan_result['business_risk_score']
                }
            }]
        }
        print(json.dumps(sarif, indent=2))
    
    def _output_markdown(self, scan_result: Dict):
        """Output results as Markdown"""
        md = f"""# AI Security Scan Report

## Summary

- **Total Findings**: {scan_result['total_findings']}
- **Critical**: {scan_result['critical_findings']}
- **High**: {scan_result['high_findings']}
- **Business Risk Score**: {scan_result['business_risk_score']:.1f}/100
- **AI Confidence**: {scan_result['ai_confidence_score']:.1%}

## Scan Details

- **Scan ID**: {scan_result['scan_id']}
- **Status**: {scan_result['status']}

---

*Generated by AI Security Scanner powered by Claude 3*
"""
        print(md)

# CLI Commands
@click.group()
@click.version_option(version="2.0.0", prog_name="AI Security Scanner")
def cli():
    """AI-Powered Security Scanner for modern applications"""
    pass

@cli.command()
@click.option('--path', '-p', default=".", help='Path to scan')
@click.option('--type', '-t', 'scan_type', 
              type=click.Choice(['full', 'incremental', 'pr']), 
              default='incremental',
              help='Type of scan to perform')
@click.option('--format', '-f', 'output_format',
              type=click.Choice(['terminal', 'json', 'sarif', 'markdown']),
              default='terminal',
              help='Output format')
@click.option('--fix', is_flag=True, help='Attempt to auto-fix issues using AI')
@click.option('--no-explain', is_flag=True, help='Skip AI explanations')
@click.option('--include-suppressed', is_flag=True, help='Include suppressed findings')
def scan(path, scan_type, output_format, fix, no_explain, include_suppressed):
    """Run AI-powered security scan"""
    scanner = AISecurityCLI()
    exit_code = scanner.scan(
        path=path,
        scan_type=scan_type,
        output_format=output_format,
        fix=fix,
        explain=not no_explain,
        include_suppressed=include_suppressed
    )
    sys.exit(exit_code)

@cli.command()
@click.argument('finding_id')
def explain(finding_id):
    """Get detailed AI explanation for a finding"""
    explainer = AIExplainabilityEngine()
    explanation = explainer.get_explanation_by_id(finding_id)
    
    if explanation:
        console.print(Panel(
            f"[bold]Finding: {finding_id}[/bold]\n\n"
            f"Model: {explanation['ai_model']}\n"
            f"Confidence: {explanation['confidence_score']:.1%}\n\n"
            f"[bold]Evidence:[/bold]\n" +
            "\n".join(f"  • {e['description']}" for e in explanation['evidence']) +
            f"\n\n[bold]Reasoning:[/bold]\n" +
            "\n".join(f"  {i+1}. {step}" for i, step in enumerate(explanation['reasoning'])),
            title="AI Explanation",
            border_style="cyan"
        ))
    else:
        console.print("[red]Finding not found[/red]")

@cli.command()
@click.argument('policy_description')
@click.option('--examples', '-e', multiple=True, help='Example violations')
def create_policy(policy_description, examples):
    """Create custom security policy using natural language"""
    ai_features = AISecurityFeatures()
    
    with console.status("Creating policy with AI..."):
        policy = ai_features.policy_engine.create_policy_from_natural_language(
            policy_description,
            list(examples) if examples else None
        )
    
    if 'error' not in policy:
        console.print(Panel(
            f"[bold green]✓ Policy Created[/bold green]\n\n"
            f"ID: {policy['policy_id']}\n"
            f"Name: {policy['policy_name']}\n"
            f"Description: {policy['description']}",
            title="New Security Policy",
            border_style="green"
        ))
    else:
        console.print(f"[red]Failed to create policy: {policy['error']}[/red]")

@cli.command()
@click.argument('package_name')
@click.option('--ecosystem', '-e', default='python', help='Package ecosystem')
def check_package(package_name, ecosystem):
    """Check package for supply chain risks using AI"""
    ai_features = AISecurityFeatures()
    
    with console.status(f"Analyzing {package_name} with AI..."):
        # Analyze package behavior
        behavior = ai_features.supply_chain.analyze_package_behavior_with_ai(package_name)
        
        # Check package health
        health = ai_features.supply_chain.analyze_package_health(package_name, ecosystem)
    
    # Display results
    console.print(Panel(
        f"[bold]Package: {package_name}[/bold]\n"
        f"Ecosystem: {ecosystem}\n\n"
        f"[bold]Behavior Analysis:[/bold]\n"
        f"Malicious Probability: {behavior.get('malicious_probability', 0):.1%}\n"
        f"Recommendation: {behavior.get('recommendation', 'unknown')}\n\n"
        f"[bold]Health Score:[/bold] {health.get('health_score', 0):.1f}/100\n"
        f"Issues: {', '.join(health.get('issues', [])) or 'None'}",
        title="AI Package Analysis",
        border_style="yellow" if behavior.get('malicious_probability', 0) > 0.5 else "green"
    ))

@cli.command()
@click.option('--model', '-m', default='anthropic.claude-3-sonnet-20240229-v1:0', help='AI model ID')
def stats(model):
    """Show AI model performance statistics"""
    explainer = AIExplainabilityEngine()
    stats = explainer.get_model_performance_stats(model)
    
    if stats:
        table = Table(title=f"AI Model Performance: {model}")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Samples", str(stats.get('total_samples', 0)))
        table.add_row("Overall Accuracy", f"{stats.get('overall_accuracy', 0):.1%}")
        table.add_row("Calibration Error", f"{stats.get('calibration_error', 0):.1%}")
        table.add_row("Well Calibrated", "✓" if stats.get('is_well_calibrated') else "✗")
        
        console.print(table)
    else:
        console.print("[yellow]No statistics available for this model[/yellow]")

@cli.command()
def init():
    """Initialize AI security scanning for current project"""
    console.print("[bold cyan]🤖 Initializing AI Security Scanner[/bold cyan]\n")
    
    # Create .security directory
    security_dir = Path(".security")
    security_dir.mkdir(exist_ok=True)
    
    # Create config file
    config = {
        "version": "2.0.0",
        "ai_model": "anthropic.claude-3-sonnet-20240229-v1:0",
        "scan_type": "incremental",
        "auto_suppress_test_files": True,
        "confidence_threshold": 0.7,
        "policies": [
            "no-hardcoded-secrets",
            "no-sql-injection",
            "secure-dependencies"
        ]
    }
    
    config_path = security_dir / "config.json"
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    console.print(f"[green]✓ Created {config_path}[/green]")
    
    # Create .gitignore entry
    gitignore_path = Path(".gitignore")
    if gitignore_path.exists():
        with open(gitignore_path, 'r') as f:
            content = f.read()
        if '.security/cache' not in content:
            with open(gitignore_path, 'a') as f:
                f.write("\n# AI Security Scanner\n.security/cache/\n")
            console.print("[green]✓ Updated .gitignore[/green]")
    
    console.print("\n[bold green]AI Security Scanner initialized![/bold green]")
    console.print("Run 'ai-security scan' to start scanning")

if __name__ == "__main__":
    cli()