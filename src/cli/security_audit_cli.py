#!/usr/bin/env python3
"""
AI Security Audit CLI - Main command line interface
"""
import click
import json
import os
import sys
import boto3
import requests
from pathlib import Path
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
import yaml

console = Console()


class SecurityAuditCLI:
    """Main CLI for AI Security Audit Framework"""
    
    def __init__(self):
        self.console = Console()
        self.config_path = Path.home() / '.security' / 'config.json'
        self.api_endpoint = os.environ.get('SECURITY_API_ENDPOINT', '')
        self.api_token = os.environ.get('SECURITY_API_TOKEN', '')
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return {}
    
    def save_config(self, config: Dict[str, Any]):
        """Save configuration to file"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)


@click.group()
@click.version_option(version='1.0.0', prog_name='AI Security Audit')
def cli():
    """AI Security Audit Framework CLI"""
    pass


@cli.command()
@click.option('--interactive/--no-interactive', default=True, help='Run in interactive mode')
@click.option('--api-endpoint', help='API endpoint URL')
@click.option('--api-token', help='API authentication token')
@click.option('--aws-region', help='AWS region')
@click.option('--output', '-o', type=click.Path(), help='Output configuration file')
def configure(interactive, api_endpoint, api_token, aws_region, output):
    """Setup wizard for AI Security Audit Framework"""
    cli_handler = SecurityAuditCLI()
    config = cli_handler.load_config()
    
    console.print("[bold cyan]AI Security Audit Configuration[/bold cyan]\n")
    
    if interactive:
        # API Configuration
        console.print("[yellow]API Configuration[/yellow]")
        api_endpoint = Prompt.ask(
            "API Endpoint URL",
            default=config.get('api', {}).get('endpoint', api_endpoint or '')
        )
        
        api_token = Prompt.ask(
            "API Authentication Token",
            password=True,
            default=config.get('api', {}).get('auth_token', api_token or '')
        )
        
        # AWS Configuration
        console.print("\n[yellow]AWS Configuration[/yellow]")
        aws_region = Prompt.ask(
            "AWS Region",
            default=config.get('aws', {}).get('region', aws_region or 'us-east-1')
        )
        
        # Scanning Configuration
        console.print("\n[yellow]Scanning Configuration[/yellow]")
        default_priority = Prompt.ask(
            "Default scan priority",
            choices=['low', 'normal', 'high', 'critical'],
            default=config.get('scanning', {}).get('default_priority', 'normal')
        )
        
        parallel_agents = Prompt.ask(
            "Number of parallel agents",
            default=str(config.get('scanning', {}).get('parallel_agents', 5))
        )
        
        # Agent Configuration
        console.print("\n[yellow]Agent Configuration[/yellow]")
        enable_sast = Confirm.ask("Enable SAST agent?", default=True)
        enable_dependency = Confirm.ask("Enable dependency scanning?", default=True)
        enable_secrets = Confirm.ask("Enable secrets scanning?", default=True)
        enable_iac = Confirm.ask("Enable IaC scanning?", default=True)
        enable_container = Confirm.ask("Enable container scanning?", default=True)
        
        # AI Features
        console.print("\n[yellow]AI Features[/yellow]")
        enable_ai = Confirm.ask("Enable AI-powered features?", default=True)
        auto_remediation = Confirm.ask("Enable auto-remediation?", default=False)
        
        # Integration Configuration
        console.print("\n[yellow]Integrations[/yellow]")
        enable_slack = Confirm.ask("Enable Slack notifications?", default=False)
        slack_webhook = ""
        if enable_slack:
            slack_webhook = Prompt.ask("Slack webhook URL", password=True)
        
        enable_teams = Confirm.ask("Enable Teams notifications?", default=False)
        teams_webhook = ""
        if enable_teams:
            teams_webhook = Prompt.ask("Teams webhook URL", password=True)
    
    # Build configuration
    config = {
        "version": "1.0.0",
        "api": {
            "endpoint": api_endpoint,
            "auth_token": api_token,
            "timeout": 300,
            "retry_attempts": 3
        },
        "aws": {
            "region": aws_region
        },
        "scanning": {
            "default_priority": default_priority if interactive else "normal",
            "parallel_agents": int(parallel_agents) if interactive else 5
        },
        "agents": {
            "sast": {"enabled": enable_sast if interactive else True},
            "dependency": {"enabled": enable_dependency if interactive else True},
            "secrets": {"enabled": enable_secrets if interactive else True},
            "iac": {"enabled": enable_iac if interactive else True},
            "container": {"enabled": enable_container if interactive else True}
        },
        "ai_features": {
            "enabled": enable_ai if interactive else True,
            "auto_remediation": auto_remediation if interactive else False
        },
        "integrations": {
            "slack": {
                "enabled": enable_slack if interactive else False,
                "webhook_url": slack_webhook if interactive else ""
            },
            "teams": {
                "enabled": enable_teams if interactive else False,
                "webhook_url": teams_webhook if interactive else ""
            }
        }
    }
    
    # Save configuration
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(config, f, indent=2)
        console.print(f"\n[green]✓ Configuration saved to {output_path}[/green]")
    else:
        cli_handler.save_config(config)
        console.print(f"\n[green]✓ Configuration saved to {cli_handler.config_path}[/green]")
    
    # Set environment variables
    os.environ['SECURITY_API_ENDPOINT'] = api_endpoint
    os.environ['SECURITY_API_TOKEN'] = api_token
    os.environ['AWS_DEFAULT_REGION'] = aws_region
    
    console.print("\n[bold green]Configuration complete![/bold green]")
    console.print("Run 'ai-security validate' to verify your configuration.")


@cli.command()
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def validate(config, verbose):
    """Pre-flight checks for AI Security Audit"""
    cli_handler = SecurityAuditCLI()
    
    if config:
        with open(config, 'r') as f:
            configuration = json.load(f)
    else:
        configuration = cli_handler.load_config()
    
    console.print("[bold cyan]AI Security Audit Validation[/bold cyan]\n")
    
    checks = []
    
    # Check configuration file
    config_exists = cli_handler.config_path.exists() or config
    checks.append(("Configuration file", config_exists, "Required"))
    
    # Check API connectivity
    api_endpoint = configuration.get('api', {}).get('endpoint', '')
    api_token = configuration.get('api', {}).get('auth_token', '')
    api_connected = False
    
    if api_endpoint and api_token:
        try:
            response = requests.get(
                f"{api_endpoint}/health",
                headers={"Authorization": f"Bearer {api_token}"},
                timeout=5
            )
            api_connected = response.status_code == 200
        except:
            api_connected = False
    
    checks.append(("API connectivity", api_connected, "Required"))
    
    # Check AWS credentials
    aws_configured = False
    try:
        session = boto3.Session()
        sts = session.client('sts')
        sts.get_caller_identity()
        aws_configured = True
    except:
        aws_configured = False
    
    checks.append(("AWS credentials", aws_configured, "Required"))
    
    # Check AWS services
    if aws_configured:
        try:
            # Check S3
            s3 = boto3.client('s3')
            s3.list_buckets()
            checks.append(("S3 access", True, "Required"))
        except:
            checks.append(("S3 access", False, "Required"))
        
        try:
            # Check DynamoDB
            dynamodb = boto3.client('dynamodb')
            dynamodb.list_tables()
            checks.append(("DynamoDB access", True, "Required"))
        except:
            checks.append(("DynamoDB access", False, "Required"))
        
        try:
            # Check Lambda
            lambda_client = boto3.client('lambda')
            lambda_client.list_functions(MaxItems=1)
            checks.append(("Lambda access", True, "Required"))
        except:
            checks.append(("Lambda access", False, "Required"))
    
    # Check agents configuration
    agents = configuration.get('agents', {})
    enabled_agents = [k for k, v in agents.items() if v.get('enabled', False)]
    checks.append(("Enabled agents", len(enabled_agents) > 0, "Required"))
    
    # Display results
    table = Table(title="Validation Results")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Requirement", style="yellow")
    
    all_passed = True
    for check_name, passed, requirement in checks:
        status = "[green]✓ Passed[/green]" if passed else "[red]✗ Failed[/red]"
        if not passed and requirement == "Required":
            all_passed = False
        table.add_row(check_name, status, requirement)
    
    console.print(table)
    
    if verbose and enabled_agents:
        console.print(f"\n[cyan]Enabled agents:[/cyan] {', '.join(enabled_agents)}")
    
    if all_passed:
        console.print("\n[bold green]✓ All validation checks passed![/bold green]")
        console.print("Your environment is ready for security scanning.")
        return 0
    else:
        console.print("\n[bold red]✗ Validation failed![/bold red]")
        console.print("Please fix the issues above before proceeding.")
        return 1


@cli.command()
@click.option('--scan-id', '-s', required=True, help='Scan ID to generate report for')
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'sarif', 'pdf']), 
              default='html', help='Report format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--dashboard/--no-dashboard', default=False, help='Open dashboard in browser')
def report(scan_id, format, output, dashboard):
    """Generate comprehensive security report"""
    cli_handler = SecurityAuditCLI()
    config = cli_handler.load_config()
    
    api_endpoint = config.get('api', {}).get('endpoint', cli_handler.api_endpoint)
    api_token = config.get('api', {}).get('auth_token', cli_handler.api_token)
    
    if not api_endpoint or not api_token:
        console.print("[red]Error: API configuration missing. Run 'ai-security configure' first.[/red]")
        return 1
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Generating report...", total=None)
        
        try:
            # Fetch scan results
            response = requests.get(
                f"{api_endpoint}/scans/{scan_id}/results",
                headers={"Authorization": f"Bearer {api_token}"},
                params={"format": format}
            )
            response.raise_for_status()
            
            if format == 'json':
                report_data = response.json()
                
                # Display summary
                console.print(f"\n[bold]Security Scan Report - {scan_id}[/bold]\n")
                
                summary = report_data.get('summary', {})
                
                table = Table(title="Vulnerability Summary")
                table.add_column("Severity", style="cyan")
                table.add_column("Count", style="white")
                
                table.add_row("Critical", str(summary.get('critical', 0)))
                table.add_row("High", str(summary.get('high', 0)))
                table.add_row("Medium", str(summary.get('medium', 0)))
                table.add_row("Low", str(summary.get('low', 0)))
                table.add_row("Info", str(summary.get('info', 0)))
                
                console.print(table)
                
                # Save report
                if output:
                    with open(output, 'w') as f:
                        json.dump(report_data, f, indent=2)
                else:
                    output = f"security-report-{scan_id}.json"
                    with open(output, 'w') as f:
                        json.dump(report_data, f, indent=2)
            else:
                # Save binary formats
                if not output:
                    output = f"security-report-{scan_id}.{format}"
                
                with open(output, 'wb') as f:
                    f.write(response.content)
            
            progress.update(task, completed=True)
            console.print(f"\n[green]✓ Report saved to {output}[/green]")
            
            # Open dashboard if requested
            if dashboard:
                dashboard_url = report_data.get('dashboard_url')
                if dashboard_url:
                    import webbrowser
                    webbrowser.open(dashboard_url)
                    console.print(f"[cyan]Dashboard opened in browser: {dashboard_url}[/cyan]")
            
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error generating report: {e}[/red]")
            return 1


@cli.command()
@click.option('--scan-id', '-s', required=True, help='Scan ID with findings to remediate')
@click.option('--finding-ids', '-f', multiple=True, help='Specific finding IDs to remediate')
@click.option('--severity', type=click.Choice(['critical', 'high', 'medium', 'low']), 
              help='Remediate all findings of this severity')
@click.option('--auto-apply/--no-auto-apply', default=False, help='Automatically apply fixes')
@click.option('--dry-run', is_flag=True, help='Show what would be fixed without applying')
def remediate(scan_id, finding_ids, severity, auto_apply, dry_run):
    """Apply AI-powered remediation for vulnerabilities"""
    cli_handler = SecurityAuditCLI()
    config = cli_handler.load_config()
    
    api_endpoint = config.get('api', {}).get('endpoint', cli_handler.api_endpoint)
    api_token = config.get('api', {}).get('auth_token', cli_handler.api_token)
    
    if not api_endpoint or not api_token:
        console.print("[red]Error: API configuration missing. Run 'ai-security configure' first.[/red]")
        return 1
    
    console.print(f"[cyan]Fetching findings for scan {scan_id}...[/cyan]")
    
    try:
        # Get scan findings
        response = requests.get(
            f"{api_endpoint}/scans/{scan_id}/findings",
            headers={"Authorization": f"Bearer {api_token}"}
        )
        response.raise_for_status()
        
        findings = response.json().get('findings', [])
        
        # Filter findings
        if finding_ids:
            findings = [f for f in findings if f['finding_id'] in finding_ids]
        elif severity:
            findings = [f for f in findings if f['severity'].lower() == severity]
        
        if not findings:
            console.print("[yellow]No findings match the criteria.[/yellow]")
            return 0
        
        console.print(f"\n[bold]Found {len(findings)} findings to remediate[/bold]\n")
        
        # Display findings
        table = Table(title="Findings to Remediate")
        table.add_column("Finding ID", style="cyan")
        table.add_column("Type", style="white")
        table.add_column("Severity", style="yellow")
        table.add_column("File", style="blue")
        
        for finding in findings[:10]:  # Show first 10
            table.add_row(
                finding['finding_id'],
                finding['type'],
                finding['severity'],
                finding.get('file_path', 'N/A')
            )
        
        if len(findings) > 10:
            table.add_row("...", "...", "...", f"... and {len(findings) - 10} more")
        
        console.print(table)
        
        if dry_run:
            console.print("\n[yellow]DRY RUN - No changes will be applied[/yellow]")
        
        if not auto_apply and not dry_run:
            if not Confirm.ask("\nDo you want to proceed with remediation?"):
                console.print("[yellow]Remediation cancelled.[/yellow]")
                return 0
        
        # Generate remediations
        console.print("\n[cyan]Generating remediations...[/cyan]")
        
        remediation_request = {
            "scan_id": scan_id,
            "finding_ids": [f['finding_id'] for f in findings],
            "dry_run": dry_run,
            "auto_apply": auto_apply
        }
        
        response = requests.post(
            f"{api_endpoint}/remediations/generate",
            headers={"Authorization": f"Bearer {api_token}"},
            json=remediation_request
        )
        response.raise_for_status()
        
        remediation_result = response.json()
        
        # Display results
        console.print(f"\n[bold]Remediation Results[/bold]\n")
        
        successful = remediation_result.get('successful', 0)
        failed = remediation_result.get('failed', 0)
        
        console.print(f"[green]✓ Successfully remediated: {successful}[/green]")
        console.print(f"[red]✗ Failed to remediate: {failed}[/red]")
        
        if remediation_result.get('remediation_details'):
            console.print("\n[cyan]Remediation Details:[/cyan]")
            for detail in remediation_result['remediation_details'][:5]:
                console.print(f"  - {detail['finding_id']}: {detail['status']}")
                if detail.get('fix_applied'):
                    console.print(f"    Fix: {detail['fix_applied']}")
        
        if not dry_run and successful > 0:
            console.print("\n[green]✓ Remediations applied successfully![/green]")
            console.print("Run a new scan to verify the fixes.")
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error during remediation: {e}[/red]")
        return 1


@cli.command()
@click.argument('repository-url')
@click.option('--branch', '-b', default='main', help='Branch to scan')
@click.option('--priority', '-p', type=click.Choice(['low', 'normal', 'high', 'critical']), 
              default='normal', help='Scan priority')
@click.option('--agents', '-a', default='all', help='Comma-separated list of agents to run')
@click.option('--wait/--no-wait', default=True, help='Wait for scan completion')
@click.option('--output-format', '-f', type=click.Choice(['json', 'table']), 
              default='table', help='Output format')
def scan(repository_url, branch, priority, agents, wait, output_format):
    """Run security scan on a repository"""
    cli_handler = SecurityAuditCLI()
    config = cli_handler.load_config()
    
    api_endpoint = config.get('api', {}).get('endpoint', cli_handler.api_endpoint)
    api_token = config.get('api', {}).get('auth_token', cli_handler.api_token)
    
    if not api_endpoint or not api_token:
        console.print("[red]Error: API configuration missing. Run 'ai-security configure' first.[/red]")
        return 1
    
    # Parse agents
    agent_list = agents.split(',') if agents != 'all' else ['all']
    
    scan_request = {
        "repository_url": repository_url,
        "branch": branch,
        "priority": priority,
        "agents": agent_list
    }
    
    console.print(f"[cyan]Starting security scan on {repository_url}...[/cyan]")
    
    try:
        # Start scan
        response = requests.post(
            f"{api_endpoint}/scans",
            headers={"Authorization": f"Bearer {api_token}"},
            json=scan_request
        )
        response.raise_for_status()
        
        scan_data = response.json()
        scan_id = scan_data['scan_id']
        
        console.print(f"[green]✓ Scan started with ID: {scan_id}[/green]")
        
        if wait:
            # Poll for completion
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Waiting for scan completion...", total=None)
                
                while True:
                    response = requests.get(
                        f"{api_endpoint}/scans/{scan_id}/status",
                        headers={"Authorization": f"Bearer {api_token}"}
                    )
                    response.raise_for_status()
                    
                    status_data = response.json()
                    status = status_data['status']
                    
                    if status in ['completed', 'failed']:
                        break
                    
                    import time
                    time.sleep(5)
                
                progress.update(task, completed=True)
            
            if status == 'completed':
                # Get results
                response = requests.get(
                    f"{api_endpoint}/scans/{scan_id}/results",
                    headers={"Authorization": f"Bearer {api_token}"}
                )
                response.raise_for_status()
                
                results = response.json()
                
                if output_format == 'json':
                    console.print_json(data=results)
                else:
                    # Display summary table
                    summary = results.get('summary', {})
                    
                    table = Table(title=f"Scan Results - {scan_id}")
                    table.add_column("Metric", style="cyan")
                    table.add_column("Value", style="white")
                    
                    table.add_row("Repository", repository_url)
                    table.add_row("Branch", branch)
                    table.add_row("Total Findings", str(summary.get('total_findings', 0)))
                    table.add_row("Critical", str(summary.get('critical', 0)))
                    table.add_row("High", str(summary.get('high', 0)))
                    table.add_row("Medium", str(summary.get('medium', 0)))
                    table.add_row("Low", str(summary.get('low', 0)))
                    table.add_row("Dashboard URL", results.get('dashboard_url', 'N/A'))
                    
                    console.print(table)
                    
                    if summary.get('critical', 0) > 0:
                        console.print("\n[red]⚠ Critical vulnerabilities found![/red]")
                        console.print("Run 'ai-security report' to view detailed findings.")
            else:
                console.print(f"[red]✗ Scan failed: {status_data.get('error', 'Unknown error')}[/red]")
                return 1
        else:
            console.print(f"\nScan ID: {scan_id}")
            console.print("Use 'ai-security status' to check scan progress.")
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        return 1


if __name__ == '__main__':
    cli()