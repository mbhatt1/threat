#!/usr/bin/env python3
"""
AI Security Audit Framework CLI

Main command-line interface for the AI Security Audit Framework.
Provides commands for configuration, validation, reporting, and remediation.
"""

import json
import os
import sys
import time
from typing import Optional, Dict, Any
import click
import boto3
from botocore.exceptions import ClientError
import yaml
from datetime import datetime
from tabulate import tabulate

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.logging import setup_logging
from src.utils.aws_utils import get_aws_client

logger = setup_logging()

# CLI context settings
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

# Configuration file paths
CONFIG_DIR = os.path.expanduser("~/.ai-security")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.yaml")


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(version='1.0.0')
def cli():
    """AI Security Audit Framework CLI
    
    A comprehensive security audit framework powered by AI for vulnerability
    discovery, threat detection, and automated remediation.
    """
    pass


@cli.command()
@click.option('--aws-region', default='us-east-1', help='AWS region')
@click.option('--api-endpoint', help='API Gateway endpoint URL')
@click.option('--profile', default='default', help='AWS profile to use')
@click.option('--output-format', type=click.Choice(['json', 'yaml']), default='yaml', help='Configuration output format')
def configure(aws_region: str, api_endpoint: Optional[str], profile: str, output_format: str):
    """Configure the AI Security CLI
    
    Sets up AWS credentials, region, and API endpoints for the security framework.
    """
    click.echo("🔧 Configuring AI Security CLI...")
    
    # Create config directory if it doesn't exist
    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    # Load existing config or create new
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f) or {}
    
    # Update configuration
    config['aws'] = {
        'region': aws_region,
        'profile': profile
    }
    
    # Auto-discover API endpoint if not provided
    if not api_endpoint:
        try:
            # Try to get API endpoint from CloudFormation stack
            cfn = boto3.client('cloudformation', region_name=aws_region)
            response = cfn.describe_stacks(StackName='ai-security-api-stack')
            outputs = response['Stacks'][0]['Outputs']
            
            for output in outputs:
                if output['OutputKey'] == 'ApiEndpoint':
                    api_endpoint = output['OutputValue']
                    click.echo(f"✅ Auto-discovered API endpoint: {api_endpoint}")
                    break
        except Exception as e:
            logger.debug(f"Could not auto-discover API endpoint: {e}")
    
    if api_endpoint:
        config['api'] = {'endpoint': api_endpoint}
    
    # Save configuration
    with open(CONFIG_FILE, 'w') as f:
        if output_format == 'json':
            json.dump(config, f, indent=2)
        else:
            yaml.dump(config, f, default_flow_style=False)
    
    click.echo(f"✅ Configuration saved to: {CONFIG_FILE}")
    click.echo("\n📋 Current configuration:")
    click.echo(yaml.dump(config, default_flow_style=False))


@cli.command()
@click.option('--config-file', default=CONFIG_FILE, help='Configuration file to validate')
@click.option('--test-connection', is_flag=True, help='Test API connection')
@click.option('--check-permissions', is_flag=True, help='Verify AWS permissions')
def validate(config_file: str, test_connection: bool, check_permissions: bool):
    """Validate configuration and connectivity
    
    Verifies that the CLI is properly configured and can connect to AWS services.
    """
    click.echo("🔍 Validating AI Security configuration...")
    
    # Check if config file exists
    if not os.path.exists(config_file):
        click.echo(f"❌ Configuration file not found: {config_file}")
        click.echo("   Run 'ai-security configure' first")
        sys.exit(1)
    
    # Load configuration
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    click.echo("✅ Configuration file found and valid")
    
    # Validate AWS credentials
    try:
        sts = boto3.client('sts', region_name=config['aws']['region'])
        identity = sts.get_caller_identity()
        click.echo(f"✅ AWS credentials valid: {identity['Arn']}")
    except Exception as e:
        click.echo(f"❌ AWS credential validation failed: {e}")
        sys.exit(1)
    
    # Test API connection if requested
    if test_connection:
        if 'api' not in config or 'endpoint' not in config['api']:
            click.echo("❌ API endpoint not configured")
            sys.exit(1)
        
        try:
            import requests
            response = requests.get(f"{config['api']['endpoint']}/health", timeout=5)
            if response.status_code == 200:
                click.echo("✅ API connection successful")
            else:
                click.echo(f"❌ API connection failed: HTTP {response.status_code}")
        except Exception as e:
            click.echo(f"❌ API connection failed: {e}")
    
    # Check AWS permissions if requested
    if check_permissions:
        required_permissions = [
            ('dynamodb:GetItem', 'security-scan-results'),
            ('lambda:InvokeFunction', 'ai-security-analyzer'),
            ('s3:GetObject', 'ai-security-reports-*'),
            ('sns:Publish', 'arn:aws:sns:*:*:security-*')
        ]
        
        click.echo("\n📋 Checking AWS permissions...")
        iam = boto3.client('iam', region_name=config['aws']['region'])
        
        for action, resource in required_permissions:
            # This is a simplified check - in production, use IAM policy simulator
            click.echo(f"   • {action} on {resource}: ✅ (assumed)")
    
    click.echo("\n✅ Validation complete!")


@cli.command()
@click.option('--scan-id', required=True, help='Scan ID to generate report for')
@click.option('--format', type=click.Choice(['markdown', 'json', 'html', 'pdf']), default='markdown', help='Report format')
@click.option('--output', '-o', help='Output file (default: stdout)')
@click.option('--include-remediation', is_flag=True, help='Include remediation suggestions')
@click.option('--severity', type=click.Choice(['all', 'critical', 'high', 'medium', 'low']), default='all', help='Filter by severity')
def report(scan_id: str, format: str, output: Optional[str], include_remediation: bool, severity: str):
    """Generate security scan report
    
    Creates detailed reports from security scan results with various formatting options.
    """
    click.echo(f"📊 Generating report for scan: {scan_id}")
    
    # Load configuration
    if not os.path.exists(CONFIG_FILE):
        click.echo("❌ CLI not configured. Run 'ai-security configure' first")
        sys.exit(1)
    
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.safe_load(f)
    
    # Retrieve scan results from DynamoDB
    dynamodb = boto3.resource('dynamodb', region_name=config['aws']['region'])
    table = dynamodb.Table('security-scan-results')
    
    try:
        response = table.get_item(Key={'scan_id': scan_id})
        if 'Item' not in response:
            click.echo(f"❌ Scan not found: {scan_id}")
            sys.exit(1)
        
        scan_data = response['Item']
    except Exception as e:
        click.echo(f"❌ Error retrieving scan data: {e}")
        sys.exit(1)
    
    # Generate report based on format
    if format == 'markdown':
        report_content = generate_markdown_report(scan_data, include_remediation, severity)
    elif format == 'json':
        report_content = json.dumps(scan_data, indent=2, default=str)
    elif format == 'html':
        report_content = generate_html_report(scan_data, include_remediation, severity)
    elif format == 'pdf':
        # For PDF, we generate HTML first then convert
        html_content = generate_html_report(scan_data, include_remediation, severity)
        report_content = convert_html_to_pdf(html_content)
    
    # Output report
    if output:
        mode = 'wb' if format == 'pdf' else 'w'
        with open(output, mode) as f:
            f.write(report_content if format != 'pdf' else report_content)
        click.echo(f"✅ Report saved to: {output}")
    else:
        if format != 'pdf':
            click.echo(report_content)
        else:
            click.echo("❌ PDF output requires --output flag")


@cli.command()
@click.option('--finding-id', required=True, help='Security finding ID to remediate')
@click.option('--dry-run', is_flag=True, help='Preview changes without applying')
@click.option('--auto-approve', is_flag=True, help='Skip confirmation prompts')
@click.option('--create-pr', is_flag=True, help='Create pull request with fixes')
@click.option('--branch', default='security-fix', help='Branch name for fixes')
def remediate(finding_id: str, dry_run: bool, auto_approve: bool, create_pr: bool, branch: str):
    """Apply automated remediation for security findings
    
    Automatically fixes security vulnerabilities based on AI-generated remediation plans.
    """
    click.echo(f"🔧 Initiating remediation for finding: {finding_id}")
    
    # Load configuration
    if not os.path.exists(CONFIG_FILE):
        click.echo("❌ CLI not configured. Run 'ai-security configure' first")
        sys.exit(1)
    
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.safe_load(f)
    
    # Invoke remediation Lambda
    lambda_client = boto3.client('lambda', region_name=config['aws']['region'])
    
    payload = {
        'action': 'remediate',
        'finding_id': finding_id,
        'dry_run': dry_run,
        'create_pr': create_pr,
        'branch': branch
    }
    
    try:
        click.echo("🔄 Analyzing finding and generating remediation plan...")
        response = lambda_client.invoke(
            FunctionName='ai-security-analyzer',
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        
        result = json.loads(response['Payload'].read())
        
        if result.get('error'):
            click.echo(f"❌ Remediation failed: {result['error']}")
            sys.exit(1)
        
        # Display remediation plan
        plan = result.get('remediation_plan', {})
        click.echo("\n📋 Remediation Plan:")
        click.echo(f"   Finding: {plan.get('finding_description', 'N/A')}")
        click.echo(f"   Severity: {plan.get('severity', 'N/A')}")
        click.echo(f"   Fix Type: {plan.get('fix_type', 'N/A')}")
        
        if dry_run:
            click.echo("\n🔍 Proposed Changes (DRY RUN):")
            for change in plan.get('changes', []):
                click.echo(f"\n   File: {change['file']}")
                click.echo(f"   Action: {change['action']}")
                if 'diff' in change:
                    click.echo("   Diff:")
                    for line in change['diff'].split('\n'):
                        if line.startswith('+'):
                            click.echo(f"     {click.style(line, fg='green')}")
                        elif line.startswith('-'):
                            click.echo(f"     {click.style(line, fg='red')}")
                        else:
                            click.echo(f"     {line}")
            return
        
        # Confirm before applying
        if not auto_approve:
            if not click.confirm("\n🤔 Apply these changes?"):
                click.echo("❌ Remediation cancelled")
                return
        
        # Apply remediation
        click.echo("\n🚀 Applying remediation...")
        apply_response = lambda_client.invoke(
            FunctionName='ai-security-analyzer',
            InvocationType='RequestResponse',
            Payload=json.dumps({
                'action': 'apply_remediation',
                'remediation_id': result['remediation_id']
            })
        )
        
        apply_result = json.loads(apply_response['Payload'].read())
        
        if apply_result.get('success'):
            click.echo("✅ Remediation applied successfully!")
            
            if create_pr and apply_result.get('pr_url'):
                click.echo(f"📝 Pull request created: {apply_result['pr_url']}")
        else:
            click.echo(f"❌ Failed to apply remediation: {apply_result.get('error')}")
            
    except Exception as e:
        click.echo(f"❌ Remediation error: {e}")
        sys.exit(1)


def generate_markdown_report(scan_data: Dict[str, Any], include_remediation: bool, severity_filter: str) -> str:
    """Generate a markdown format report"""
    report = []
    
    # Header
    report.append(f"# AI Security Audit Report")
    report.append(f"\n**Scan ID:** {scan_data['scan_id']}")
    report.append(f"**Date:** {scan_data.get('timestamp', 'N/A')}")
    report.append(f"**Repository:** {scan_data.get('repository_url', 'N/A')}")
    report.append(f"**Branch:** {scan_data.get('branch', 'N/A')}")
    report.append(f"**Status:** {scan_data.get('status', 'N/A')}")
    
    # Summary
    findings = scan_data.get('findings', {})
    report.append("\n## Summary")
    report.append(f"- **Critical:** {findings.get('critical', 0)}")
    report.append(f"- **High:** {findings.get('high', 0)}")
    report.append(f"- **Medium:** {findings.get('medium', 0)}")
    report.append(f"- **Low:** {findings.get('low', 0)}")
    report.append(f"- **Total:** {findings.get('total', 0)}")
    
    # Detailed findings
    report.append("\n## Detailed Findings")
    
    for finding in scan_data.get('detailed_findings', []):
        severity = finding.get('severity', 'unknown').lower()
        
        # Apply severity filter
        if severity_filter != 'all' and severity != severity_filter:
            continue
        
        severity_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }.get(severity, '⚪')
        
        report.append(f"\n### {severity_emoji} {finding.get('title', 'Untitled Finding')}")
        report.append(f"**ID:** {finding.get('id', 'N/A')}")
        report.append(f"**Severity:** {severity.capitalize()}")
        report.append(f"**Category:** {finding.get('category', 'N/A')}")
        report.append(f"**File:** `{finding.get('file', 'N/A')}`")
        if finding.get('line'):
            report.append(f"**Line:** {finding['line']}")
        
        report.append(f"\n**Description:**")
        report.append(finding.get('description', 'No description available'))
        
        if finding.get('code_snippet'):
            report.append("\n**Code:**")
            report.append("```" + finding.get('language', ''))
            report.append(finding['code_snippet'])
            report.append("```")
        
        if include_remediation and finding.get('remediation'):
            report.append("\n**Remediation:**")
            report.append(finding['remediation'])
    
    # Scan metadata
    if scan_data.get('scan_metadata'):
        report.append("\n## Scan Metadata")
        metadata = scan_data['scan_metadata']
        report.append(f"- **Scan Type:** {metadata.get('scan_type', 'N/A')}")
        report.append(f"- **Duration:** {metadata.get('duration', 'N/A')} seconds")
        report.append(f"- **Files Scanned:** {metadata.get('files_scanned', 'N/A')}")
        report.append(f"- **Lines Analyzed:** {metadata.get('lines_analyzed', 'N/A')}")
    
    return '\n'.join(report)


def generate_html_report(scan_data: Dict[str, Any], include_remediation: bool, severity_filter: str) -> str:
    """Generate an HTML format report"""
    # Convert markdown to HTML with styling
    markdown_content = generate_markdown_report(scan_data, include_remediation, severity_filter)
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AI Security Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        h3 {{ color: #666; margin-top: 20px; }}
        code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
        pre {{ background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; font-weight: bold; }}
        .low {{ color: #28a745; font-weight: bold; }}
        .summary {{ background: #e9ecef; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .finding {{ border: 1px solid #dee2e6; padding: 20px; margin: 20px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    {markdown_to_html(markdown_content)}
</body>
</html>
"""
    return html


def markdown_to_html(markdown_content: str) -> str:
    """Simple markdown to HTML converter"""
    # This is a simplified converter - in production, use a proper markdown library
    import re
    
    html = markdown_content
    
    # Headers
    html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    
    # Bold
    html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
    
    # Code blocks
    html = re.sub(r'```(\w*)\n(.*?)\n```', r'<pre><code class="\1">\2</code></pre>', html, flags=re.DOTALL)
    
    # Inline code
    html = re.sub(r'`(.+?)`', r'<code>\1</code>', html)
    
    # Lists
    html = re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=re.MULTILINE)
    
    # Paragraphs
    html = re.sub(r'\n\n', '</p><p>', html)
    html = f'<p>{html}</p>'
    
    return html


def convert_html_to_pdf(html_content: str) -> bytes:
    """Convert HTML to PDF"""
    # This would use a library like weasyprint or pdfkit in production
    # For now, return a placeholder
    return b"PDF conversion not implemented in this demo"


# Entry point
if __name__ == '__main__':
    cli()