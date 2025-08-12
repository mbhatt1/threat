#!/usr/bin/env python3
"""
Security Audit Framework CLI
Main command-line interface for the security audit framework
"""

import click
import sys
from pathlib import Path
from rich.console import Console

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

# Import CLI modules
from cli.secure_archive_cli import cli as secure_archive_cli
from cli.secure_archive_kms_cli import cli as secure_archive_kms_cli

console = Console()


@click.group()
@click.version_option(version='1.0.0', prog_name='Security Audit Framework')
def cli():
    """
    Security Audit Framework CLI
    
    A comprehensive security audit and analysis tool for AWS environments.
    """
    pass


@cli.group()
def scan():
    """Run security scans"""
    pass


@scan.command()
@click.argument('target', type=click.Path(exists=True))
@click.option('--type', '-t', type=click.Choice(['sast', 'container', 'iac', 'dependency']), 
              default='sast', help='Type of scan to run')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'pdf']), 
              default='json', help='Output format')
def run(target, type, output, format):
    """Run a security scan on target"""
    console.print(f"[cyan]Running {type} scan on {target}...[/cyan]")
    
    # TODO: Implement scan runners
    console.print("[yellow]Scan functionality not yet implemented[/yellow]")


@cli.group()
def agent():
    """Manage security agents"""
    pass


@agent.command()
@click.option('--all', is_flag=True, help='List all agents')
@click.option('--status', is_flag=True, help='Show agent status')
def list(all, status):
    """List available agents"""
    agents = [
        ('sast', 'Static Application Security Testing', 'active'),
        ('container-scanner', 'Container Security Scanner', 'active'),
        ('threat-intel', 'Threat Intelligence Agent', 'active'),
        ('supply-chain', 'Supply Chain Security', 'active'),
        ('infra-security', 'Infrastructure Security', 'active'),
        ('red-team', 'Red Team Agent', 'inactive'),
    ]
    
    from rich.table import Table
    
    table = Table(title="Security Agents")
    table.add_column("Agent", style="cyan")
    table.add_column("Description", style="white")
    if status:
        table.add_column("Status", style="green")
    
    for agent_info in agents:
        row = [agent_info[0], agent_info[1]]
        if status:
            row.append(agent_info[2])
        table.add_row(*row)
    
    console.print(table)


@cli.group()
def report():
    """Generate and manage reports"""
    pass


@report.command()
@click.option('--scan-id', '-s', help='Scan ID to generate report for')
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'pdf', 'executive']), 
              default='html', help='Report format')
@click.option('--output', '-o', help='Output file path')
def generate(scan_id, format, output):
    """Generate security report"""
    console.print(f"[cyan]Generating {format} report...[/cyan]")
    
    # TODO: Implement report generation
    console.print("[yellow]Report generation not yet implemented[/yellow]")


@cli.group()
def deploy():
    """Deploy framework to AWS"""
    pass


@deploy.command()
@click.option('--environment', '-e', type=click.Choice(['dev', 'staging', 'prod']), 
              default='dev', help='Deployment environment')
@click.option('--region', '-r', default='us-east-1', help='AWS region')
@click.option('--profile', '-p', help='AWS profile to use')
def aws(environment, region, profile):
    """Deploy to AWS using CDK"""
    console.print(f"[cyan]Deploying to AWS {environment} in {region}...[/cyan]")
    
    import subprocess
    
    cmd = ['cdk', 'deploy', '--all', '--require-approval', 'never']
    cmd.extend(['--context', f'environment={environment}'])
    
    if profile:
        cmd.extend(['--profile', profile])
    
    env = {'AWS_REGION': region}
    
    try:
        subprocess.run(cmd, env=env, check=True)
        console.print("[green]✓ Deployment successful![/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]✗ Deployment failed: {e}[/red]")
        sys.exit(1)


# Add the secure archive commands
cli.add_command(secure_archive_cli, name='archive')
cli.add_command(secure_archive_kms_cli, name='archive-kms')


@cli.command()
@click.option('--check', is_flag=True, help='Check configuration')
def config(check):
    """Manage framework configuration"""
    if check:
        import os
        
        console.print("[bold]Configuration Check[/bold]\n")
        
        # Check environment variables
        env_vars = [
            ('AWS_REGION', 'AWS region'),
            ('ARCHIVE_S3_BUCKET', 'Archive S3 bucket'),
            ('BEDROCK_MODEL_ID', 'Bedrock model ID'),
            ('LOG_LEVEL', 'Logging level'),
        ]
        
        from rich.table import Table
        
        table = Table(title="Environment Variables")
        table.add_column("Variable", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Value", style="yellow")
        table.add_column("Status", style="green")
        
        for var, desc in env_vars:
            value = os.environ.get(var, '')
            status = '✓' if value else '✗'
            status_color = 'green' if value else 'red'
            table.add_row(
                var, 
                desc, 
                value[:20] + '...' if len(value) > 20 else value,
                f'[{status_color}]{status}[/{status_color}]'
            )
        
        console.print(table)


@cli.command()
def init():
    """Initialize a new security audit project"""
    console.print("[cyan]Initializing Security Audit Framework...[/cyan]")
    
    import os
    import shutil
    
    # Create project structure
    dirs = [
        'scans',
        'reports',
        'configs',
        'archives',
    ]
    
    for dir_name in dirs:
        os.makedirs(dir_name, exist_ok=True)
        console.print(f"  [green]✓[/green] Created {dir_name}/")
    
    # Copy example configuration
    if os.path.exists('.env.example') and not os.path.exists('.env'):
        shutil.copy('.env.example', '.env')
        console.print("  [green]✓[/green] Created .env from example")
    
    console.print("\n[green]✓ Project initialized successfully![/green]")
    console.print("\nNext steps:")
    console.print("  1. Edit .env with your configuration")
    console.print("  2. Run 'saf-cli deploy aws' to deploy to AWS")
    console.print("  3. Run 'saf-cli scan run <target>' to start scanning")


# Quick commands for common tasks
@cli.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--password', '-p', prompt=True, hide_input=True,
              confirmation_prompt=True, help='Encryption password')
def quick_backup(directory, password):
    """Quick backup of a directory (archive + encrypt + upload)"""
    from shared.secure_archive import SecureArchive
    
    sa = SecureArchive()
    
    with console.status("[cyan]Performing quick backup...") as status:
        try:
            result = sa.secure_backup_directory(directory, password=password)
            
            console.print(f"\n[green]✓ Backup completed![/green]")
            console.print(f"  Location: [blue]{result['s3_uri']}[/blue]")
            console.print(f"  Size: [yellow]{result['encrypted_size']:,} bytes[/yellow]")
            
            if result['analysis']['security_concerns']:
                console.print(f"\n[red]⚠ Security concerns found:[/red]")
                for concern in result['analysis']['security_concerns'][:3]:
                    console.print(f"  - {concern['file']}: {concern['concern']}")
                    
        except Exception as e:
            console.print(f"[red]✗ Backup failed: {e}[/red]")
            sys.exit(1)


@cli.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--kms-key', '-k', envvar='KMS_KEY_ID', help='KMS key ID or alias')
@click.option('--s3-prefix', '-p', help='S3 key prefix')
def quick_backup_kms(directory, kms_key, s3_prefix):
    """Quick backup with KMS encryption (archive + encrypt + upload)"""
    from shared.secure_archive_kms import SecureArchiveKMS
    
    if not kms_key:
        console.print("[red]Error: KMS key ID is required![/red]")
        console.print("Set KMS_KEY_ID environment variable or use --kms-key option")
        sys.exit(1)
    
    try:
        sa = SecureArchiveKMS(kms_key_id=kms_key)
    except Exception as e:
        console.print(f"[red]✗ KMS initialization failed: {e}[/red]")
        sys.exit(1)
    
    with console.status("[cyan]Performing KMS-secured backup...") as status:
        try:
            result = sa.secure_backup_directory_kms(directory, s3_prefix)
            
            console.print(f"\n[green]✓ KMS Backup completed![/green]")
            console.print(f"  Location: [blue]{result['s3_uri']}[/blue]")
            console.print(f"  Size: [yellow]{result['encrypted_size']:,} bytes[/yellow]")
            console.print(f"  KMS Key: [cyan]{kms_key}[/cyan]")
            console.print(f"  Encryption: [green]{result['encryption_type']}[/green]")
            
            if result['analysis']['security_concerns']:
                console.print(f"\n[red]⚠ Security concerns found:[/red]")
                for concern in result['analysis']['security_concerns'][:3]:
                    console.print(f"  - {concern['file']}: {concern['concern']} [{concern['severity']}]")
                    
        except Exception as e:
            console.print(f"[red]✗ Backup failed: {e}[/red]")
            sys.exit(1)


if __name__ == '__main__':
    cli()