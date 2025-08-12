#!/usr/bin/env python3
"""
Secure Archive KMS CLI Tool
Command-line interface for secure directory archiving with AWS KMS encryption
"""

import click
import json
import os
import sys
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.syntax import Syntax

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
from shared.secure_archive_kms import SecureArchiveKMS

console = Console()


@click.group()
@click.option('--s3-bucket', envvar='ARCHIVE_S3_BUCKET', help='S3 bucket for storage')
@click.option('--kms-key', envvar='KMS_KEY_ID', help='AWS KMS key ID or alias')
@click.option('--region', envvar='AWS_REGION', default='us-east-1', help='AWS region')
@click.pass_context
def cli(ctx, s3_bucket: Optional[str], kms_key: Optional[str], region: str):
    """Security Audit Framework - Secure Archive Tool with AWS KMS"""
    ctx.ensure_object(dict)
    
    if not kms_key:
        console.print("[red]Error: KMS key ID is required![/red]")
        console.print("Set KMS_KEY_ID environment variable or use --kms-key option")
        sys.exit(1)
    
    try:
        ctx.obj['archive'] = SecureArchiveKMS(
            s3_bucket=s3_bucket, 
            kms_key_id=kms_key,
            region=region
        )
        console.print(f"[green]✓[/green] Using KMS key: [cyan]{kms_key}[/cyan]")
    except Exception as e:
        console.print(f"[red]✗ Error initializing KMS:[/red] {str(e)}")
        sys.exit(1)


@cli.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output archive path')
@click.option('--exclude', '-e', multiple=True, help='Patterns to exclude')
@click.pass_context
def archive(ctx, directory: str, output: Optional[str], exclude: tuple):
    """Create tar.gz archive of a directory"""
    sa = ctx.obj['archive']
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Creating archive...", total=None)
        
        try:
            archive_path = sa.archive_directory(directory, output, list(exclude))
            progress.update(task, completed=100)
            
            console.print(f"\n[green]✓[/green] Archive created: [blue]{archive_path}[/blue]")
            
            # Show archive info
            size_mb = os.path.getsize(archive_path) / (1024 * 1024)
            console.print(f"  Size: [yellow]{size_mb:.2f} MB[/yellow]")
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


@cli.command()
@click.argument('archive-path', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output encrypted file path')
@click.pass_context
def encrypt(ctx, archive_path: str, output: Optional[str]):
    """Encrypt a tar.gz archive using AWS KMS"""
    sa = ctx.obj['archive']
    
    with console.status("[bold cyan]Encrypting archive with KMS...") as status:
        try:
            result = sa.encrypt_archive_kms(archive_path, output)
            
            console.print(f"\n[green]✓[/green] Archive encrypted: [blue]{result['encrypted_path']}[/blue]")
            
            # Show encryption details
            table = Table(title="KMS Encryption Details", show_header=False)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="yellow")
            
            metadata = result['metadata']
            table.add_row("Original Size", f"{metadata['original_size']:,} bytes")
            table.add_row("Encrypted Size", f"{metadata['encrypted_size']:,} bytes")
            table.add_row("KMS Key ID", metadata['kms_key_id'])
            table.add_row("Encryption Algorithm", metadata['encryption_algorithm'])
            table.add_row("Checksum", metadata['checksum'][:16] + "...")
            table.add_row("Timestamp", metadata['timestamp'])
            
            console.print(table)
            console.print(f"\n[dim]KMS Key ARN: {result['kms_key_arn']}[/dim]")
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


@cli.command()
@click.argument('encrypted-path', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output decrypted file path')
@click.pass_context
def decrypt(ctx, encrypted_path: str, output: Optional[str]):
    """Decrypt a KMS-encrypted archive"""
    sa = ctx.obj['archive']
    
    with console.status("[bold cyan]Decrypting archive with KMS...") as status:
        try:
            decrypted_path = sa.decrypt_archive_kms(encrypted_path, output)
            
            console.print(f"\n[green]✓[/green] Archive decrypted: [blue]{decrypted_path}[/blue]")
            
            # Show decrypted file info
            size_mb = os.path.getsize(decrypted_path) / (1024 * 1024)
            console.print(f"  Size: [yellow]{size_mb:.2f} MB[/yellow]")
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            console.print("\n[yellow]Possible causes:[/yellow]")
            console.print("  • Insufficient KMS permissions")
            console.print("  • Wrong KMS key or region")
            console.print("  • Corrupted encrypted file")
            sys.exit(1)


@cli.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--s3-prefix', '-p', help='S3 key prefix')
@click.option('--analyze', is_flag=True, help='Show content analysis')
@click.pass_context
def backup(ctx, directory: str, s3_prefix: Optional[str], analyze: bool):
    """Complete backup workflow with KMS: archive, encrypt, and upload"""
    sa = ctx.obj['archive']
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Performing KMS-secured backup...", total=3)
        
        try:
            progress.update(task, description="[cyan]Creating archive...", completed=1)
            result = sa.secure_backup_directory_kms(directory, s3_prefix)
            progress.update(task, completed=3)
            
            # Display results
            panel = Panel(
                f"[green]✓ Backup completed successfully![/green]\n\n"
                f"S3 URI: [blue]{result['s3_uri']}[/blue]\n"
                f"Archive size: [yellow]{result['archive_size']:,} bytes[/yellow]\n"
                f"Encrypted size: [yellow]{result['encrypted_size']:,} bytes[/yellow]\n"
                f"Encryption: [cyan]{result['encryption_type']}[/cyan]\n"
                f"KMS Key: [dim]{result['kms_key_arn']}[/dim]",
                title="Backup Summary",
                border_style="green"
            )
            console.print(panel)
            
            if analyze and 'analysis' in result:
                console.print("\n[bold]Content Analysis[/bold]")
                analysis = result['analysis']
                
                # Summary table
                summary_table = Table(show_header=False)
                summary_table.add_column("Metric", style="cyan")
                summary_table.add_column("Value", style="yellow")
                
                summary_table.add_row("Total Files", f"{analysis['total_files']:,}")
                summary_table.add_row("Total Size", f"{analysis['summary']['total_size_mb']:.2f} MB")
                summary_table.add_row("Security Risk", 
                    f"[{'red' if analysis['summary']['security_risk'] == 'high' else 'green'}]"
                    f"{analysis['summary']['security_risk']}[/]"
                )
                
                console.print(summary_table)
                
                # Security concerns if any
                if analysis['security_concerns']:
                    console.print(f"\n[red]⚠ Security Concerns ({len(analysis['security_concerns'])})[/red]")
                    for concern in analysis['security_concerns'][:5]:
                        severity_color = 'red' if concern['severity'] == 'critical' else 'yellow'
                        console.print(
                            f"  [{severity_color}]•[/{severity_color}] {concern['file']}: "
                            f"{concern['concern']} [{concern['severity']}]"
                        )
                    if len(analysis['security_concerns']) > 5:
                        console.print(f"  [dim]... and {len(analysis['security_concerns']) - 5} more[/dim]")
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


@cli.command()
@click.argument('encrypted-path', type=click.Path(exists=True))
@click.argument('new-kms-key')
@click.pass_context
def rotate_key(ctx, encrypted_path: str, new_kms_key: str):
    """Re-encrypt archive with a new KMS key"""
    sa = ctx.obj['archive']
    
    with console.status("[bold cyan]Rotating encryption key...") as status:
        try:
            new_path = sa.rotate_encryption_key(encrypted_path, new_kms_key)
            
            console.print(f"\n[green]✓[/green] Key rotation complete!")
            console.print(f"  New encrypted file: [blue]{new_path}[/blue]")
            console.print(f"  New KMS key: [cyan]{new_kms_key}[/cyan]")
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


@cli.command()
@click.option('--admin-role', required=True, help='Admin role ARN')
@click.option('--user-role', multiple=True, required=True, help='User role ARNs')
@click.option('--output', '-o', help='Output policy file')
@click.pass_context
def generate_policy(ctx, admin_role: str, user_role: tuple, output: Optional[str]):
    """Generate recommended KMS key policy for secure archive"""
    sa = ctx.obj['archive']
    
    try:
        policy = sa.create_kms_key_policy(admin_role, list(user_role))
        
        policy_json = json.dumps(policy, indent=2)
        
        if output:
            with open(output, 'w') as f:
                f.write(policy_json)
            console.print(f"[green]✓[/green] Policy saved to: [blue]{output}[/blue]")
        else:
            # Display policy
            console.print("\n[bold]Recommended KMS Key Policy[/bold]\n")
            syntax = Syntax(policy_json, "json", theme="monokai", line_numbers=True)
            console.print(syntax)
            
            console.print("\n[yellow]Instructions:[/yellow]")
            console.print("1. Create a new KMS key in AWS Console or CLI")
            console.print("2. Apply this policy to the key")
            console.print("3. Use the key ID/alias with this tool")
        
    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {str(e)}")
        sys.exit(1)


@cli.command()
@click.argument('archive-path', type=click.Path(exists=True))
@click.option('--encrypted', is_flag=True, help='Archive is KMS-encrypted')
@click.option('--json-output', is_flag=True, help='Output as JSON')
@click.pass_context
def analyze(ctx, archive_path: str, encrypted: bool, json_output: bool):
    """Analyze archive contents without extraction"""
    sa = ctx.obj['archive']
    
    with console.status("[bold cyan]Analyzing archive...") as status:
        try:
            analysis = sa.analyze_archive_contents(archive_path, encrypted)
            
            if json_output:
                click.echo(json.dumps(analysis, indent=2))
            else:
                # Display analysis results
                console.print("\n[bold]Archive Analysis[/bold]\n")
                
                # Summary panel
                summary_text = (
                    f"Total Files: [yellow]{analysis['total_files']:,}[/yellow]\n"
                    f"Total Size: [yellow]{analysis['summary']['total_size_mb']:.2f} MB[/yellow]\n"
                    f"File Types: [yellow]{analysis['summary']['file_type_count']}[/yellow]\n"
                    f"Security Risk: [{'red' if analysis['summary']['security_risk'] == 'high' else 'green'}]"
                    f"{analysis['summary']['security_risk']}[/]"
                )
                
                panel = Panel(summary_text, title="Summary", border_style="blue")
                console.print(panel)
                
                # File types
                if analysis['file_types']:
                    console.print("\n[bold]File Types Distribution[/bold]")
                    types_table = Table()
                    types_table.add_column("Extension", style="cyan")
                    types_table.add_column("Count", style="yellow")
                    types_table.add_column("Percentage")
                    
                    total_files = analysis['total_files']
                    for ext, count in sorted(analysis['file_types'].items(), 
                                            key=lambda x: x[1], reverse=True)[:10]:
                        percentage = (count / total_files) * 100
                        types_table.add_row(
                            ext or "(no extension)", 
                            str(count),
                            f"{percentage:.1f}%"
                        )
                    
                    console.print(types_table)
                
                # Security concerns
                if analysis['security_concerns']:
                    console.print(f"\n[bold red]Security Concerns ({len(analysis['security_concerns'])})[/bold red]")
                    
                    concerns_table = Table()
                    concerns_table.add_column("File", style="cyan")
                    concerns_table.add_column("Concern", style="yellow")
                    concerns_table.add_column("Severity")
                    
                    for concern in analysis['security_concerns'][:10]:
                        severity_color = 'red' if concern['severity'] == 'critical' else 'yellow'
                        concerns_table.add_row(
                            concern['file'],
                            concern['concern'],
                            f"[{severity_color}]{concern['severity']}[/{severity_color}]"
                        )
                    
                    console.print(concerns_table)
                    
                    if len(analysis['security_concerns']) > 10:
                        console.print(f"\n[dim]... and {len(analysis['security_concerns']) - 10} more concerns[/dim]")
                
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


@cli.command()
@click.argument('s3-key')
@click.pass_context
def stream_analyze(ctx, s3_key: str):
    """Analyze S3 archive without full download"""
    sa = ctx.obj['archive']
    
    with console.status("[bold cyan]Streaming and analyzing from S3...") as status:
        try:
            analysis = sa.stream_analyze_from_s3_kms(s3_key)
            
            # Display results
            console.print(f"\n[bold]Archive Analysis - [cyan]{s3_key}[/cyan][/bold]\n")
            
            summary = Table(title="Summary", show_header=False)
            summary.add_column("Metric", style="cyan")
            summary.add_column("Value", style="yellow")
            
            summary.add_row("Total Files", f"{analysis['total_files']:,}")
            summary.add_row("Total Size", f"{analysis['summary']['total_size_mb']:.2f} MB")
            summary.add_row("Security Risk", 
                f"[{'red' if analysis['summary']['security_risk'] == 'high' else 'green'}]"
                f"{analysis['summary']['security_risk']}[/]"
            )
            
            console.print(summary)
            
            if analysis['security_concerns']:
                console.print(f"\n[red]Found {len(analysis['security_concerns'])} security concerns[/red]")
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


if __name__ == '__main__':
    cli()