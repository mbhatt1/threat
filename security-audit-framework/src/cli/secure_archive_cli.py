#!/usr/bin/env python3
"""
Secure Archive CLI Tool
Command-line interface for secure directory archiving with encryption and S3 storage
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

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
from shared.secure_archive import SecureArchive

console = Console()


@click.group()
@click.option('--s3-bucket', envvar='ARCHIVE_S3_BUCKET', help='S3 bucket for storage')
@click.option('--kms-key', envvar='KMS_KEY_ID', help='AWS KMS key ID')
@click.pass_context
def cli(ctx, s3_bucket: Optional[str], kms_key: Optional[str]):
    """Security Audit Framework - Secure Archive Tool"""
    ctx.ensure_object(dict)
    ctx.obj['archive'] = SecureArchive(s3_bucket=s3_bucket, kms_key_id=kms_key)


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
@click.option('--password', '-p', prompt=True, hide_input=True, help='Encryption password')
@click.pass_context
def encrypt(ctx, archive_path: str, output: Optional[str], password: str):
    """Encrypt a tar.gz archive"""
    sa = ctx.obj['archive']
    
    with console.status("[bold cyan]Encrypting archive...") as status:
        try:
            result = sa.encrypt_archive(archive_path, output, password)
            
            console.print(f"\n[green]✓[/green] Archive encrypted: [blue]{result['encrypted_path']}[/blue]")
            
            # Show encryption details
            table = Table(title="Encryption Details", show_header=False)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="yellow")
            
            metadata = result['metadata']
            table.add_row("Original Size", f"{metadata['original_size']:,} bytes")
            table.add_row("Encrypted Size", f"{metadata['encrypted_size']:,} bytes")
            table.add_row("Checksum", metadata['checksum'][:16] + "...")
            table.add_row("Timestamp", metadata['timestamp'])
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


@cli.command()
@click.argument('file-path', type=click.Path(exists=True))
@click.option('--s3-key', '-k', help='S3 object key')
@click.option('--metadata', '-m', multiple=True, help='Metadata key=value pairs')
@click.pass_context
def upload(ctx, file_path: str, s3_key: Optional[str], metadata: tuple):
    """Upload file to S3"""
    sa = ctx.obj['archive']
    
    # Parse metadata
    metadata_dict = {}
    for m in metadata:
        if '=' in m:
            key, value = m.split('=', 1)
            metadata_dict[key] = value
    
    with console.status("[bold cyan]Uploading to S3...") as status:
        try:
            s3_uri = sa.upload_to_s3(file_path, s3_key, metadata_dict)
            
            console.print(f"\n[green]✓[/green] Uploaded to: [blue]{s3_uri}[/blue]")
            
            # Show upload details
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            console.print(f"  Size: [yellow]{size_mb:.2f} MB[/yellow]")
            if metadata_dict:
                console.print(f"  Metadata: [dim]{metadata_dict}[/dim]")
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


@cli.command()
@click.argument('s3-key')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def download(ctx, s3_key: str, output: Optional[str]):
    """Download file from S3"""
    sa = ctx.obj['archive']
    
    with console.status("[bold cyan]Downloading from S3...") as status:
        try:
            local_path = sa.download_from_s3(s3_key, output)
            
            console.print(f"\n[green]✓[/green] Downloaded to: [blue]{local_path}[/blue]")
            
            # Show download details
            size_mb = os.path.getsize(local_path) / (1024 * 1024)
            console.print(f"  Size: [yellow]{size_mb:.2f} MB[/yellow]")
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


@cli.command()
@click.argument('encrypted-path', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output decrypted file path')
@click.option('--password', '-p', prompt=True, hide_input=True, help='Decryption password')
@click.pass_context
def decrypt(ctx, encrypted_path: str, output: Optional[str], password: str):
    """Decrypt an encrypted archive"""
    sa = ctx.obj['archive']
    
    with console.status("[bold cyan]Decrypting archive...") as status:
        try:
            decrypted_path = sa.decrypt_archive(encrypted_path, output, password)
            
            console.print(f"\n[green]✓[/green] Archive decrypted: [blue]{decrypted_path}[/blue]")
            
            # Show decrypted file info
            size_mb = os.path.getsize(decrypted_path) / (1024 * 1024)
            console.print(f"  Size: [yellow]{size_mb:.2f} MB[/yellow]")
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


@cli.command()
@click.argument('archive-path', type=click.Path(exists=True))
@click.option('--encrypted', is_flag=True, help='Archive is encrypted')
@click.option('--password', '-p', help='Password for encrypted archive')
@click.option('--json-output', is_flag=True, help='Output as JSON')
@click.pass_context
def analyze(ctx, archive_path: str, encrypted: bool, password: Optional[str], json_output: bool):
    """Analyze archive contents without extraction"""
    sa = ctx.obj['archive']
    
    if encrypted and not password:
        password = click.prompt('Password', hide_input=True)
    
    with console.status("[bold cyan]Analyzing archive...") as status:
        try:
            analysis = sa.analyze_archive_contents(archive_path, encrypted, password)
            
            if json_output:
                click.echo(json.dumps(analysis, indent=2))
            else:
                # Display analysis results
                console.print("\n[bold]Archive Analysis[/bold]\n")
                
                # Summary table
                summary = Table(title="Summary", show_header=False)
                summary.add_column("Metric", style="cyan")
                summary.add_column("Value", style="yellow")
                
                summary.add_row("Total Files", f"{analysis['total_files']:,}")
                summary.add_row("Total Size", f"{analysis['total_size']:,} bytes")
                summary.add_row("File Types", f"{len(analysis['file_types'])} types")
                
                console.print(summary)
                
                # File types table
                if analysis['file_types']:
                    console.print("\n[bold]File Types[/bold]")
                    types_table = Table()
                    types_table.add_column("Extension", style="cyan")
                    types_table.add_column("Count", style="yellow")
                    
                    for ext, count in sorted(analysis['file_types'].items(), 
                                            key=lambda x: x[1], reverse=True):
                        types_table.add_row(ext or "(no extension)", str(count))
                    
                    console.print(types_table)
                
                # Largest files
                if analysis['largest_files']:
                    console.print("\n[bold]Largest Files[/bold]")
                    files_table = Table()
                    files_table.add_column("File", style="cyan")
                    files_table.add_column("Size", style="yellow")
                    
                    for file_info in analysis['largest_files'][:5]:
                        size_mb = file_info['size'] / (1024 * 1024)
                        files_table.add_row(
                            file_info['name'],
                            f"{size_mb:.2f} MB"
                        )
                    
                    console.print(files_table)
                
                # Security concerns
                if analysis['security_concerns']:
                    console.print("\n[bold red]Security Concerns[/bold red]")
                    for concern in analysis['security_concerns']:
                        console.print(f"  [red]⚠[/red]  {concern['file']}: {concern['concern']}")
                
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


@cli.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--s3-prefix', '-p', help='S3 key prefix')
@click.option('--password', prompt=True, hide_input=True, help='Encryption password')
@click.option('--analyze', is_flag=True, help='Analyze contents')
@click.pass_context
def backup(ctx, directory: str, s3_prefix: Optional[str], password: str, analyze: bool):
    """Complete backup workflow: archive, encrypt, and upload"""
    sa = ctx.obj['archive']
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Performing secure backup...", total=3)
        
        try:
            result = sa.secure_backup_directory(directory, s3_prefix, password)
            progress.update(task, completed=3)
            
            console.print(f"\n[green]✓[/green] Backup completed successfully!")
            console.print(f"  S3 URI: [blue]{result['s3_uri']}[/blue]")
            console.print(f"  Archive size: [yellow]{result['archive_size']:,} bytes[/yellow]")
            console.print(f"  Encrypted size: [yellow]{result['encrypted_size']:,} bytes[/yellow]")
            
            if analyze and 'analysis' in result:
                console.print("\n[bold]Content Analysis[/bold]")
                analysis = result['analysis']
                console.print(f"  Files: [cyan]{analysis['total_files']}[/cyan]")
                console.print(f"  Total size: [cyan]{analysis['total_size']:,} bytes[/cyan]")
                
                if analysis['security_concerns']:
                    console.print(f"  [red]Security concerns: {len(analysis['security_concerns'])}[/red]")
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


@cli.command()
@click.argument('s3-key')
@click.option('--password', '-p', help='Password for encrypted archive')
@click.pass_context
def stream_analyze(ctx, s3_key: str, password: Optional[str]):
    """Analyze S3 archive without full download"""
    sa = ctx.obj['archive']
    
    if password is None:
        password = click.prompt('Password (if encrypted)', hide_input=True, default='')
    
    with console.status("[bold cyan]Streaming and analyzing from S3...") as status:
        try:
            analysis = sa.stream_analyze_from_s3(s3_key, password if password else None)
            
            # Display results (same as analyze command)
            console.print("\n[bold]Archive Analysis (from S3)[/bold]\n")
            
            summary = Table(title="Summary", show_header=False)
            summary.add_column("Metric", style="cyan")
            summary.add_column("Value", style="yellow")
            
            summary.add_row("Total Files", f"{analysis['total_files']:,}")
            summary.add_row("Total Size", f"{analysis['total_size']:,} bytes")
            
            console.print(summary)
            
        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {str(e)}")
            sys.exit(1)


if __name__ == '__main__':
    cli()