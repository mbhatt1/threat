"""
Repository Cloner Lambda Function
Clones Git repositories for security scanning
"""
import os
import json
import boto3
import tempfile
import shutil
import subprocess
from typing import Dict, Any
from datetime import datetime
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
s3_client = boto3.client('s3')
efs_client = boto3.client('efs')


def clone_repository(repository_url: str, branch: str = 'main', target_path: str = None) -> Dict[str, Any]:
    """
    Clone a Git repository to a temporary directory or EFS mount
    """
    if not target_path:
        target_path = tempfile.mkdtemp(prefix='repo_')
    
    try:
        # Configure git to handle large repositories
        subprocess.run(['git', 'config', '--global', 'http.postBuffer', '524288000'], check=True)
        subprocess.run(['git', 'config', '--global', 'core.compression', '0'], check=True)
        
        # Clone with depth limit for efficiency
        clone_command = [
            'git', 'clone',
            '--depth', '1',
            '--branch', branch,
            repository_url,
            target_path
        ]
        
        logger.info(f"Cloning repository: {repository_url} (branch: {branch})")
        result = subprocess.run(clone_command, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            raise Exception(f"Git clone failed: {result.stderr}")
        
        # Get repository metadata
        os.chdir(target_path)
        
        # Get current commit hash
        commit_result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            capture_output=True,
            text=True
        )
        commit_hash = commit_result.stdout.strip()
        
        # Get repository size
        size_result = subprocess.run(
            ['du', '-sh', target_path],
            capture_output=True,
            text=True
        )
        repo_size = size_result.stdout.split()[0] if size_result.stdout else 'unknown'
        
        # Count files
        file_count = sum(len(files) for _, _, files in os.walk(target_path))
        
        return {
            'success': True,
            'path': target_path,
            'commit_hash': commit_hash,
            'branch': branch,
            'repository_url': repository_url,
            'size': repo_size,
            'file_count': file_count,
            'cloned_at': datetime.utcnow().isoformat()
        }
        
    except subprocess.TimeoutExpired:
        logger.error(f"Repository clone timeout: {repository_url}")
        raise Exception("Repository clone operation timed out after 5 minutes")
    except Exception as e:
        logger.error(f"Failed to clone repository: {str(e)}")
        if target_path and os.path.exists(target_path):
            shutil.rmtree(target_path, ignore_errors=True)
        raise


def upload_to_s3(local_path: str, bucket: str, key_prefix: str) -> str:
    """
    Upload cloned repository to S3 for processing
    """
    import tarfile
    
    # Create tar archive
    tar_path = f"{local_path}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(local_path, arcname=os.path.basename(local_path))
    
    # Upload to S3
    s3_key = f"{key_prefix}/{os.path.basename(tar_path)}"
    s3_client.upload_file(tar_path, bucket, s3_key)
    
    # Cleanup
    os.remove(tar_path)
    
    return f"s3://{bucket}/{s3_key}"


def handler(event, context):
    """
    Lambda handler for repository cloning
    """
    try:
        # Extract parameters
        repository_url = event.get('repository_url')
        branch = event.get('branch', 'main')
        scan_id = event.get('scan_id')
        storage_type = event.get('storage_type', 'efs')  # 'efs' or 's3'
        
        if not repository_url:
            raise ValueError("repository_url is required")
        
        if not scan_id:
            raise ValueError("scan_id is required")
        
        # Determine storage location
        if storage_type == 'efs':
            # Use EFS mount point
            efs_mount = os.environ.get('EFS_MOUNT_PATH', '/mnt/efs')
            target_path = os.path.join(efs_mount, 'repositories', scan_id)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
        else:
            # Use temporary directory for S3 upload
            target_path = None
        
        # Clone repository
        clone_result = clone_repository(repository_url, branch, target_path)
        
        # Handle storage
        if storage_type == 's3':
            # Upload to S3
            results_bucket = os.environ.get('RESULTS_BUCKET')
            if not results_bucket:
                raise ValueError("RESULTS_BUCKET environment variable not set")
            
            s3_location = upload_to_s3(
                clone_result['path'],
                results_bucket,
                f"repositories/{scan_id}"
            )
            clone_result['s3_location'] = s3_location
            
            # Cleanup local files
            shutil.rmtree(clone_result['path'], ignore_errors=True)
            clone_result['path'] = s3_location
        
        logger.info(f"Successfully cloned repository: {repository_url}")
        
        return {
            'statusCode': 200,
            'body': json.dumps(clone_result),
            'repository': clone_result
        }
        
    except Exception as e:
        logger.error(f"Repository cloning failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'success': False
            })
        }


if __name__ == "__main__":
    # Test locally
    test_event = {
        'repository_url': 'https://github.com/example/repo.git',
        'branch': 'main',
        'scan_id': 'test-scan-123',
        'storage_type': 'efs'
    }
    result = handler(test_event, None)
    print(json.dumps(result, indent=2))