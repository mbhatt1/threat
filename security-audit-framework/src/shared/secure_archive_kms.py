#!/usr/bin/env python3
"""
Secure Archive Module with AWS KMS Integration
Provides functionality to tar.gz, encrypt (using KMS), upload, download, decrypt, and analyze directories
"""

import os
import io
import tarfile
import hashlib
import json
import logging
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, BinaryIO, Tuple
from datetime import datetime
import base64

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)


class SecureArchiveKMS:
    """Handles secure archiving with AWS KMS for key management"""
    
    def __init__(self, 
                 s3_bucket: Optional[str] = None,
                 kms_key_id: Optional[str] = None,
                 region: Optional[str] = None):
        """
        Initialize SecureArchiveKMS with AWS KMS integration
        
        Args:
            s3_bucket: S3 bucket for storage
            kms_key_id: AWS KMS key ID or alias (e.g., 'alias/my-key')
            region: AWS region
        """
        self.s3_bucket = s3_bucket or os.environ.get('ARCHIVE_S3_BUCKET')
        self.kms_key_id = kms_key_id or os.environ.get('KMS_KEY_ID')
        self.region = region or os.environ.get('AWS_REGION', 'us-east-1')
        
        if not self.kms_key_id:
            raise ValueError("KMS key ID is required. Set KMS_KEY_ID environment variable or pass kms_key_id parameter.")
        
        # Initialize AWS clients
        self.s3_client = boto3.client('s3', region_name=self.region)
        self.kms_client = boto3.client('kms', region_name=self.region)
        
        # Verify KMS key exists and is accessible
        self._verify_kms_key()
    
    def _verify_kms_key(self):
        """Verify KMS key exists and is accessible"""
        try:
            response = self.kms_client.describe_key(KeyId=self.kms_key_id)
            key_state = response['KeyMetadata']['KeyState']
            if key_state != 'Enabled':
                raise ValueError(f"KMS key {self.kms_key_id} is not enabled. Current state: {key_state}")
            logger.info(f"Using KMS key: {response['KeyMetadata']['Arn']}")
        except ClientError as e:
            raise ValueError(f"Cannot access KMS key {self.kms_key_id}: {str(e)}")
    
    def _generate_data_encryption_key(self) -> Tuple[bytes, bytes]:
        """
        Generate a data encryption key using KMS
        
        Returns:
            Tuple of (plaintext_key, encrypted_key)
        """
        try:
            response = self.kms_client.generate_data_key(
                KeyId=self.kms_key_id,
                KeySpec='AES_256'  # 256-bit AES key
            )
            return response['Plaintext'], response['CiphertextBlob']
        except ClientError as e:
            raise Exception(f"Failed to generate data encryption key: {str(e)}")
    
    def _decrypt_data_encryption_key(self, encrypted_key: bytes) -> bytes:
        """
        Decrypt a data encryption key using KMS
        
        Args:
            encrypted_key: The encrypted data key
            
        Returns:
            The plaintext data key
        """
        try:
            response = self.kms_client.decrypt(
                CiphertextBlob=encrypted_key,
                KeyId=self.kms_key_id  # Optional, but helps with key policies
            )
            return response['Plaintext']
        except ClientError as e:
            raise Exception(f"Failed to decrypt data encryption key: {str(e)}")
    
    def _encrypt_data(self, data: bytes, key: bytes) -> Dict[str, bytes]:
        """
        Encrypt data using AES-256-GCM
        
        Returns dict with 'encrypted_data', 'nonce', 'tag'
        """
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        return {
            'encrypted_data': encrypted_data,
            'nonce': nonce,
            'tag': encryptor.tag
        }
    
    def _decrypt_data(self, encrypted_data: bytes, nonce: bytes, tag: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data) + decryptor.finalize()
    
    def archive_directory(self, directory_path: str, output_path: Optional[str] = None,
                         exclude_patterns: Optional[List[str]] = None) -> str:
        """
        Create tar.gz archive of directory
        
        Args:
            directory_path: Path to directory to archive
            output_path: Optional output path for archive
            exclude_patterns: List of patterns to exclude
            
        Returns:
            Path to created archive
        """
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        # Default exclude patterns
        default_excludes = ['.git', '__pycache__', '*.pyc', '.DS_Store', 'node_modules', '.env.local']
        exclude_patterns = (exclude_patterns or []) + default_excludes
        
        # Generate output path if not provided
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"{os.path.basename(directory_path)}_{timestamp}.tar.gz"
        
        # Create tar.gz archive
        with tarfile.open(output_path, 'w:gz') as tar:
            for root, dirs, files in os.walk(directory_path):
                # Filter directories
                dirs[:] = [d for d in dirs if not any(
                    d == pattern or d.startswith(pattern.rstrip('*'))
                    for pattern in exclude_patterns
                )]
                
                # Add files
                for file in files:
                    if not any(file.endswith(pattern.lstrip('*')) 
                              for pattern in exclude_patterns):
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, directory_path)
                        tar.add(file_path, arcname=arcname)
        
        logger.info(f"Created archive: {output_path}")
        return output_path
    
    def encrypt_archive_kms(self, archive_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Encrypt tar.gz archive using KMS-managed keys
        
        Args:
            archive_path: Path to archive file
            output_path: Optional output path for encrypted file
            
        Returns:
            Dict with encryption metadata
        """
        if not os.path.exists(archive_path):
            raise FileNotFoundError(f"Archive not found: {archive_path}")
        
        # Read archive data
        with open(archive_path, 'rb') as f:
            archive_data = f.read()
        
        # Generate data encryption key using KMS
        plaintext_key, encrypted_key = self._generate_data_encryption_key()
        
        try:
            # Encrypt data with the plaintext key
            encrypted = self._encrypt_data(archive_data, plaintext_key)
            
            # Prepare metadata
            metadata = {
                'original_name': os.path.basename(archive_path),
                'original_size': len(archive_data),
                'encrypted_size': len(encrypted['encrypted_data']),
                'kms_key_id': self.kms_key_id,
                'encryption_context': {
                    'purpose': 'secure-archive',
                    'timestamp': datetime.utcnow().isoformat()
                },
                'encrypted_dek': base64.b64encode(encrypted_key).decode(),
                'nonce': base64.b64encode(encrypted['nonce']).decode(),
                'tag': base64.b64encode(encrypted['tag']).decode(),
                'timestamp': datetime.utcnow().isoformat(),
                'checksum': hashlib.sha256(archive_data).hexdigest(),
                'encryption_algorithm': 'AES-256-GCM',
                'kms_algorithm': 'AWS_KMS'
            }
            
            # Write encrypted file
            output_path = output_path or f"{archive_path}.kms.enc"
            with open(output_path, 'wb') as f:
                # Write metadata length (4 bytes)
                metadata_json = json.dumps(metadata).encode()
                f.write(len(metadata_json).to_bytes(4, 'big'))
                # Write metadata
                f.write(metadata_json)
                # Write encrypted data
                f.write(encrypted['encrypted_data'])
            
            logger.info(f"Encrypted archive with KMS: {output_path}")
            return {
                'encrypted_path': output_path,
                'metadata': metadata,
                'kms_key_arn': self._get_key_arn()
            }
            
        finally:
            # Clear the plaintext key from memory
            plaintext_key = None
    
    def _get_key_arn(self) -> str:
        """Get the ARN of the KMS key"""
        try:
            response = self.kms_client.describe_key(KeyId=self.kms_key_id)
            return response['KeyMetadata']['Arn']
        except:
            return self.kms_key_id
    
    def upload_to_s3(self, file_path: str, s3_key: Optional[str] = None,
                    metadata: Optional[Dict[str, str]] = None,
                    server_side_encryption: bool = True) -> str:
        """
        Upload file to S3 with KMS encryption
        
        Args:
            file_path: Path to file to upload
            s3_key: S3 object key (default: filename)
            metadata: Optional metadata to attach
            server_side_encryption: Use S3 server-side encryption with KMS
            
        Returns:
            S3 URI
        """
        if not self.s3_bucket:
            raise ValueError("S3 bucket not configured")
        
        s3_key = s3_key or os.path.basename(file_path)
        
        # Prepare upload arguments
        upload_args = {
            'Bucket': self.s3_bucket,
            'Key': s3_key
        }
        
        if metadata:
            upload_args['Metadata'] = metadata
        
        # Add KMS server-side encryption
        if server_side_encryption:
            upload_args['ServerSideEncryption'] = 'aws:kms'
            upload_args['SSEKMSKeyId'] = self.kms_key_id
        
        # Upload file
        with open(file_path, 'rb') as f:
            self.s3_client.put_object(Body=f, **upload_args)
        
        s3_uri = f"s3://{self.s3_bucket}/{s3_key}"
        logger.info(f"Uploaded to S3 with KMS encryption: {s3_uri}")
        return s3_uri
    
    def download_from_s3(self, s3_key: str, output_path: Optional[str] = None) -> str:
        """
        Download file from S3
        
        Args:
            s3_key: S3 object key
            output_path: Local output path
            
        Returns:
            Local file path
        """
        if not self.s3_bucket:
            raise ValueError("S3 bucket not configured")
        
        output_path = output_path or os.path.basename(s3_key)
        
        self.s3_client.download_file(self.s3_bucket, s3_key, output_path)
        logger.info(f"Downloaded from S3: {output_path}")
        return output_path
    
    def decrypt_archive_kms(self, encrypted_path: str, output_path: Optional[str] = None) -> str:
        """
        Decrypt KMS-encrypted archive
        
        Args:
            encrypted_path: Path to encrypted file
            output_path: Optional output path
            
        Returns:
            Path to decrypted archive
        """
        with open(encrypted_path, 'rb') as f:
            # Read metadata length
            metadata_length = int.from_bytes(f.read(4), 'big')
            # Read metadata
            metadata_json = f.read(metadata_length)
            metadata = json.loads(metadata_json)
            # Read encrypted data
            encrypted_data = f.read()
        
        # Decrypt the data encryption key using KMS
        encrypted_key = base64.b64decode(metadata['encrypted_dek'])
        plaintext_key = self._decrypt_data_encryption_key(encrypted_key)
        
        try:
            # Decrypt data
            decrypted_data = self._decrypt_data(
                encrypted_data,
                base64.b64decode(metadata['nonce']),
                base64.b64decode(metadata['tag']),
                plaintext_key
            )
            
            # Verify checksum
            checksum = hashlib.sha256(decrypted_data).hexdigest()
            if checksum != metadata['checksum']:
                raise ValueError("Checksum verification failed - data may be corrupted")
            
            # Write decrypted archive
            output_path = output_path or metadata['original_name']
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            logger.info(f"Decrypted archive: {output_path}")
            return output_path
            
        finally:
            # Clear the plaintext key from memory
            plaintext_key = None
    
    def analyze_archive_contents(self, archive_path: str, encrypted: bool = False) -> Dict[str, Any]:
        """
        Analyze archive contents without full extraction
        
        Args:
            archive_path: Path to archive (encrypted or not)
            encrypted: Whether archive is encrypted
            
        Returns:
            Analysis results
        """
        # Handle encrypted archives
        if encrypted:
            with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as tmp:
                temp_path = tmp.name
            try:
                self.decrypt_archive_kms(archive_path, temp_path)
                return self._analyze_tar_contents(temp_path)
            finally:
                os.unlink(temp_path)
        else:
            return self._analyze_tar_contents(archive_path)
    
    def _analyze_tar_contents(self, tar_path: str) -> Dict[str, Any]:
        """Analyze tar.gz contents"""
        analysis = {
            'total_files': 0,
            'total_size': 0,
            'file_types': {},
            'largest_files': [],
            'directory_structure': {},
            'security_concerns': [],
            'sensitive_patterns': []
        }
        
        # Patterns for sensitive files
        sensitive_patterns = [
            (r'\.pem$', 'Private key file'),
            (r'\.key$', 'Key file'),
            (r'\.env$', 'Environment configuration'),
            (r'\.credentials$', 'Credentials file'),
            (r'id_rsa', 'SSH private key'),
            (r'\.p12$', 'Certificate file'),
            (r'\.pfx$', 'Certificate file'),
            (r'password|passwd', 'Possible password file'),
            (r'secret', 'Possible secrets file'),
            (r'\.aws/credentials', 'AWS credentials'),
            (r'\.kube/config', 'Kubernetes config')
        ]
        
        import re
        
        with tarfile.open(tar_path, 'r:gz') as tar:
            for member in tar.getmembers():
                if member.isfile():
                    analysis['total_files'] += 1
                    analysis['total_size'] += member.size
                    
                    # Track file types
                    ext = os.path.splitext(member.name)[1].lower()
                    analysis['file_types'][ext] = analysis['file_types'].get(ext, 0) + 1
                    
                    # Track largest files
                    analysis['largest_files'].append({
                        'name': member.name,
                        'size': member.size,
                        'size_mb': round(member.size / (1024 * 1024), 2)
                    })
                    
                    # Check for sensitive patterns
                    for pattern, description in sensitive_patterns:
                        if re.search(pattern, member.name, re.IGNORECASE):
                            analysis['security_concerns'].append({
                                'file': member.name,
                                'concern': description,
                                'severity': 'high'
                            })
                    
                    # Check for path traversal
                    if '../' in member.name or member.name.startswith('/'):
                        analysis['security_concerns'].append({
                            'file': member.name,
                            'concern': 'Path traversal risk',
                            'severity': 'critical'
                        })
        
        # Sort largest files
        analysis['largest_files'].sort(key=lambda x: x['size'], reverse=True)
        analysis['largest_files'] = analysis['largest_files'][:10]  # Top 10
        
        # Add summary
        analysis['summary'] = {
            'total_size_mb': round(analysis['total_size'] / (1024 * 1024), 2),
            'security_risk': 'high' if analysis['security_concerns'] else 'low',
            'file_type_count': len(analysis['file_types'])
        }
        
        return analysis
    
    def secure_backup_directory_kms(self, directory_path: str, s3_key_prefix: str = None) -> Dict[str, Any]:
        """
        Complete secure backup workflow with KMS: archive, encrypt, upload
        
        Args:
            directory_path: Directory to backup
            s3_key_prefix: S3 key prefix for organization
            
        Returns:
            Backup metadata
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dir_name = os.path.basename(directory_path.rstrip('/'))
        
        # Create archive
        archive_path = self.archive_directory(directory_path)
        
        try:
            # Encrypt archive with KMS
            encrypted_result = self.encrypt_archive_kms(archive_path)
            
            # Upload to S3 with KMS encryption
            s3_key = f"{s3_key_prefix or 'backups'}/{dir_name}_{timestamp}.tar.gz.kms.enc"
            s3_uri = self.upload_to_s3(
                encrypted_result['encrypted_path'],
                s3_key,
                metadata={
                    'original_name': dir_name,
                    'timestamp': timestamp,
                    'encrypted': 'true',
                    'kms_encrypted': 'true',
                    'kms_key_id': self.kms_key_id
                }
            )
            
            # Analyze contents
            analysis = self.analyze_archive_contents(archive_path, encrypted=False)
            
            # Log to CloudTrail via KMS
            logger.info(f"Backup completed with KMS encryption. Key: {self.kms_key_id}")
            
            return {
                'success': True,
                's3_uri': s3_uri,
                'archive_size': os.path.getsize(archive_path),
                'encrypted_size': os.path.getsize(encrypted_result['encrypted_path']),
                'analysis': analysis,
                'metadata': encrypted_result['metadata'],
                'kms_key_arn': encrypted_result['kms_key_arn'],
                'encryption_type': 'KMS-managed'
            }
            
        finally:
            # Cleanup temporary files
            if os.path.exists(archive_path):
                os.unlink(archive_path)
            if os.path.exists(encrypted_result['encrypted_path']):
                os.unlink(encrypted_result['encrypted_path'])
    
    def rotate_encryption_key(self, encrypted_path: str, new_kms_key_id: str) -> str:
        """
        Re-encrypt archive with a new KMS key (for key rotation)
        
        Args:
            encrypted_path: Path to encrypted archive
            new_kms_key_id: New KMS key ID to use
            
        Returns:
            Path to re-encrypted file
        """
        # Decrypt with current key
        temp_decrypted = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as tmp:
                temp_decrypted = tmp.name
            
            self.decrypt_archive_kms(encrypted_path, temp_decrypted)
            
            # Switch to new key
            old_key = self.kms_key_id
            self.kms_key_id = new_kms_key_id
            self._verify_kms_key()
            
            # Re-encrypt with new key
            new_encrypted_path = encrypted_path.replace('.enc', '.rotated.enc')
            result = self.encrypt_archive_kms(temp_decrypted, new_encrypted_path)
            
            logger.info(f"Successfully rotated encryption from {old_key} to {new_kms_key_id}")
            return result['encrypted_path']
            
        finally:
            if temp_decrypted and os.path.exists(temp_decrypted):
                os.unlink(temp_decrypted)
    
    def create_kms_key_policy(self, admin_role_arn: str, user_role_arns: List[str]) -> Dict[str, Any]:
        """
        Create a recommended KMS key policy for secure archive operations
        
        Args:
            admin_role_arn: ARN of admin role
            user_role_arns: List of user role ARNs
            
        Returns:
            KMS key policy document
        """
        account_id = admin_role_arn.split(':')[4]
        
        policy = {
            "Version": "2012-10-17",
            "Id": "secure-archive-key-policy",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{account_id}:root"
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Sid": "Allow administrators to manage key",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": admin_role_arn
                    },
                    "Action": [
                        "kms:Create*",
                        "kms:Describe*",
                        "kms:Enable*",
                        "kms:List*",
                        "kms:Put*",
                        "kms:Update*",
                        "kms:Revoke*",
                        "kms:Disable*",
                        "kms:Get*",
                        "kms:Delete*",
                        "kms:ScheduleKeyDeletion",
                        "kms:CancelKeyDeletion"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "Allow use of the key for encryption/decryption",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": user_role_arns
                    },
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:CreateGrant",
                        "kms:DescribeKey"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:ViaService": [
                                f"s3.{self.region}.amazonaws.com"
                            ]
                        }
                    }
                },
                {
                    "Sid": "Allow attachment of persistent resources",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": user_role_arns
                    },
                    "Action": [
                        "kms:CreateGrant",
                        "kms:ListGrants",
                        "kms:RevokeGrant"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "Bool": {
                            "kms:GrantIsForAWSResource": "true"
                        }
                    }
                }
            ]
        }
        
        return policy
    
    def stream_analyze_from_s3_kms(self, s3_key: str) -> Dict[str, Any]:
        """
        Stream and analyze KMS-encrypted archive directly from S3
        
        Args:
            s3_key: S3 object key
            
        Returns:
            Analysis results
        """
        # Stream from S3
        response = self.s3_client.get_object(Bucket=self.s3_bucket, Key=s3_key)
        
        # Check if KMS encrypted
        is_kms_encrypted = response.get('Metadata', {}).get('kms_encrypted') == 'true'
        
        if not is_kms_encrypted:
            raise ValueError("File is not KMS encrypted")
        
        with tempfile.NamedTemporaryFile(suffix='.kms.enc') as tmp:
            # Stream to temporary file
            for chunk in response['Body'].iter_chunks(chunk_size=1024*1024):
                tmp.write(chunk)
            tmp.flush()
            
            # Analyze
            return self.analyze_archive_contents(tmp.name, encrypted=True)


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python secure_archive_kms.py archive <directory> [--kms-key <key-id>]")
        print("  python secure_archive_kms.py decrypt <file> [--kms-key <key-id>]")
        print("  python secure_archive_kms.py analyze <file> [--encrypted]")
        print("  python secure_archive_kms.py backup <directory> [--s3-prefix <prefix>]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    # Get KMS key from args or environment
    kms_key = None
    for i in range(len(sys.argv)):
        if sys.argv[i] == "--kms-key" and i + 1 < len(sys.argv):
            kms_key = sys.argv[i + 1]
    
    if command == "archive":
        directory = sys.argv[2]
        sa = SecureArchiveKMS(kms_key_id=kms_key)
        
        # Create and encrypt archive
        archive_path = sa.archive_directory(directory)
        encrypted = sa.encrypt_archive_kms(archive_path)
        print(f"Encrypted with KMS: {encrypted['encrypted_path']}")
        print(f"KMS Key: {encrypted['kms_key_arn']}")
    
    elif command == "decrypt":
        file_path = sys.argv[2]
        sa = SecureArchiveKMS(kms_key_id=kms_key)
        decrypted = sa.decrypt_archive_kms(file_path)
        print(f"Decrypted to: {decrypted}")
    
    elif command == "analyze":
        file_path = sys.argv[2]
        encrypted = "--encrypted" in sys.argv
        sa = SecureArchiveKMS(kms_key_id=kms_key)
        analysis = sa.analyze_archive_contents(file_path, encrypted=encrypted)
        print(json.dumps(analysis, indent=2))
    
    elif command == "backup":
        directory = sys.argv[2]
        s3_prefix = None
        
        for i in range(len(sys.argv)):
            if sys.argv[i] == "--s3-prefix" and i + 1 < len(sys.argv):
                s3_prefix = sys.argv[i + 1]
        
        sa = SecureArchiveKMS(kms_key_id=kms_key)
        result = sa.secure_backup_directory_kms(directory, s3_prefix)
        print(f"Backup complete: {result['s3_uri']}")
        print(f"Encrypted with KMS key: {result['kms_key_arn']}")