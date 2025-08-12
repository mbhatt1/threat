#!/usr/bin/env python3
"""
Secure Archive Module
Provides functionality to tar.gz, encrypt, upload, download, decrypt, and analyze directories
"""

import os
import io
import tarfile
import hashlib
import json
import logging
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, BinaryIO
from datetime import datetime
import base64

import boto3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

logger = logging.getLogger(__name__)


class SecureArchive:
    """Handles secure archiving, encryption, and analysis of directories"""
    
    def __init__(self, 
                 s3_bucket: Optional[str] = None,
                 kms_key_id: Optional[str] = None,
                 encryption_key: Optional[bytes] = None):
        """
        Initialize SecureArchive
        
        Args:
            s3_bucket: S3 bucket for storage
            kms_key_id: AWS KMS key ID for enhanced security
            encryption_key: Optional fixed encryption key (if not provided, generates random)
        """
        self.s3_bucket = s3_bucket or os.environ.get('ARCHIVE_S3_BUCKET')
        self.kms_key_id = kms_key_id
        self.s3_client = boto3.client('s3')
        self.kms_client = boto3.client('kms') if kms_key_id else None
        
        # Generate or use provided encryption key
        self._encryption_key = encryption_key or os.urandom(32)
        self._salt = os.urandom(16)
        
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def _encrypt_data(self, data: bytes, key: Optional[bytes] = None) -> Dict[str, bytes]:
        """
        Encrypt data using AES-256-GCM
        
        Returns dict with 'encrypted_data', 'nonce', 'tag'
        """
        key = key or self._encryption_key
        nonce = os.urandom(12)
        
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
    
    def _decrypt_data(self, encrypted_data: bytes, nonce: bytes, tag: bytes, 
                      key: Optional[bytes] = None) -> bytes:
        """Decrypt data using AES-256-GCM"""
        key = key or self._encryption_key
        
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
        default_excludes = ['.git', '__pycache__', '*.pyc', '.DS_Store', 'node_modules']
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
    
    def encrypt_archive(self, archive_path: str, output_path: Optional[str] = None,
                       password: Optional[str] = None) -> Dict[str, Any]:
        """
        Encrypt tar.gz archive
        
        Args:
            archive_path: Path to archive file
            output_path: Optional output path for encrypted file
            password: Optional password for key derivation
            
        Returns:
            Dict with encryption metadata
        """
        if not os.path.exists(archive_path):
            raise FileNotFoundError(f"Archive not found: {archive_path}")
        
        # Read archive data
        with open(archive_path, 'rb') as f:
            archive_data = f.read()
        
        # Derive key from password if provided
        if password:
            salt = os.urandom(16)
            key = self._derive_key(password, salt)
        else:
            salt = self._salt
            key = self._encryption_key
        
        # Encrypt data
        encrypted = self._encrypt_data(archive_data, key)
        
        # Prepare metadata
        metadata = {
            'original_name': os.path.basename(archive_path),
            'original_size': len(archive_data),
            'encrypted_size': len(encrypted['encrypted_data']),
            'salt': base64.b64encode(salt).decode(),
            'nonce': base64.b64encode(encrypted['nonce']).decode(),
            'tag': base64.b64encode(encrypted['tag']).decode(),
            'timestamp': datetime.utcnow().isoformat(),
            'checksum': hashlib.sha256(archive_data).hexdigest()
        }
        
        # Write encrypted file
        output_path = output_path or f"{archive_path}.enc"
        with open(output_path, 'wb') as f:
            # Write metadata length (4 bytes)
            metadata_json = json.dumps(metadata).encode()
            f.write(len(metadata_json).to_bytes(4, 'big'))
            # Write metadata
            f.write(metadata_json)
            # Write encrypted data
            f.write(encrypted['encrypted_data'])
        
        logger.info(f"Encrypted archive: {output_path}")
        return {
            'encrypted_path': output_path,
            'metadata': metadata
        }
    
    def upload_to_s3(self, file_path: str, s3_key: Optional[str] = None,
                    metadata: Optional[Dict[str, str]] = None) -> str:
        """
        Upload file to S3
        
        Args:
            file_path: Path to file to upload
            s3_key: S3 object key (default: filename)
            metadata: Optional metadata to attach
            
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
        
        # Add KMS encryption if configured
        if self.kms_key_id:
            upload_args['ServerSideEncryption'] = 'aws:kms'
            upload_args['SSEKMSKeyId'] = self.kms_key_id
        
        # Upload file
        with open(file_path, 'rb') as f:
            self.s3_client.put_object(Body=f, **upload_args)
        
        s3_uri = f"s3://{self.s3_bucket}/{s3_key}"
        logger.info(f"Uploaded to S3: {s3_uri}")
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
    
    def decrypt_archive(self, encrypted_path: str, output_path: Optional[str] = None,
                       password: Optional[str] = None) -> str:
        """
        Decrypt encrypted archive
        
        Args:
            encrypted_path: Path to encrypted file
            output_path: Optional output path
            password: Password if used during encryption
            
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
        
        # Derive key if password provided
        if password:
            salt = base64.b64decode(metadata['salt'])
            key = self._derive_key(password, salt)
        else:
            key = self._encryption_key
        
        # Decrypt data
        decrypted_data = self._decrypt_data(
            encrypted_data,
            base64.b64decode(metadata['nonce']),
            base64.b64decode(metadata['tag']),
            key
        )
        
        # Verify checksum
        checksum = hashlib.sha256(decrypted_data).hexdigest()
        if checksum != metadata['checksum']:
            raise ValueError("Checksum verification failed")
        
        # Write decrypted archive
        output_path = output_path or metadata['original_name']
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        logger.info(f"Decrypted archive: {output_path}")
        return output_path
    
    def analyze_archive_contents(self, archive_path: str, encrypted: bool = False,
                               password: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze archive contents without full extraction
        
        Args:
            archive_path: Path to archive (encrypted or not)
            encrypted: Whether archive is encrypted
            password: Password for encrypted archive
            
        Returns:
            Analysis results
        """
        # Handle encrypted archives
        if encrypted:
            with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as tmp:
                temp_path = tmp.name
            try:
                self.decrypt_archive(archive_path, temp_path, password)
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
            'security_concerns': []
        }
        
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
                        'size': member.size
                    })
                    
                    # Security checks
                    if member.name.endswith(('.pem', '.key', '.env', '.credentials')):
                        analysis['security_concerns'].append({
                            'file': member.name,
                            'concern': 'Potentially sensitive file'
                        })
                    
                    # Check for suspicious patterns
                    if '../' in member.name or member.name.startswith('/'):
                        analysis['security_concerns'].append({
                            'file': member.name,
                            'concern': 'Path traversal risk'
                        })
        
        # Sort largest files
        analysis['largest_files'].sort(key=lambda x: x['size'], reverse=True)
        analysis['largest_files'] = analysis['largest_files'][:10]  # Top 10
        
        return analysis
    
    def secure_backup_directory(self, directory_path: str, s3_key_prefix: str = None,
                              password: Optional[str] = None) -> Dict[str, Any]:
        """
        Complete secure backup workflow: archive, encrypt, upload
        
        Args:
            directory_path: Directory to backup
            s3_key_prefix: S3 key prefix for organization
            password: Optional password for encryption
            
        Returns:
            Backup metadata
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dir_name = os.path.basename(directory_path.rstrip('/'))
        
        # Create archive
        archive_path = self.archive_directory(directory_path)
        
        try:
            # Encrypt archive
            encrypted_result = self.encrypt_archive(archive_path, password=password)
            
            # Upload to S3
            s3_key = f"{s3_key_prefix or 'backups'}/{dir_name}_{timestamp}.tar.gz.enc"
            s3_uri = self.upload_to_s3(
                encrypted_result['encrypted_path'],
                s3_key,
                metadata={
                    'original_name': dir_name,
                    'timestamp': timestamp,
                    'encrypted': 'true'
                }
            )
            
            # Analyze contents
            analysis = self.analyze_archive_contents(archive_path, encrypted=False)
            
            return {
                'success': True,
                's3_uri': s3_uri,
                'archive_size': os.path.getsize(archive_path),
                'encrypted_size': os.path.getsize(encrypted_result['encrypted_path']),
                'analysis': analysis,
                'metadata': encrypted_result['metadata']
            }
            
        finally:
            # Cleanup temporary files
            if os.path.exists(archive_path):
                os.unlink(archive_path)
            if os.path.exists(encrypted_result['encrypted_path']):
                os.unlink(encrypted_result['encrypted_path'])
    
    def stream_analyze_from_s3(self, s3_key: str, password: Optional[str] = None) -> Dict[str, Any]:
        """
        Stream and analyze archive directly from S3 without full download
        
        Args:
            s3_key: S3 object key
            password: Password for encrypted archives
            
        Returns:
            Analysis results
        """
        # Stream from S3
        response = self.s3_client.get_object(Bucket=self.s3_bucket, Key=s3_key)
        
        # Check if encrypted
        is_encrypted = response.get('Metadata', {}).get('encrypted') == 'true'
        
        with tempfile.NamedTemporaryFile(suffix='.enc' if is_encrypted else '.tar.gz') as tmp:
            # Stream to temporary file
            for chunk in response['Body'].iter_chunks(chunk_size=1024*1024):
                tmp.write(chunk)
            tmp.flush()
            
            # Analyze
            return self.analyze_archive_contents(tmp.name, encrypted=is_encrypted, password=password)


class SecureArchiveCLI:
    """Command-line interface for SecureArchive"""
    
    @staticmethod
    def archive_and_encrypt(directory: str, password: str = None, s3_bucket: str = None):
        """CLI command to archive and encrypt a directory"""
        sa = SecureArchive(s3_bucket=s3_bucket)
        
        # Create archive
        archive_path = sa.archive_directory(directory)
        print(f"Created archive: {archive_path}")
        
        # Encrypt
        encrypted = sa.encrypt_archive(archive_path, password=password)
        print(f"Encrypted: {encrypted['encrypted_path']}")
        
        # Upload if S3 bucket provided
        if s3_bucket:
            s3_uri = sa.upload_to_s3(encrypted['encrypted_path'])
            print(f"Uploaded to: {s3_uri}")
        
        return encrypted
    
    @staticmethod
    def download_and_decrypt(s3_key: str, password: str = None, s3_bucket: str = None):
        """CLI command to download and decrypt from S3"""
        sa = SecureArchive(s3_bucket=s3_bucket)
        
        # Download
        encrypted_path = sa.download_from_s3(s3_key)
        print(f"Downloaded: {encrypted_path}")
        
        # Decrypt
        decrypted_path = sa.decrypt_archive(encrypted_path, password=password)
        print(f"Decrypted: {decrypted_path}")
        
        return decrypted_path


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python secure_archive.py archive <directory> [--password <pass>] [--s3-bucket <bucket>]")
        print("  python secure_archive.py decrypt <file> [--password <pass>]")
        print("  python secure_archive.py analyze <file> [--encrypted] [--password <pass>]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "archive":
        directory = sys.argv[2]
        password = None
        s3_bucket = None
        
        # Parse optional arguments
        for i in range(3, len(sys.argv)):
            if sys.argv[i] == "--password" and i + 1 < len(sys.argv):
                password = sys.argv[i + 1]
            elif sys.argv[i] == "--s3-bucket" and i + 1 < len(sys.argv):
                s3_bucket = sys.argv[i + 1]
        
        SecureArchiveCLI.archive_and_encrypt(directory, password, s3_bucket)
    
    elif command == "decrypt":
        file_path = sys.argv[2]
        password = None
        
        for i in range(3, len(sys.argv)):
            if sys.argv[i] == "--password" and i + 1 < len(sys.argv):
                password = sys.argv[i + 1]
        
        sa = SecureArchive()
        decrypted = sa.decrypt_archive(file_path, password=password)
        print(f"Decrypted to: {decrypted}")
    
    elif command == "analyze":
        file_path = sys.argv[2]
        encrypted = "--encrypted" in sys.argv
        password = None
        
        for i in range(3, len(sys.argv)):
            if sys.argv[i] == "--password" and i + 1 < len(sys.argv):
                password = sys.argv[i + 1]
        
        sa = SecureArchive()
        analysis = sa.analyze_archive_contents(file_path, encrypted=encrypted, password=password)
        print(json.dumps(analysis, indent=2))