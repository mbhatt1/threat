"""
Immediate Remediation Lambda - Automatic response to critical security findings
"""
import os
import json
import boto3
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
import hashlib
import secrets
import string

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
secrets_manager = boto3.client('secretsmanager')
ssm_client = boto3.client('ssm')
iam_client = boto3.client('iam')
sns_client = boto3.client('sns')
dynamodb = boto3.resource('dynamodb')
organizations_client = boto3.client('organizations')

# Environment variables
ALERT_TOPIC_ARN = os.environ.get('ALERT_TOPIC_ARN')
REMEDIATION_TABLE = os.environ.get('REMEDIATION_TABLE', 'SecurityRemediations')
APPROVED_ACTIONS = os.environ.get('APPROVED_ACTIONS', 'rotate_secret,disable_key,tag_resource').split(',')
AUTO_REMEDIATE = os.environ.get('AUTO_REMEDIATE', 'false').lower() == 'true'


class RemediationHandler:
    """Handles automatic remediation of critical security findings"""
    
    def __init__(self):
        self.remediation_table = dynamodb.Table(REMEDIATION_TABLE)
        self.alert_topic = ALERT_TOPIC_ARN
        
    def handle_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process remediation request
        Event sources:
        1. Direct invocation from Secrets agent
        2. SNS from critical findings
        3. Manual invocation via API
        """
        try:
            # Extract finding details
            finding_type = event.get('finding_type')
            severity = event.get('severity', 'unknown')
            scan_id = event.get('scan_id')
            findings = event.get('findings', [])
            
            if severity != 'critical' and not event.get('force_remediation'):
                return {
                    'statusCode': 200,
                    'message': 'Only critical findings trigger automatic remediation'
                }
            
            # Process each finding
            remediations = []
            for finding in findings:
                remediation = self._process_finding(finding, scan_id)
                if remediation:
                    remediations.append(remediation)
            
            # Store remediation record
            if remediations:
                self._store_remediation_record(scan_id, remediations)
                
                # Send notification
                self._send_remediation_notification(scan_id, remediations)
            
            return {
                'statusCode': 200,
                'scan_id': scan_id,
                'remediations_performed': len(remediations),
                'remediations': remediations
            }
            
        except Exception as e:
            logger.error(f"Remediation failed: {str(e)}", exc_info=True)
            return {
                'statusCode': 500,
                'error': str(e)
            }
    
    def _process_finding(self, finding: Dict[str, Any], scan_id: str) -> Optional[Dict[str, Any]]:
        """Process individual finding and perform remediation if appropriate"""
        finding_type = finding.get('type', '').lower()
        
        # Route to appropriate remediation handler
        if 'secret' in finding_type or 'credential' in finding_type:
            return self._remediate_exposed_secret(finding, scan_id)
        elif 'access_key' in finding_type or 'api_key' in finding_type:
            return self._remediate_exposed_access_key(finding, scan_id)
        elif 'private_key' in finding_type or 'ssh_key' in finding_type:
            return self._remediate_exposed_private_key(finding, scan_id)
        elif 'database' in finding_type and 'password' in finding_type:
            return self._remediate_database_credential(finding, scan_id)
        else:
            logger.warning(f"No remediation handler for finding type: {finding_type}")
            return None
    
    def _remediate_exposed_secret(self, finding: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
        """Remediate exposed secrets in AWS Secrets Manager"""
        try:
            secret_identifier = self._extract_secret_identifier(finding)
            
            if not secret_identifier:
                return {
                    'status': 'skipped',
                    'reason': 'Could not identify secret in Secrets Manager',
                    'finding_id': finding.get('finding_id')
                }
            
            # Check if auto-remediation is enabled
            if not AUTO_REMEDIATE and 'rotate_secret' in APPROVED_ACTIONS:
                # Create rotation schedule but don't execute
                self._schedule_secret_rotation(secret_identifier)
                return {
                    'status': 'scheduled',
                    'action': 'rotate_secret',
                    'secret_id': secret_identifier,
                    'scheduled_at': datetime.utcnow().isoformat()
                }
            
            # Perform immediate rotation
            rotation_result = self._rotate_secret(secret_identifier)
            
            # Tag the secret as compromised
            self._tag_compromised_resource(
                f"arn:aws:secretsmanager:{os.environ['AWS_REGION']}:{self._get_account_id()}:secret:{secret_identifier}",
                scan_id
            )
            
            return {
                'status': 'success',
                'action': 'rotate_secret',
                'secret_id': secret_identifier,
                'new_version_id': rotation_result.get('VersionId'),
                'remediated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to remediate secret: {e}")
            return {
                'status': 'failed',
                'action': 'rotate_secret',
                'error': str(e),
                'finding_id': finding.get('finding_id')
            }
    
    def _remediate_exposed_access_key(self, finding: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
        """Remediate exposed IAM access keys"""
        try:
            access_key_id = self._extract_access_key_id(finding)
            
            if not access_key_id:
                return {
                    'status': 'skipped',
                    'reason': 'Could not identify IAM access key',
                    'finding_id': finding.get('finding_id')
                }
            
            # Get key metadata
            key_info = self._get_access_key_info(access_key_id)
            if not key_info:
                return {
                    'status': 'failed',
                    'reason': 'Access key not found',
                    'access_key_id': access_key_id
                }
            
            user_name = key_info['UserName']
            
            if not AUTO_REMEDIATE and 'disable_key' in APPROVED_ACTIONS:
                # Schedule for review
                return {
                    'status': 'requires_approval',
                    'action': 'disable_access_key',
                    'access_key_id': access_key_id,
                    'user_name': user_name
                }
            
            # Disable the access key
            iam_client.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )
            
            # Create new access key if safe to do so
            new_key = None
            if self._is_safe_to_rotate_key(user_name):
                response = iam_client.create_access_key(UserName=user_name)
                new_key = response['AccessKey']['AccessKeyId']
                
                # Store new key in Secrets Manager
                self._store_new_access_key(user_name, response['AccessKey'])
            
            # Tag user as having compromised credentials
            iam_client.tag_user(
                UserName=user_name,
                Tags=[
                    {'Key': 'CompromisedCredential', 'Value': 'true'},
                    {'Key': 'RemediationScanId', 'Value': scan_id},
                    {'Key': 'RemediatedAt', 'Value': datetime.utcnow().isoformat()}
                ]
            )
            
            return {
                'status': 'success',
                'action': 'disable_access_key',
                'access_key_id': access_key_id,
                'user_name': user_name,
                'new_access_key_id': new_key,
                'remediated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to remediate access key: {e}")
            return {
                'status': 'failed',
                'action': 'disable_access_key',
                'error': str(e),
                'finding_id': finding.get('finding_id')
            }
    
    def _remediate_exposed_private_key(self, finding: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
        """Remediate exposed SSH/private keys"""
        try:
            key_info = self._extract_key_info(finding)
            
            # For SSH keys in EC2
            if key_info.get('type') == 'ec2_key_pair':
                key_name = key_info.get('key_name')
                if key_name:
                    # Delete the key pair
                    ec2_client = boto3.client('ec2')
                    ec2_client.delete_key_pair(KeyName=key_name)
                    
                    return {
                        'status': 'success',
                        'action': 'delete_key_pair',
                        'key_name': key_name,
                        'remediated_at': datetime.utcnow().isoformat()
                    }
            
            # For keys stored in Systems Manager Parameter Store
            elif key_info.get('type') == 'parameter_store':
                param_name = key_info.get('parameter_name')
                if param_name:
                    # Delete the parameter
                    ssm_client.delete_parameter(Name=param_name)
                    
                    # Create new key if needed
                    if key_info.get('generate_new'):
                        new_key = self._generate_ssh_key_pair()
                        ssm_client.put_parameter(
                            Name=f"{param_name}-rotated",
                            Value=json.dumps(new_key),
                            Type='SecureString',
                            Tags=[
                                {'Key': 'RotatedFrom', 'Value': param_name},
                                {'Key': 'RotatedAt', 'Value': datetime.utcnow().isoformat()}
                            ]
                        )
                    
                    return {
                        'status': 'success',
                        'action': 'rotate_private_key',
                        'parameter_name': param_name,
                        'new_parameter_name': f"{param_name}-rotated" if key_info.get('generate_new') else None,
                        'remediated_at': datetime.utcnow().isoformat()
                    }
            
            return {
                'status': 'skipped',
                'reason': 'Could not determine key type or location',
                'finding_id': finding.get('finding_id')
            }
            
        except Exception as e:
            logger.error(f"Failed to remediate private key: {e}")
            return {
                'status': 'failed',
                'action': 'remediate_private_key',
                'error': str(e),
                'finding_id': finding.get('finding_id')
            }
    
    def _remediate_database_credential(self, finding: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
        """Remediate exposed database credentials"""
        try:
            db_info = self._extract_database_info(finding)
            
            if not db_info:
                return {
                    'status': 'skipped',
                    'reason': 'Could not identify database connection',
                    'finding_id': finding.get('finding_id')
                }
            
            # For RDS databases
            if db_info.get('type') == 'rds':
                db_instance_id = db_info.get('instance_id')
                master_username = db_info.get('username')
                
                if db_instance_id and master_username:
                    # Generate new password
                    new_password = self._generate_secure_password()
                    
                    # Update RDS master password
                    rds_client = boto3.client('rds')
                    rds_client.modify_db_instance(
                        DBInstanceIdentifier=db_instance_id,
                        MasterUserPassword=new_password,
                        ApplyImmediately=True
                    )
                    
                    # Store new password in Secrets Manager
                    secret_name = f"rds/{db_instance_id}/master"
                    self._store_database_credential(secret_name, master_username, new_password)
                    
                    return {
                        'status': 'success',
                        'action': 'rotate_database_password',
                        'database_id': db_instance_id,
                        'secret_name': secret_name,
                        'remediated_at': datetime.utcnow().isoformat()
                    }
            
            # For credentials in Secrets Manager
            elif db_info.get('type') == 'secrets_manager':
                return self._remediate_exposed_secret(finding, scan_id)
            
            return {
                'status': 'skipped',
                'reason': 'Unsupported database type',
                'finding_id': finding.get('finding_id')
            }
            
        except Exception as e:
            logger.error(f"Failed to remediate database credential: {e}")
            return {
                'status': 'failed',
                'action': 'remediate_database_credential',
                'error': str(e),
                'finding_id': finding.get('finding_id')
            }
    
    def _rotate_secret(self, secret_id: str) -> Dict[str, Any]:
        """Rotate a secret in AWS Secrets Manager"""
        # Check if rotation is already configured
        try:
            response = secrets_manager.describe_secret(SecretId=secret_id)
            
            if response.get('RotationEnabled'):
                # Trigger rotation
                return secrets_manager.rotate_secret(
                    SecretId=secret_id,
                    RotationLambdaARN=response['RotationLambdaARN']
                )
            else:
                # Manual rotation - update secret value
                new_secret_value = self._generate_new_secret_value(response)
                return secrets_manager.update_secret(
                    SecretId=secret_id,
                    SecretString=json.dumps(new_secret_value)
                )
                
        except Exception as e:
            logger.error(f"Failed to rotate secret {secret_id}: {e}")
            raise
    
    def _generate_new_secret_value(self, secret_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate new secret value based on secret type"""
        # Get current secret to understand structure
        try:
            current = secrets_manager.get_secret_value(SecretId=secret_metadata['ARN'])
            secret_dict = json.loads(current['SecretString'])
            
            # Generate new values for each field
            new_secret = {}
            for key, value in secret_dict.items():
                if 'password' in key.lower():
                    new_secret[key] = self._generate_secure_password()
                elif 'key' in key.lower() or 'token' in key.lower():
                    new_secret[key] = self._generate_api_key()
                else:
                    # Keep non-sensitive values
                    new_secret[key] = value
            
            return new_secret
            
        except Exception as e:
            logger.error(f"Failed to generate new secret value: {e}")
            # Fallback to simple password
            return {'password': self._generate_secure_password()}
    
    def _generate_secure_password(self, length: int = 32) -> str:
        """Generate a secure password"""
        alphabet = string.ascii_letters + string.digits + string.punctuation
        # Remove problematic characters
        alphabet = alphabet.replace('"', '').replace("'", '').replace('\\', '')
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def _generate_api_key(self, length: int = 32) -> str:
        """Generate a secure API key"""
        return secrets.token_urlsafe(length)
    
    def _generate_ssh_key_pair(self) -> Dict[str, str]:
        """Generate SSH key pair"""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        # Get private key in PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Get public key in OpenSSH format
        public_key = private_key.public_key()
        public_ssh = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        return {
            'private_key': private_pem,
            'public_key': public_ssh
        }
    
    def _store_remediation_record(self, scan_id: str, remediations: List[Dict[str, Any]]) -> None:
        """Store remediation record in DynamoDB"""
        try:
            self.remediation_table.put_item(
                Item={
                    'remediation_id': f"{scan_id}-{datetime.utcnow().timestamp()}",
                    'scan_id': scan_id,
                    'timestamp': datetime.utcnow().isoformat(),
                    'remediations': remediations,
                    'total_remediations': len(remediations),
                    'successful_remediations': len([r for r in remediations if r.get('status') == 'success']),
                    'ttl': int(datetime.utcnow().timestamp()) + 2592000  # 30 days
                }
            )
        except Exception as e:
            logger.error(f"Failed to store remediation record: {e}")
    
    def _send_remediation_notification(self, scan_id: str, remediations: List[Dict[str, Any]]) -> None:
        """Send notification about remediation actions"""
        if not self.alert_topic:
            return
        
        try:
            successful = [r for r in remediations if r.get('status') == 'success']
            failed = [r for r in remediations if r.get('status') == 'failed']
            
            message = f"""
Security Remediation Report
Scan ID: {scan_id}
Time: {datetime.utcnow().isoformat()}

Total Remediations: {len(remediations)}
Successful: {len(successful)}
Failed: {len(failed)}

Actions Performed:
"""
            for r in successful:
                message += f"- {r.get('action', 'unknown')}: {r.get('status')}\n"
            
            if failed:
                message += "\nFailed Actions:\n"
                for r in failed:
                    message += f"- {r.get('action', 'unknown')}: {r.get('error', 'unknown error')}\n"
            
            sns_client.publish(
                TopicArn=self.alert_topic,
                Subject=f"Security Remediation Report - Scan {scan_id}",
                Message=message
            )
            
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
    
    # Helper methods for extracting identifiers from findings
    
    def _extract_secret_identifier(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract AWS Secrets Manager secret identifier from finding"""
        # Look in common locations
        code_snippet = finding.get('code_snippet', '')
        message = finding.get('message', '')
        
        # Pattern matching for secret ARNs or names
        import re
        
        # Match secret ARN
        arn_pattern = r'arn:aws:secretsmanager:[^:]+:[^:]+:secret:([^:]+)'
        arn_match = re.search(arn_pattern, code_snippet) or re.search(arn_pattern, message)
        if arn_match:
            return arn_match.group(1).split('-')[0]  # Remove version suffix
        
        # Match secret name references
        name_patterns = [
            r'secret[_-]?name["\']?\s*[:=]\s*["\']([\w/-]+)',
            r'get_secret_value\(["\']([^"\']+)',
            r'SecretId["\']?\s*[:=]\s*["\']([\w/-]+)'
        ]
        
        for pattern in name_patterns:
            match = re.search(pattern, code_snippet, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_access_key_id(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract IAM access key ID from finding"""
        import re
        
        code_snippet = finding.get('code_snippet', '')
        
        # AWS access key pattern
        key_pattern = r'AKIA[0-9A-Z]{16}'
        match = re.search(key_pattern, code_snippet)
        
        return match.group(0) if match else None
    
    def _extract_key_info(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract private key information from finding"""
        file_path = finding.get('file_path', '')
        code_snippet = finding.get('code_snippet', '')
        
        # Check for EC2 key pairs
        if '.pem' in file_path or 'KeyName' in code_snippet:
            import re
            key_name_match = re.search(r'KeyName["\']?\s*[:=]\s*["\']([\w-]+)', code_snippet)
            if key_name_match:
                return {
                    'type': 'ec2_key_pair',
                    'key_name': key_name_match.group(1)
                }
        
        # Check for parameter store keys
        if 'parameter' in file_path.lower() or 'ssm' in code_snippet.lower():
            import re
            param_match = re.search(r'[Pp]arameter["\']?\s*[:=]\s*["\']([\w/-]+)', code_snippet)
            if param_match:
                return {
                    'type': 'parameter_store',
                    'parameter_name': param_match.group(1),
                    'generate_new': True
                }
        
        return {}
    
    def _extract_database_info(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract database connection information from finding"""
        import re
        
        code_snippet = finding.get('code_snippet', '')
        
        # RDS instance pattern
        rds_pattern = r'DBInstanceIdentifier["\']?\s*[:=]\s*["\']([\w-]+)'
        rds_match = re.search(rds_pattern, code_snippet)
        
        if rds_match:
            # Look for username
            user_pattern = r'MasterUsername["\']?\s*[:=]\s*["\']([\w-]+)'
            user_match = re.search(user_pattern, code_snippet)
            
            return {
                'type': 'rds',
                'instance_id': rds_match.group(1),
                'username': user_match.group(1) if user_match else 'admin'
            }
        
        # Check if it's a secrets manager reference
        if 'secret' in code_snippet.lower():
            return {'type': 'secrets_manager'}
        
        return {}
    
    def _get_access_key_info(self, access_key_id: str) -> Optional[Dict[str, Any]]:
        """Get IAM access key information"""
        try:
            # List all users and find the key
            paginator = iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    # List access keys for user
                    keys_response = iam_client.list_access_keys(UserName=user['UserName'])
                    
                    for key_metadata in keys_response['AccessKeyMetadata']:
                        if key_metadata['AccessKeyId'] == access_key_id:
                            return {
                                'UserName': user['UserName'],
                                'Status': key_metadata['Status'],
                                'CreateDate': key_metadata['CreateDate'].isoformat()
                            }
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get access key info: {e}")
            return None
    
    def _is_safe_to_rotate_key(self, user_name: str) -> bool:
        """Check if it's safe to create a new access key for user"""
        try:
            # Check current number of keys
            response = iam_client.list_access_keys(UserName=user_name)
            active_keys = [k for k in response['AccessKeyMetadata'] if k['Status'] == 'Active']
            
            # IAM allows maximum 2 access keys per user
            return len(active_keys) < 2
            
        except Exception:
            return False
    
    def _store_new_access_key(self, user_name: str, access_key: Dict[str, Any]) -> None:
        """Store new access key in Secrets Manager"""
        try:
            secret_name = f"iam/{user_name}/access-key-{datetime.utcnow().strftime('%Y%m%d')}"
            
            secrets_manager.create_secret(
                Name=secret_name,
                SecretString=json.dumps({
                    'AccessKeyId': access_key['AccessKeyId'],
                    'SecretAccessKey': access_key['SecretAccessKey'],
                    'UserName': user_name,
                    'CreateDate': access_key['CreateDate'].isoformat()
                }),
                Tags=[
                    {'Key': 'Type', 'Value': 'IAMAccessKey'},
                    {'Key': 'UserName', 'Value': user_name},
                    {'Key': 'AutoRotated', 'Value': 'true'}
                ]
            )
            
        except Exception as e:
            logger.error(f"Failed to store new access key: {e}")
    
    def _store_database_credential(self, secret_name: str, username: str, password: str) -> None:
        """Store database credential in Secrets Manager"""
        try:
            secret_value = {
                'username': username,
                'password': password,
                'engine': 'mysql',  # Default, should be determined from context
                'rotated_at': datetime.utcnow().isoformat()
            }
            
            try:
                # Try to create new secret
                secrets_manager.create_secret(
                    Name=secret_name,
                    SecretString=json.dumps(secret_value),
                    Tags=[
                        {'Key': 'Type', 'Value': 'DatabaseCredential'},
                        {'Key': 'AutoRotated', 'Value': 'true'}
                    ]
                )
            except secrets_manager.exceptions.ResourceExistsException:
                # Update existing secret
                secrets_manager.update_secret(
                    SecretId=secret_name,
                    SecretString=json.dumps(secret_value)
                )
                
        except Exception as e:
            logger.error(f"Failed to store database credential: {e}")
    
    def _tag_compromised_resource(self, resource_arn: str, scan_id: str) -> None:
        """Tag a resource as compromised"""
        try:
            # Determine resource type and use appropriate tagging API
            if ':secretsmanager:' in resource_arn:
                secrets_manager.tag_resource(
                    SecretId=resource_arn.split(':')[-1],
                    Tags=[
                        {'Key': 'CompromisedCredential', 'Value': 'true'},
                        {'Key': 'RemediationScanId', 'Value': scan_id},
                        {'Key': 'RemediatedAt', 'Value': datetime.utcnow().isoformat()}
                    ]
                )
                
        except Exception as e:
            logger.error(f"Failed to tag resource {resource_arn}: {e}")
    
    def _schedule_secret_rotation(self, secret_id: str) -> None:
        """Schedule secret for rotation (when auto-remediation is disabled)"""
        try:
            # Add tags to indicate pending rotation
            secrets_manager.tag_resource(
                SecretId=secret_id,
                Tags=[
                    {'Key': 'PendingRotation', 'Value': 'true'},
                    {'Key': 'RotationRequestedAt', 'Value': datetime.utcnow().isoformat()}
                ]
            )
            
        except Exception as e:
            logger.error(f"Failed to schedule rotation for {secret_id}: {e}")
    
    def _get_account_id(self) -> str:
        """Get current AWS account ID"""
        try:
            return boto3.client('sts').get_caller_identity()['Account']
        except Exception:
            return 'unknown'


def lambda_handler(event, context):
    """AWS Lambda handler function"""
    handler = RemediationHandler()
    return handler.handle_event(event)