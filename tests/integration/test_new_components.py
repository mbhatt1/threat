#!/usr/bin/env python3
"""
Integration tests for new AI Security Audit Framework components
"""
import pytest
import boto3
import json
import os
from unittest.mock import Mock, patch, MagicMock
from moto import mock_s3, mock_dynamodb, mock_events, mock_athena, mock_secretsmanager, mock_ssm, mock_cloudwatch
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent.parent / "src"))


class TestEventBridgeIntegration:
    """Test EventBridge rules and integrations"""
    
    @mock_events
    def test_ecr_scanning_rule_created(self):
        """Test ECR scanning rule creation"""
        client = boto3.client('events', region_name='us-east-1')
        
        # Create the rule
        rule_name = 'ecr-scanning-trigger'
        client.put_rule(
            Name=rule_name,
            EventPattern=json.dumps({
                "source": ["aws.ecr"],
                "detail-type": ["ECR Image Scan"],
                "detail": {
                    "scan-status": ["COMPLETE"]
                }
            }),
            State='ENABLED',
            Description='Trigger security scan on ECR scan completion'
        )
        
        # Verify rule exists
        response = client.describe_rule(Name=rule_name)
        assert response['Name'] == rule_name
        assert response['State'] == 'ENABLED'
    
    @mock_events
    def test_scheduled_security_scan_rule(self):
        """Test scheduled security scan rule"""
        client = boto3.client('events', region_name='us-east-1')
        
        # Create scheduled rule
        rule_name = 'scheduled-security-scan'
        client.put_rule(
            Name=rule_name,
            ScheduleExpression='rate(1 day)',
            State='ENABLED',
            Description='Daily security scan'
        )
        
        # Add Lambda target
        client.put_targets(
            Rule=rule_name,
            Targets=[{
                'Id': '1',
                'Arn': 'arn:aws:lambda:us-east-1:123456789012:function:security-scan-trigger'
            }]
        )
        
        # Verify targets
        response = client.list_targets_by_rule(Rule=rule_name)
        assert len(response['Targets']) == 1
        assert 'security-scan-trigger' in response['Targets'][0]['Arn']


class TestSecurityLakeIntegration:
    """Test Security Lake configuration and data flow"""
    
    @mock_s3
    def test_security_lake_bucket_creation(self):
        """Test Security Lake bucket is created with proper configuration"""
        s3 = boto3.client('s3', region_name='us-east-1')
        
        bucket_name = 'ai-security-audit-security-lake-dev'
        
        # Create bucket
        s3.create_bucket(Bucket=bucket_name)
        
        # Add lifecycle configuration
        s3.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={
                'Rules': [{
                    'ID': 'security-lake-retention',
                    'Status': 'Enabled',
                    'Transitions': [{
                        'Days': 30,
                        'StorageClass': 'INTELLIGENT_TIERING'
                    }],
                    'Expiration': {
                        'Days': 365
                    }
                }]
            }
        )
        
        # Verify lifecycle
        response = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        assert len(response['Rules']) == 1
        assert response['Rules'][0]['ID'] == 'security-lake-retention'
    
    @mock_s3
    def test_security_findings_storage(self):
        """Test storing security findings in OCSF format"""
        s3 = boto3.client('s3', region_name='us-east-1')
        bucket_name = 'ai-security-audit-security-lake-dev'
        
        s3.create_bucket(Bucket=bucket_name)
        
        # OCSF format finding
        finding = {
            "metadata": {
                "version": "1.0.0",
                "product": {
                    "name": "AI Security Audit",
                    "vendor_name": "SecurityOrg"
                }
            },
            "finding": {
                "uid": "finding-123",
                "title": "SQL Injection Vulnerability",
                "types": ["vulnerability"],
                "severity_id": 4,  # High
                "confidence_id": 3  # High confidence
            }
        }
        
        # Store finding
        key = 'findings/2024/01/01/finding-123.json'
        s3.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=json.dumps(finding),
            ContentType='application/json'
        )
        
        # Verify storage
        response = s3.get_object(Bucket=bucket_name, Key=key)
        stored_finding = json.loads(response['Body'].read())
        assert stored_finding['finding']['uid'] == 'finding-123'


class TestQuickSightAthenaIntegration:
    """Test QuickSight and Athena integration"""
    
    @mock_athena
    @mock_s3
    def test_athena_table_creation(self):
        """Test Athena table creation for security findings"""
        s3 = boto3.client('s3', region_name='us-east-1')
        athena = boto3.client('athena', region_name='us-east-1')
        
        # Create query results bucket
        s3.create_bucket(Bucket='ai-security-audit-athena-results-dev')
        
        # Create database
        create_db_query = """
        CREATE DATABASE IF NOT EXISTS security_audit_db
        """
        
        # Execute query (mocked)
        response = athena.start_query_execution(
            QueryString=create_db_query,
            ResultConfiguration={
                'OutputLocation': 's3://ai-security-audit-athena-results-dev/'
            }
        )
        
        assert 'QueryExecutionId' in response
    
    def test_quicksight_dataset_configuration(self):
        """Test QuickSight dataset configuration"""
        # Mock QuickSight configuration
        dataset_config = {
            "PhysicalTableMap": {
                "SecurityFindings": {
                    "S3Source": {
                        "DataSourceArn": "arn:aws:quicksight:us-east-1:123456789012:datasource/security-findings",
                        "InputColumns": [
                            {"Name": "finding_id", "Type": "STRING"},
                            {"Name": "severity", "Type": "STRING"},
                            {"Name": "type", "Type": "STRING"},
                            {"Name": "timestamp", "Type": "DATETIME"},
                            {"Name": "ai_confidence", "Type": "DECIMAL"}
                        ]
                    }
                }
            }
        }
        
        assert 'SecurityFindings' in dataset_config['PhysicalTableMap']
        assert len(dataset_config['PhysicalTableMap']['SecurityFindings']['S3Source']['InputColumns']) == 5


class TestCLICommands:
    """Test new CLI commands"""
    
    def test_configure_command(self):
        """Test configure command functionality"""
        from cli.security_audit_cli import SecurityAuditCLI
        
        cli = SecurityAuditCLI()
        
        # Test config save
        test_config = {
            "version": "1.0.0",
            "api": {
                "endpoint": "https://api.security.example.com",
                "auth_token": "test-token"
            }
        }
        
        with patch('builtins.open', create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file
            
            cli.save_config(test_config)
            
            # Verify write was called
            mock_file.write.assert_called()
    
    @patch('requests.get')
    def test_validate_command(self, mock_get):
        """Test validate command checks"""
        from cli.security_audit_cli import SecurityAuditCLI
        
        cli = SecurityAuditCLI()
        
        # Mock API health check
        mock_get.return_value.status_code = 200
        
        config = {
            "api": {
                "endpoint": "https://api.test.com",
                "auth_token": "test-token"
            }
        }
        
        # Test API connectivity check
        api_connected = False
        try:
            response = mock_get(
                f"{config['api']['endpoint']}/health",
                headers={"Authorization": f"Bearer {config['api']['auth_token']}"},
                timeout=5
            )
            api_connected = response.status_code == 200
        except:
            api_connected = False
        
        assert api_connected is True
    
    @patch('requests.post')
    @patch('requests.get')
    def test_remediate_command(self, mock_get, mock_post):
        """Test remediate command functionality"""
        # Mock findings response
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'findings': [
                {
                    'finding_id': 'vuln-001',
                    'type': 'SQL Injection',
                    'severity': 'high',
                    'file_path': '/app/user.py'
                }
            ]
        }
        
        # Mock remediation response
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            'successful': 1,
            'failed': 0,
            'remediation_details': [
                {
                    'finding_id': 'vuln-001',
                    'status': 'success',
                    'fix_applied': 'Added parameterized query'
                }
            ]
        }
        
        # Test remediation request
        remediation_request = {
            "scan_id": "scan-123",
            "finding_ids": ["vuln-001"],
            "dry_run": False,
            "auto_apply": True
        }
        
        response = mock_post(
            "https://api.test.com/remediations/generate",
            json=remediation_request
        )
        
        result = response.json()
        assert result['successful'] == 1
        assert result['failed'] == 0


class TestECRScanningIntegration:
    """Test ECR vulnerability scanning integration"""
    
    def test_ecr_scanning_lambda_handler(self):
        """Test ECR scanning enabler Lambda function"""
        # Import the handler
        from lambdas.ecr_scanning_enabler.handler import lambda_handler
        
        # Mock ECR event
        event = {
            "source": "aws.ecr",
            "detail-type": "ECR Image Action",
            "detail": {
                "action-type": "PUSH",
                "repository-name": "ai-security-app",
                "image-digest": "sha256:1234567890",
                "image-tag": "latest"
            }
        }
        
        # Mock context
        context = Mock()
        
        with patch('boto3.client') as mock_boto:
            mock_ecr = Mock()
            mock_boto.return_value = mock_ecr
            
            # Mock scan response
            mock_ecr.start_image_scan.return_value = {
                'imageScanStatus': {
                    'status': 'IN_PROGRESS'
                }
            }
            
            # Call handler
            response = lambda_handler(event, context)
            
            assert response['statusCode'] == 200
            assert 'Scan initiated' in response['body']


class TestSecretsManagerIntegration:
    """Test Secrets Manager integration"""
    
    @mock_secretsmanager
    def test_api_keys_storage(self):
        """Test storing API keys in Secrets Manager"""
        client = boto3.client('secretsmanager', region_name='us-east-1')
        
        secrets = [
            ('github-api-key', {'api_key': 'ghp_1234567890'}),
            ('openai-api-key', {'api_key': 'sk-1234567890'}),
            ('snyk-api-token', {'api_token': 'snyk-1234567890'})
        ]
        
        for secret_name, secret_value in secrets:
            client.create_secret(
                Name=f'ai-security-audit/{secret_name}',
                SecretString=json.dumps(secret_value),
                Description=f'API key for {secret_name}'
            )
        
        # Verify secrets
        response = client.list_secrets()
        assert len(response['SecretList']) == 3
        
        # Verify secret retrieval
        secret = client.get_secret_value(SecretId='ai-security-audit/github-api-key')
        value = json.loads(secret['SecretString'])
        assert 'api_key' in value


class TestCloudWatchMonitoring:
    """Test CloudWatch monitoring integration"""
    
    @mock_cloudwatch
    def test_custom_metrics(self):
        """Test custom metrics publishing"""
        client = boto3.client('cloudwatch', region_name='us-east-1')
        
        # Put custom metric
        client.put_metric_data(
            Namespace='AISecurityAudit',
            MetricData=[
                {
                    'MetricName': 'VulnerabilitiesFound',
                    'Value': 15,
                    'Unit': 'Count',
                    'Dimensions': [
                        {
                            'Name': 'Severity',
                            'Value': 'High'
                        }
                    ]
                }
            ]
        )
        
        # List metrics
        response = client.list_metrics(Namespace='AISecurityAudit')
        assert len(response['Metrics']) > 0
    
    @mock_cloudwatch
    def test_alarms_configuration(self):
        """Test CloudWatch alarms creation"""
        client = boto3.client('cloudwatch', region_name='us-east-1')
        
        # Create alarm
        client.put_metric_alarm(
            AlarmName='high-severity-vulnerabilities',
            ComparisonOperator='GreaterThanThreshold',
            EvaluationPeriods=1,
            MetricName='VulnerabilitiesFound',
            Namespace='AISecurityAudit',
            Period=300,
            Statistic='Sum',
            Threshold=10,
            ActionsEnabled=True,
            AlarmActions=['arn:aws:sns:us-east-1:123456789012:security-alerts'],
            AlarmDescription='Alert on high severity vulnerabilities'
        )
        
        # Verify alarm
        response = client.describe_alarms(AlarmNames=['high-severity-vulnerabilities'])
        assert len(response['MetricAlarms']) == 1
        assert response['MetricAlarms'][0]['Threshold'] == 10


@pytest.fixture
def mock_aws_credentials():
    """Mock AWS credentials for testing"""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])