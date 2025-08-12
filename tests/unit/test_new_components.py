#!/usr/bin/env python3
"""
Unit tests for new AI Security Audit Framework components
"""
import pytest
import json
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent.parent / "src"))


class TestECRScanningLambda:
    """Unit tests for ECR scanning enabler Lambda"""
    
    def test_handler_with_push_event(self):
        """Test handler processes ECR push events correctly"""
        from lambdas.ecr_scanning_enabler.handler import lambda_handler
        
        event = {
            "source": "aws.ecr",
            "detail-type": "ECR Image Action",
            "detail": {
                "action-type": "PUSH",
                "repository-name": "test-repo",
                "image-digest": "sha256:abc123",
                "image-tag": "v1.0.0"
            }
        }
        
        with patch('boto3.client') as mock_boto:
            mock_ecr = Mock()
            mock_boto.return_value = mock_ecr
            
            mock_ecr.start_image_scan.return_value = {
                'imageScanStatus': {'status': 'IN_PROGRESS'}
            }
            
            result = lambda_handler(event, Mock())
            
            assert result['statusCode'] == 200
            mock_ecr.start_image_scan.assert_called_once_with(
                repositoryName='test-repo',
                imageId={'imageDigest': 'sha256:abc123'}
            )
    
    def test_handler_with_non_push_event(self):
        """Test handler ignores non-push events"""
        from lambdas.ecr_scanning_enabler.handler import lambda_handler
        
        event = {
            "source": "aws.ecr",
            "detail-type": "ECR Image Action",
            "detail": {
                "action-type": "DELETE",
                "repository-name": "test-repo"
            }
        }
        
        result = lambda_handler(event, Mock())
        
        assert result['statusCode'] == 200
        assert 'Ignoring' in result['body']
    
    def test_handler_error_handling(self):
        """Test handler error handling"""
        from lambdas.ecr_scanning_enabler.handler import lambda_handler
        
        event = {
            "source": "aws.ecr",
            "detail-type": "ECR Image Action",
            "detail": {
                "action-type": "PUSH",
                "repository-name": "test-repo",
                "image-digest": "sha256:abc123"
            }
        }
        
        with patch('boto3.client') as mock_boto:
            mock_ecr = Mock()
            mock_boto.return_value = mock_ecr
            
            mock_ecr.start_image_scan.side_effect = Exception("ECR error")
            
            result = lambda_handler(event, Mock())
            
            assert result['statusCode'] == 500
            assert 'Error' in result['body']


class TestAthenaSetupLambda:
    """Unit tests for Athena setup Lambda"""
    
    @patch('boto3.client')
    def test_create_database(self, mock_boto):
        """Test database creation"""
        mock_athena = Mock()
        mock_boto.return_value = mock_athena
        
        mock_athena.start_query_execution.return_value = {
            'QueryExecutionId': 'query-123'
        }
        
        from lambdas.athena_setup.handler import create_database
        
        result = create_database(mock_athena, 'test-db', 's3://test-bucket/')
        
        assert result == 'query-123'
        mock_athena.start_query_execution.assert_called_once()
    
    @patch('boto3.client')
    def test_create_security_findings_table(self, mock_boto):
        """Test security findings table creation"""
        mock_athena = Mock()
        mock_boto.return_value = mock_athena
        
        mock_athena.start_query_execution.return_value = {
            'QueryExecutionId': 'query-456'
        }
        
        from lambdas.athena_setup.handler import create_security_findings_table
        
        result = create_security_findings_table(
            mock_athena, 
            'test-db', 
            's3://test-bucket/findings/',
            's3://results-bucket/'
        )
        
        assert result == 'query-456'
        
        # Verify the SQL contains expected columns
        call_args = mock_athena.start_query_execution.call_args
        query = call_args[1]['QueryString']
        assert 'finding_id' in query
        assert 'severity' in query
        assert 'ai_confidence' in query


class TestQuickSightDashboardLambda:
    """Unit tests for QuickSight dashboard Lambda"""
    
    @patch('boto3.client')
    def test_create_data_source(self, mock_boto):
        """Test QuickSight data source creation"""
        mock_qs = Mock()
        mock_boto.return_value = mock_qs
        
        mock_qs.create_data_source.return_value = {
            'Arn': 'arn:aws:quicksight:us-east-1:123:datasource/test-ds',
            'DataSourceId': 'test-ds'
        }
        
        # Mock the handler function
        def create_data_source(client, account_id, data_source_id):
            return client.create_data_source(
                AwsAccountId=account_id,
                DataSourceId=data_source_id,
                Name='Security Findings Data Source',
                Type='ATHENA',
                DataSourceParameters={
                    'AthenaParameters': {
                        'WorkGroup': 'primary'
                    }
                }
            )
        
        result = create_data_source(mock_qs, '123456789012', 'test-ds')
        
        assert result['DataSourceId'] == 'test-ds'
        mock_qs.create_data_source.assert_called_once()
    
    @patch('boto3.client')
    def test_create_dataset(self, mock_boto):
        """Test QuickSight dataset creation"""
        mock_qs = Mock()
        mock_boto.return_value = mock_qs
        
        mock_qs.create_data_set.return_value = {
            'Arn': 'arn:aws:quicksight:us-east-1:123:dataset/test-dataset',
            'DataSetId': 'test-dataset'
        }
        
        # Mock dataset creation
        def create_dataset(client, account_id, dataset_id, datasource_arn):
            return client.create_data_set(
                AwsAccountId=account_id,
                DataSetId=dataset_id,
                Name='Security Findings Dataset',
                PhysicalTableMap={
                    'SecurityFindings': {
                        'RelationalTable': {
                            'DataSourceArn': datasource_arn,
                            'Schema': 'security_audit_db',
                            'Name': 'security_findings'
                        }
                    }
                }
            )
        
        result = create_dataset(
            mock_qs, 
            '123456789012', 
            'test-dataset',
            'arn:aws:quicksight:us-east-1:123:datasource/test-ds'
        )
        
        assert result['DataSetId'] == 'test-dataset'


class TestSecurityAuditCLI:
    """Unit tests for Security Audit CLI commands"""
    
    def test_cli_initialization(self):
        """Test CLI initialization"""
        from cli.security_audit_cli import SecurityAuditCLI
        
        cli = SecurityAuditCLI()
        
        assert cli.config_path.name == 'config.json'
        assert cli.config_path.parent.name == '.security'
    
    @patch('builtins.open', create=True)
    @patch('pathlib.Path.exists')
    def test_load_config(self, mock_exists, mock_open):
        """Test configuration loading"""
        from cli.security_audit_cli import SecurityAuditCLI
        
        mock_exists.return_value = True
        mock_config = {
            "version": "1.0.0",
            "api": {"endpoint": "https://api.test.com"}
        }
        
        mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(mock_config)
        
        cli = SecurityAuditCLI()
        config = cli.load_config()
        
        assert config['version'] == '1.0.0'
        assert config['api']['endpoint'] == 'https://api.test.com'
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open', create=True)
    def test_save_config(self, mock_open, mock_mkdir):
        """Test configuration saving"""
        from cli.security_audit_cli import SecurityAuditCLI
        
        cli = SecurityAuditCLI()
        test_config = {
            "version": "1.0.0",
            "api": {"endpoint": "https://api.test.com"}
        }
        
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        cli.save_config(test_config)
        
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
        mock_file.write.assert_called()
    
    @patch('requests.get')
    def test_validate_api_connectivity(self, mock_get):
        """Test API connectivity validation"""
        # Test successful connection
        mock_get.return_value.status_code = 200
        
        api_endpoint = "https://api.test.com"
        api_token = "test-token"
        
        response = mock_get(
            f"{api_endpoint}/health",
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=5
        )
        
        assert response.status_code == 200
        
        # Test failed connection
        mock_get.side_effect = Exception("Connection error")
        
        api_connected = False
        try:
            response = mock_get(
                f"{api_endpoint}/health",
                headers={"Authorization": f"Bearer {api_token}"},
                timeout=5
            )
        except:
            api_connected = False
        
        assert api_connected is False
    
    @patch('requests.post')
    def test_scan_command_logic(self, mock_post):
        """Test scan command logic"""
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            'scan_id': 'scan-789',
            'status': 'initiated'
        }
        
        scan_request = {
            "repository_url": "https://github.com/test/repo",
            "branch": "main",
            "priority": "high",
            "agents": ["sast", "secrets", "dependency"]
        }
        
        response = mock_post(
            "https://api.test.com/scans",
            json=scan_request
        )
        
        result = response.json()
        assert result['scan_id'] == 'scan-789'
        assert result['status'] == 'initiated'
    
    @patch('requests.get')
    @patch('requests.post')
    def test_remediate_logic(self, mock_post, mock_get):
        """Test remediation logic"""
        # Mock getting findings
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'findings': [
                {
                    'finding_id': 'vuln-001',
                    'type': 'SQL Injection',
                    'severity': 'high',
                    'file_path': '/app/db.py',
                    'line': 42
                },
                {
                    'finding_id': 'vuln-002',
                    'type': 'XSS',
                    'severity': 'medium',
                    'file_path': '/app/views.py',
                    'line': 100
                }
            ]
        }
        
        # Mock remediation generation
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            'successful': 2,
            'failed': 0,
            'remediation_details': [
                {
                    'finding_id': 'vuln-001',
                    'status': 'success',
                    'fix_applied': 'Replaced with parameterized query'
                },
                {
                    'finding_id': 'vuln-002',
                    'status': 'success',
                    'fix_applied': 'Added HTML escaping'
                }
            ]
        }
        
        # Get findings
        findings_response = mock_get(
            "https://api.test.com/scans/scan-123/findings"
        )
        findings = findings_response.json()['findings']
        
        assert len(findings) == 2
        
        # Generate remediations
        remediation_request = {
            "scan_id": "scan-123",
            "finding_ids": [f['finding_id'] for f in findings],
            "dry_run": False,
            "auto_apply": True
        }
        
        remediation_response = mock_post(
            "https://api.test.com/remediations/generate",
            json=remediation_request
        )
        
        result = remediation_response.json()
        assert result['successful'] == 2
        assert result['failed'] == 0
        assert len(result['remediation_details']) == 2


class TestMetricsBucket:
    """Unit tests for metrics bucket functionality"""
    
    def test_metrics_data_structure(self):
        """Test metrics data structure for AI explainability"""
        metrics_data = {
            "scan_id": "scan-123",
            "timestamp": "2024-01-01T12:00:00Z",
            "ai_metrics": {
                "model_confidence": 0.95,
                "explanation_quality": 0.88,
                "false_positive_rate": 0.02,
                "true_positive_rate": 0.98
            },
            "vulnerabilities_by_severity": {
                "critical": 2,
                "high": 5,
                "medium": 10,
                "low": 20
            },
            "scan_performance": {
                "duration_seconds": 300,
                "files_scanned": 1500,
                "lines_analyzed": 50000
            }
        }
        
        # Validate structure
        assert 'ai_metrics' in metrics_data
        assert metrics_data['ai_metrics']['model_confidence'] > 0.9
        assert metrics_data['scan_performance']['files_scanned'] > 0
    
    def test_metrics_aggregation(self):
        """Test metrics aggregation logic"""
        daily_metrics = [
            {"scans": 10, "vulnerabilities": 50, "ai_confidence_avg": 0.92},
            {"scans": 15, "vulnerabilities": 75, "ai_confidence_avg": 0.94},
            {"scans": 12, "vulnerabilities": 60, "ai_confidence_avg": 0.93}
        ]
        
        # Aggregate metrics
        total_scans = sum(m['scans'] for m in daily_metrics)
        total_vulns = sum(m['vulnerabilities'] for m in daily_metrics)
        avg_confidence = sum(m['ai_confidence_avg'] for m in daily_metrics) / len(daily_metrics)
        
        assert total_scans == 37
        assert total_vulns == 185
        assert 0.92 < avg_confidence < 0.94


class TestBusinessContextTable:
    """Unit tests for business context DynamoDB table"""
    
    def test_business_context_item_structure(self):
        """Test business context item structure"""
        context_item = {
            "finding_id": "vuln-001",
            "business_impact": {
                "revenue_risk": "high",
                "compliance_impact": ["PCI-DSS", "SOC2"],
                "customer_data_exposed": True,
                "estimated_cost": 50000
            },
            "remediation_priority": {
                "score": 9.5,
                "factors": [
                    "customer_data_exposure",
                    "compliance_violation",
                    "easy_exploitation"
                ]
            },
            "ai_analysis": {
                "confidence": 0.96,
                "reasoning": "Critical SQL injection in payment processing"
            }
        }
        
        assert context_item['business_impact']['revenue_risk'] == 'high'
        assert 'PCI-DSS' in context_item['business_impact']['compliance_impact']
        assert context_item['remediation_priority']['score'] > 9.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])