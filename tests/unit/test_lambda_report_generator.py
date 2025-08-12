import pytest
import json
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from lambdas.report_generator.handler import lambda_handler, generate_html_report, generate_json_report


class TestReportGeneratorLambda:
    """Test cases for Report Generator Lambda function"""
    
    @patch('lambdas.report_generator.handler.boto3.client')
    def test_successful_report_generation(self, mock_boto_client):
        """Test successful report generation with AI agents"""
        # Mock S3 client
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3
        
        # Test event
        event = {
            'scan_id': 'scan-001',
            'scan_metadata': {
                'repository_url': 'https://github.com/test/repo',
                'branch': 'main',
                'scan_date': '2024-01-15T10:30:00Z',
                'total_cost': 12.50,  # Higher cost for AI agents
                'ai_tokens_used': 75000
            },
            'aggregated_results': {
                'total_findings': 10,
                'severity_distribution': {
                    'CRITICAL': 1,
                    'HIGH': 3,
                    'MEDIUM': 4,
                    'LOW': 2,
                    'INFO': 0
                },
                'agent_summary': {
                    'BEDROCK_UNIFIED': {
                        'findings_count': 5,
                        'execution_time': 600,
                        'status': 'success',
                        'ai_metrics': {
                            'tokens_used': 25000,
                            'model': 'claude-3-sonnet',
                            'confidence_score': 0.93
                        }
                    },
                    'AUTONOMOUS_CODE_ANALYZER': {
                        'findings_count': 3,
                        'execution_time': 480,
                        'status': 'success',
                        'ai_metrics': {
                            'tokens_used': 30000,
                            'model': 'claude-3-opus',
                            'confidence_score': 0.96
                        }
                    },
                    'AUTONOMOUS_THREAT_INTEL': {
                        'findings_count': 2,
                        'execution_time': 300,
                        'status': 'success',
                        'ai_metrics': {
                            'tokens_used': 20000,
                            'model': 'claude-3-sonnet',
                            'confidence_score': 0.91
                        }
                    }
                },
                'all_findings': [
                    {
                        'finding_id': 'bedrock-001',
                        'type': 'sql_injection',
                        'severity': 'CRITICAL',
                        'title': 'SQL Injection Vulnerability',
                        'file_path': 'src/api.py',
                        'line_number': 42,
                        'remediation': 'Use parameterized queries',
                        'ai_analysis': {
                            'model': 'claude-3-sonnet',
                            'confidence_score': 0.97,
                            'explanation': 'Direct string concatenation of user input in SQL query'
                        }
                    }
                ]
            }
        }
        
        # Call handler
        response = lambda_handler(event, None)
        
        # Verify response
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['status'] == 'success'
        assert 'report_url' in body
        assert 'json_report_url' in body
        
        # Verify S3 uploads were called
        assert mock_s3.put_object.call_count >= 2  # HTML and JSON reports
    
    @patch('lambdas.report_generator.handler.boto3.client')
    def test_report_with_no_findings(self, mock_boto_client):
        """Test report generation with no findings from AI agents"""
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3
        
        event = {
            'scan_id': 'scan-002',
            'scan_metadata': {
                'repository_url': 'https://github.com/test/clean-repo',
                'branch': 'main',
                'scan_date': '2024-01-15T10:30:00Z'
            },
            'aggregated_results': {
                'total_findings': 0,
                'severity_distribution': {
                    'CRITICAL': 0,
                    'HIGH': 0,
                    'MEDIUM': 0,
                    'LOW': 0,
                    'INFO': 0
                },
                'agent_summary': {
                    'BEDROCK_UNIFIED': {
                        'findings_count': 0,
                        'execution_time': 600,
                        'status': 'success',
                        'ai_metrics': {
                            'tokens_used': 15000,
                            'model': 'claude-3-sonnet',
                            'confidence_score': 0.99
                        }
                    }
                },
                'all_findings': []
            }
        }
        
        response = lambda_handler(event, None)
        
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['status'] == 'success'
        
        # Verify clean report was generated
        put_calls = mock_s3.put_object.call_args_list
        html_content = None
        for call in put_calls:
            if 'html' in call[1]['Key']:
                html_content = call[1]['Body']
                break
        
        assert html_content is not None
        assert 'No security findings' in html_content or 'clean' in html_content.lower()
    
    def test_missing_required_fields(self):
        """Test handling of missing required fields"""
        event = {
            'scan_id': 'scan-003'
            # Missing aggregated_results
        }
        
        response = lambda_handler(event, None)
        
        assert response['statusCode'] == 400
        body = json.loads(response['body'])
        assert 'error' in body
    
    @patch('lambdas.report_generator.handler.boto3.client')
    def test_s3_upload_failure(self, mock_boto_client):
        """Test handling of S3 upload failure"""
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = Exception("S3 upload failed")
        mock_boto_client.return_value = mock_s3
        
        event = {
            'scan_id': 'scan-004',
            'scan_metadata': {
                'repository_url': 'https://github.com/test/repo'
            },
            'aggregated_results': {
                'total_findings': 1,
                'all_findings': []
            }
        }
        
        response = lambda_handler(event, None)
        
        assert response['statusCode'] == 500
        body = json.loads(response['body'])
        assert 'error' in body
        assert 'S3 upload failed' in body['error']
    
    @patch('lambdas.report_generator.handler.boto3.client')
    def test_report_with_all_ai_agents(self, mock_boto_client):
        """Test report generation with all AI agents"""
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3
        
        event = {
            'scan_id': 'scan-005',
            'scan_metadata': {
                'repository_url': 'https://github.com/test/comprehensive-repo',
                'branch': 'main',
                'scan_date': '2024-01-15T10:30:00Z',
                'total_cost': 25.00,
                'ai_tokens_used': 150000
            },
            'aggregated_results': {
                'total_findings': 25,
                'severity_distribution': {
                    'CRITICAL': 3,
                    'HIGH': 8,
                    'MEDIUM': 10,
                    'LOW': 4,
                    'INFO': 0
                },
                'agent_summary': {
                    'BEDROCK_UNIFIED': {
                        'findings_count': 8,
                        'execution_time': 600,
                        'status': 'success'
                    },
                    'AUTONOMOUS_CODE_ANALYZER': {
                        'findings_count': 6,
                        'execution_time': 480,
                        'status': 'success'
                    },
                    'AUTONOMOUS_THREAT_INTEL': {
                        'findings_count': 4,
                        'execution_time': 300,
                        'status': 'success'
                    },
                    'AUTONOMOUS_INFRA_SECURITY': {
                        'findings_count': 3,
                        'execution_time': 360,
                        'status': 'success'
                    },
                    'AUTONOMOUS_SUPPLY_CHAIN': {
                        'findings_count': 3,
                        'execution_time': 420,
                        'status': 'success'
                    },
                    'AUTONOMOUS_DYNAMIC_TOOL_CREATION': {
                        'findings_count': 1,
                        'execution_time': 540,
                        'status': 'success'
                    }
                },
                'all_findings': []
            }
        }
        
        response = lambda_handler(event, None)
        
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['status'] == 'success'


class TestReportGeneratorHelpers:
    """Test helper functions in Report Generator"""
    
    def test_generate_html_report(self):
        """Test HTML report generation with AI findings"""
        scan_data = {
            'scan_id': 'scan-001',
            'repository_url': 'https://github.com/test/repo',
            'scan_date': '2024-01-15T10:30:00Z',
            'total_findings': 5,
            'severity_distribution': {
                'CRITICAL': 1,
                'HIGH': 2,
                'MEDIUM': 2,
                'LOW': 0,
                'INFO': 0
            },
            'findings': [
                {
                    'severity': 'CRITICAL',
                    'title': 'SQL Injection',
                    'file_path': 'src/api.py',
                    'line_number': 42,
                    'description': 'User input not sanitized',
                    'remediation': 'Use parameterized queries',
                    'ai_analysis': {
                        'model': 'claude-3-sonnet',
                        'confidence_score': 0.97,
                        'explanation': 'Direct concatenation of user input detected'
                    }
                }
            ],
            'ai_metrics': {
                'total_tokens': 75000,
                'total_model_calls': 15,
                'average_confidence': 0.94
            }
        }
        
        html_report = generate_html_report(scan_data)
        
        # Verify HTML structure
        assert '<!DOCTYPE html>' in html_report
        assert '<html' in html_report
        assert scan_data['repository_url'] in html_report
        assert 'SQL Injection' in html_report
        assert 'CRITICAL' in html_report
        assert 'src/api.py:42' in html_report or 'src/api.py' in html_report
        assert 'claude-3-sonnet' in html_report or 'AI Analysis' in html_report
    
    def test_generate_json_report(self):
        """Test JSON report generation with AI metadata"""
        scan_data = {
            'scan_id': 'scan-001',
            'repository_url': 'https://github.com/test/repo',
            'total_findings': 3,
            'findings': [
                {
                    'severity': 'HIGH', 
                    'title': 'Finding 1',
                    'ai_analysis': {'confidence_score': 0.95}
                },
                {
                    'severity': 'MEDIUM', 
                    'title': 'Finding 2',
                    'ai_analysis': {'confidence_score': 0.88}
                },
                {
                    'severity': 'LOW', 
                    'title': 'Finding 3',
                    'ai_analysis': {'confidence_score': 0.82}
                }
            ],
            'ai_metrics': {
                'total_tokens': 50000,
                'models_used': ['claude-3-sonnet', 'claude-3-opus']
            }
        }
        
        json_report = generate_json_report(scan_data)
        report_data = json.loads(json_report)
        
        assert report_data['scan_id'] == 'scan-001'
        assert report_data['total_findings'] == 3
        assert len(report_data['findings']) == 3
        assert report_data['findings'][0]['severity'] == 'HIGH'
        assert 'ai_metrics' in report_data
        assert report_data['ai_metrics']['total_tokens'] == 50000
    
    def test_severity_color_mapping(self):
        """Test severity to color mapping for HTML report"""
        from lambdas.report_generator.handler import get_severity_color
        
        assert get_severity_color('CRITICAL') == '#dc3545'  # red
        assert get_severity_color('HIGH') == '#fd7e14'      # orange
        assert get_severity_color('MEDIUM') == '#ffc107'    # yellow
        assert get_severity_color('LOW') == '#28a745'       # green
        assert get_severity_color('INFO') == '#17a2b8'      # blue
    
    def test_format_finding_for_report(self):
        """Test finding formatting for report with AI analysis"""
        from lambdas.report_generator.handler import format_finding
        
        finding = {
            'finding_id': 'bedrock-001',
            'severity': 'HIGH',
            'title': 'SQL Injection',
            'file_path': 'src/api.py',
            'line_number': 42,
            'description': 'User input not sanitized',
            'code_snippet': 'query = f"SELECT * FROM users WHERE id = {user_id}"',
            'remediation': 'Use parameterized queries',
            'cwe_id': 'CWE-89',
            'ai_analysis': {
                'model': 'claude-3-sonnet',
                'confidence_score': 0.96,
                'explanation': 'Direct string interpolation of user input in SQL query',
                'attack_vector': 'Remote exploitation via crafted input'
            }
        }
        
        formatted = format_finding(finding)
        
        assert formatted['display_location'] == 'src/api.py:42'
        assert formatted['severity_color'] == get_severity_color('HIGH')
        assert 'cwe_link' in formatted
        assert 'CWE-89' in formatted['cwe_link']
        assert formatted['ai_confidence'] == 96  # Percentage


class TestReportMetrics:
    """Test report metrics calculation"""
    
    def test_calculate_risk_score(self):
        """Test risk score calculation"""
        from lambdas.report_generator.handler import calculate_risk_score
        
        severity_distribution = {
            'CRITICAL': 2,
            'HIGH': 5,
            'MEDIUM': 10,
            'LOW': 20,
            'INFO': 5
        }
        
        risk_score = calculate_risk_score(severity_distribution)
        
        # Risk score should be weighted by severity
        assert risk_score > 0
        assert risk_score <= 100
        
        # Test with no findings
        empty_distribution = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        
        assert calculate_risk_score(empty_distribution) == 0
    
    def test_generate_executive_summary(self):
        """Test executive summary generation with AI insights"""
        from lambdas.report_generator.handler import generate_executive_summary
        
        scan_results = {
            'total_findings': 42,
            'severity_distribution': {
                'CRITICAL': 2,
                'HIGH': 5,
                'MEDIUM': 15,
                'LOW': 20,
                'INFO': 0
            },
            'agent_summary': {
                'BEDROCK_UNIFIED': {'findings_count': 15},
                'AUTONOMOUS_CODE_ANALYZER': {'findings_count': 12},
                'AUTONOMOUS_THREAT_INTEL': {'findings_count': 8},
                'AUTONOMOUS_SUPPLY_CHAIN': {'findings_count': 7}
            },
            'ai_metrics': {
                'total_tokens': 100000,
                'average_confidence': 0.92,
                'models_used': ['claude-3-sonnet', 'claude-3-opus']
            }
        }
        
        summary = generate_executive_summary(scan_results)
        
        assert 'risk_level' in summary
        assert 'key_insights' in summary
        assert 'recommendations' in summary
        assert 'ai_analysis_summary' in summary
        assert len(summary['key_insights']) > 0
        assert summary['risk_level'] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        assert 'confidence' in summary['ai_analysis_summary']
    
    def test_calculate_ai_cost_metrics(self):
        """Test AI cost metrics calculation"""
        from lambdas.report_generator.handler import calculate_ai_cost_metrics
        
        ai_metrics = {
            'total_tokens': 150000,
            'model_calls': {
                'claude-3-opus': 5,
                'claude-3-sonnet': 10,
                'claude-3-instant': 20
            }
        }
        
        cost_metrics = calculate_ai_cost_metrics(ai_metrics)
        
        assert 'total_cost' in cost_metrics
        assert 'cost_per_model' in cost_metrics
        assert 'tokens_per_dollar' in cost_metrics
        assert cost_metrics['total_cost'] > 0
        assert len(cost_metrics['cost_per_model']) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])