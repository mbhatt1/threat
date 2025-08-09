import pytest
import json
from unittest.mock import patch, MagicMock
from datetime import datetime
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from lambdas.ceo_agent.handler import lambda_handler


class TestCEOAgentLambda:
    """Test cases for CEO Agent Lambda function"""
    
    @patch('lambdas.ceo_agent.handler.HASHIRUCore')
    @patch('lambdas.ceo_agent.handler.StrandsProtocol')
    def test_successful_scan_initiation(self, mock_protocol_class, mock_hashiru_class):
        """Test successful scan initiation with AI agents"""
        # Setup mocks
        mock_protocol = MagicMock()
        mock_hashiru = MagicMock()
        
        mock_protocol_class.return_value = mock_protocol
        mock_hashiru_class.return_value = mock_hashiru
        
        # Mock repository analysis
        mock_hashiru.analyze_repository.return_value = {
            'total_lines': 5000,
            'languages': {'python': 4000, 'javascript': 1000},
            'recommended_agents': [
                {'agent': 'BEDROCK_UNIFIED', 'priority': 'critical', 'estimated_runtime': 600},
                {'agent': 'AUTONOMOUS_CODE_ANALYZER', 'priority': 'high', 'estimated_runtime': 480}
            ]
        }
        
        # Mock execution plan for AI agents
        mock_hashiru.create_execution_plan.return_value = {
            'tasks': [
                {
                    'agent': 'BEDROCK_UNIFIED',
                    'priority': 1,
                    'estimated_cost': 2.50,  # Higher cost for AI agent
                    'use_spot': True
                },
                {
                    'agent': 'AUTONOMOUS_CODE_ANALYZER',
                    'priority': 2,
                    'estimated_cost': 2.00,  # Higher cost for AI agent
                    'use_spot': True
                }
            ],
            'estimated_cost': 4.50,
            'estimated_duration': 1080,
            'optimizations': ['spot_instances', 'ai_model_optimization']
        }
        
        # Create event
        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'repository_url': 'https://github.com/test/repo',
                'branch': 'main',
                'priority': 'normal',
                'deadline_minutes': 60
            })
        }
        
        # Call handler
        response = lambda_handler(event, None)
        
        # Verify response
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert 'scan_id' in body
        assert body['status'] == 'initiated'
        assert body['estimated_cost'] == 4.50
        assert len(body['tasks']) == 2
        
        # Verify mocks were called
        mock_hashiru.analyze_repository.assert_called_once()
        mock_hashiru.create_execution_plan.assert_called_once()
    
    def test_missing_repository_url(self):
        """Test handling missing repository URL"""
        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'branch': 'main'  # Missing repository_url
            })
        }
        
        response = lambda_handler(event, None)
        
        assert response['statusCode'] == 400
        body = json.loads(response['body'])
        assert 'error' in body
        assert 'repository_url' in body['error']
    
    def test_invalid_json_body(self):
        """Test handling invalid JSON in body"""
        event = {
            'httpMethod': 'POST',
            'body': 'invalid json'
        }
        
        response = lambda_handler(event, None)
        
        assert response['statusCode'] == 400
        body = json.loads(response['body'])
        assert 'error' in body
    
    @patch('lambdas.ceo_agent.handler.HASHIRUCore')
    def test_repository_analysis_failure(self, mock_hashiru_class):
        """Test handling repository analysis failure"""
        mock_hashiru = MagicMock()
        mock_hashiru.analyze_repository.side_effect = Exception("Failed to clone repository")
        mock_hashiru_class.return_value = mock_hashiru
        
        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'repository_url': 'https://github.com/test/repo'
            })
        }
        
        response = lambda_handler(event, None)
        
        assert response['statusCode'] == 500
        body = json.loads(response['body'])
        assert 'error' in body
        assert 'Failed to clone repository' in body['error']
    
    @patch('lambdas.ceo_agent.handler.HASHIRUCore')
    @patch('lambdas.ceo_agent.handler.StrandsProtocol')
    def test_cost_limit_enforcement(self, mock_protocol_class, mock_hashiru_class):
        """Test cost limit enforcement with AI agents"""
        # Setup mocks
        mock_protocol = MagicMock()
        mock_hashiru = MagicMock()
        
        mock_protocol_class.return_value = mock_protocol
        mock_hashiru_class.return_value = mock_hashiru
        
        # Mock repository analysis
        mock_hashiru.analyze_repository.return_value = {
            'recommended_agents': [
                {'agent': 'BEDROCK_UNIFIED', 'priority': 'high', 'estimated_runtime': 3600},
                {'agent': 'AUTONOMOUS_THREAT_INTEL', 'priority': 'high', 'estimated_runtime': 2400}
            ]
        }
        
        # Mock execution plan exceeding cost limit (AI agents cost more)
        mock_hashiru.create_execution_plan.return_value = {
            'tasks': [
                {'agent': 'BEDROCK_UNIFIED', 'estimated_cost': 8.0},
                {'agent': 'AUTONOMOUS_THREAT_INTEL', 'estimated_cost': 7.0}
            ],
            'estimated_cost': 15.0,
            'estimated_duration': 6000
        }
        
        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'repository_url': 'https://github.com/test/repo',
                'cost_limit_usd': 10.0  # Limit is $10
            })
        }
        
        response = lambda_handler(event, None)
        
        # Should still succeed but with warning
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert 'warnings' in body
        assert any('exceeds cost limit' in w for w in body['warnings'])
    
    @patch('lambdas.ceo_agent.handler.HASHIRUCore')
    @patch('lambdas.ceo_agent.handler.StrandsProtocol')
    def test_all_ai_agents_triggered(self, mock_protocol_class, mock_hashiru_class):
        """Test triggering all AI agents for comprehensive analysis"""
        # Setup mocks
        mock_protocol = MagicMock()
        mock_hashiru = MagicMock()
        
        mock_protocol_class.return_value = mock_protocol
        mock_hashiru_class.return_value = mock_hashiru
        
        # Mock repository analysis recommending all AI agents
        mock_hashiru.analyze_repository.return_value = {
            'total_lines': 50000,
            'languages': {'python': 30000, 'javascript': 10000, 'terraform': 10000},
            'recommended_agents': [
                {'agent': 'BEDROCK_UNIFIED', 'priority': 'critical', 'estimated_runtime': 600},
                {'agent': 'AUTONOMOUS_CODE_ANALYZER', 'priority': 'high', 'estimated_runtime': 480},
                {'agent': 'AUTONOMOUS_THREAT_INTEL', 'priority': 'high', 'estimated_runtime': 300},
                {'agent': 'AUTONOMOUS_INFRA_SECURITY', 'priority': 'high', 'estimated_runtime': 360},
                {'agent': 'AUTONOMOUS_SUPPLY_CHAIN', 'priority': 'medium', 'estimated_runtime': 420},
                {'agent': 'AUTONOMOUS_DYNAMIC_TOOL_CREATION', 'priority': 'medium', 'estimated_runtime': 540}
            ]
        }
        
        # Mock execution plan with all AI agents
        mock_hashiru.create_execution_plan.return_value = {
            'tasks': [
                {'agent': 'BEDROCK_UNIFIED', 'priority': 1, 'estimated_cost': 2.50, 'use_spot': True},
                {'agent': 'AUTONOMOUS_CODE_ANALYZER', 'priority': 2, 'estimated_cost': 2.00, 'use_spot': True},
                {'agent': 'AUTONOMOUS_THREAT_INTEL', 'priority': 3, 'estimated_cost': 1.50, 'use_spot': True},
                {'agent': 'AUTONOMOUS_INFRA_SECURITY', 'priority': 4, 'estimated_cost': 1.80, 'use_spot': True},
                {'agent': 'AUTONOMOUS_SUPPLY_CHAIN', 'priority': 5, 'estimated_cost': 2.10, 'use_spot': True},
                {'agent': 'AUTONOMOUS_DYNAMIC_TOOL_CREATION', 'priority': 6, 'estimated_cost': 2.60, 'use_spot': True}
            ],
            'estimated_cost': 12.50,
            'estimated_duration': 2700,
            'optimizations': ['spot_instances', 'ai_model_optimization', 'parallel_execution']
        }
        
        event = {
            'httpMethod': 'POST',
            'body': json.dumps({
                'repository_url': 'https://github.com/test/large-repo',
                'branch': 'main',
                'priority': 'high',
                'deadline_minutes': 120
            })
        }
        
        response = lambda_handler(event, None)
        
        # Verify response
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert len(body['tasks']) == 6  # All AI agents
        assert body['estimated_cost'] == 12.50
        assert all(task['agent'].startswith('AUTONOMOUS_') or task['agent'] == 'BEDROCK_UNIFIED' 
                  for task in body['tasks'])


class TestCEOAgentHelpers:
    """Test helper functions in CEO Agent"""
    
    @patch('lambdas.ceo_agent.handler.boto3.client')
    def test_clone_repository_to_efs(self, mock_boto_client):
        """Test repository cloning to EFS"""
        from lambdas.ceo_agent.handler import clone_repository_to_efs
        
        # Mock successful clone
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            repo_path = clone_repository_to_efs(
                'https://github.com/test/repo',
                'main'
            )
            
            assert repo_path.startswith('/mnt/efs/repos/')
            mock_run.assert_called()
    
    @patch('lambdas.ceo_agent.handler.boto3.client')
    def test_cleanup_efs_repository(self, mock_boto_client):
        """Test EFS repository cleanup"""
        from lambdas.ceo_agent.handler import cleanup_efs_repository
        
        with patch('shutil.rmtree') as mock_rmtree:
            cleanup_efs_repository('/mnt/efs/repos/test-repo')
            mock_rmtree.assert_called_once_with('/mnt/efs/repos/test-repo')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])