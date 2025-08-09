import pytest
import json
from unittest.mock import patch, MagicMock
from datetime import datetime
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from lambdas.aggregator.handler import lambda_handler, aggregate_findings, calculate_severity_distribution


class TestAggregatorLambda:
    """Test cases for Aggregator Lambda function"""
    
    def test_successful_aggregation(self):
        """Test successful aggregation of AI agent results"""
        event = {
            'scan_id': 'scan-001',
            'agent_results': [
                {
                    'agent': 'BEDROCK_UNIFIED',
                    'status': 'success',
                    'findings': [
                        {
                            'finding_id': 'bedrock-001',
                            'type': 'sql_injection',
                            'severity': 'HIGH',
                            'confidence': 'HIGH',
                            'title': 'SQL Injection Vulnerability',
                            'file_path': 'src/api.py',
                            'ai_analysis': {
                                'model': 'claude-3-sonnet',
                                'confidence_score': 0.95
                            }
                        },
                        {
                            'finding_id': 'bedrock-002',
                            'type': 'xss',
                            'severity': 'MEDIUM',
                            'confidence': 'MEDIUM',
                            'title': 'Cross-Site Scripting',
                            'file_path': 'src/views.py',
                            'ai_analysis': {
                                'model': 'claude-3-sonnet',
                                'confidence_score': 0.85
                            }
                        }
                    ],
                    'execution_time': 600
                },
                {
                    'agent': 'AUTONOMOUS_CODE_ANALYZER',
                    'status': 'success',
                    'findings': [
                        {
                            'finding_id': 'code-analyzer-001',
                            'type': 'hardcoded_secret',
                            'severity': 'CRITICAL',
                            'confidence': 'HIGH',
                            'title': 'Hardcoded API Key Detected',
                            'file_path': 'config.py',
                            'ai_analysis': {
                                'model': 'claude-3-opus',
                                'confidence_score': 0.99,
                                'semantic_context': 'API key exposed in configuration'
                            }
                        }
                    ],
                    'execution_time': 480
                }
            ]
        }
        
        response = lambda_handler(event, None)
        
        # Verify response structure
        assert response['scan_id'] == 'scan-001'
        assert response['status'] == 'completed'
        assert response['total_findings'] == 3
        assert response['total_execution_time'] == 1080
        
        # Verify severity distribution
        assert response['severity_distribution']['CRITICAL'] == 1
        assert response['severity_distribution']['HIGH'] == 1
        assert response['severity_distribution']['MEDIUM'] == 1
        
        # Verify agent summary
        assert len(response['agent_summary']) == 2
        assert response['agent_summary']['BEDROCK_UNIFIED']['findings_count'] == 2
        assert response['agent_summary']['AUTONOMOUS_CODE_ANALYZER']['findings_count'] == 1
    
    def test_aggregation_with_failed_agents(self):
        """Test aggregation when some AI agents fail"""
        event = {
            'scan_id': 'scan-002',
            'agent_results': [
                {
                    'agent': 'BEDROCK_UNIFIED',
                    'status': 'success',
                    'findings': [
                        {
                            'finding_id': 'bedrock-001',
                            'severity': 'HIGH',
                            'title': 'Security Issue',
                            'ai_analysis': {
                                'model': 'claude-3-sonnet',
                                'confidence_score': 0.92
                            }
                        }
                    ],
                    'execution_time': 600
                },
                {
                    'agent': 'AUTONOMOUS_THREAT_INTEL',
                    'status': 'error',
                    'error': 'Failed to analyze threat patterns - model timeout',
                    'execution_time': 300
                }
            ]
        }
        
        response = lambda_handler(event, None)
        
        # Should still complete with partial results
        assert response['status'] == 'completed_with_errors'
        assert response['total_findings'] == 1
        assert len(response['errors']) == 1
        assert response['errors'][0]['agent'] == 'AUTONOMOUS_THREAT_INTEL'
    
    def test_empty_results(self):
        """Test aggregation with no findings from AI agents"""
        event = {
            'scan_id': 'scan-003',
            'agent_results': [
                {
                    'agent': 'BEDROCK_UNIFIED',
                    'status': 'success',
                    'findings': [],
                    'execution_time': 600
                }
            ]
        }
        
        response = lambda_handler(event, None)
        
        assert response['status'] == 'completed'
        assert response['total_findings'] == 0
        assert response['severity_distribution'] == {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
    
    def test_deduplicate_findings(self):
        """Test deduplication of similar findings across AI agents"""
        event = {
            'scan_id': 'scan-004',
            'agent_results': [
                {
                    'agent': 'BEDROCK_UNIFIED',
                    'status': 'success',
                    'findings': [
                        {
                            'finding_id': 'bedrock-001',
                            'type': 'sql_injection',
                            'severity': 'HIGH',
                            'file_path': 'src/api.py',
                            'line_number': 42,
                            'ai_analysis': {
                                'model': 'claude-3-sonnet',
                                'confidence_score': 0.94
                            }
                        }
                    ]
                },
                {
                    'agent': 'AUTONOMOUS_CODE_ANALYZER',
                    'status': 'success',
                    'findings': [
                        {
                            'finding_id': 'code-analyzer-001',
                            'type': 'sql_injection',  # Same type
                            'severity': 'HIGH',
                            'file_path': 'src/api.py',  # Same file
                            'line_number': 42,  # Same line
                            'ai_analysis': {
                                'model': 'claude-3-opus',
                                'confidence_score': 0.96
                            }
                        }
                    ]
                }
            ]
        }
        
        response = lambda_handler(event, None)
        
        # Should deduplicate similar findings
        assert response['total_findings'] == 1
        assert response['deduplication_count'] == 1
    
    def test_all_ai_agents_results(self):
        """Test aggregation of all AI agents"""
        event = {
            'scan_id': 'scan-005',
            'agent_results': [
                {
                    'agent': 'BEDROCK_UNIFIED',
                    'status': 'success',
                    'findings': [{'severity': 'HIGH', 'title': 'Generic Security Issue'}],
                    'execution_time': 600
                },
                {
                    'agent': 'AUTONOMOUS_CODE_ANALYZER',
                    'status': 'success',
                    'findings': [{'severity': 'CRITICAL', 'title': 'Code Quality Issue'}],
                    'execution_time': 480
                },
                {
                    'agent': 'AUTONOMOUS_THREAT_INTEL',
                    'status': 'success',
                    'findings': [{'severity': 'HIGH', 'title': 'Potential Threat Pattern'}],
                    'execution_time': 300
                },
                {
                    'agent': 'AUTONOMOUS_INFRA_SECURITY',
                    'status': 'success',
                    'findings': [{'severity': 'MEDIUM', 'title': 'Infrastructure Misconfiguration'}],
                    'execution_time': 360
                },
                {
                    'agent': 'AUTONOMOUS_SUPPLY_CHAIN',
                    'status': 'success',
                    'findings': [{'severity': 'HIGH', 'title': 'Vulnerable Dependency'}],
                    'execution_time': 420
                },
                {
                    'agent': 'AUTONOMOUS_DYNAMIC_TOOL_CREATION',
                    'status': 'success',
                    'findings': [{'severity': 'LOW', 'title': 'Custom Check Finding'}],
                    'execution_time': 540
                }
            ]
        }
        
        response = lambda_handler(event, None)
        
        assert response['status'] == 'completed'
        assert response['total_findings'] == 6
        assert len(response['agent_summary']) == 6
        assert response['total_execution_time'] == 2700


class TestAggregatorHelpers:
    """Test helper functions in Aggregator"""
    
    def test_aggregate_findings(self):
        """Test finding aggregation logic for AI agents"""
        agent_results = [
            {
                'agent': 'BEDROCK_UNIFIED',
                'findings': [
                    {'severity': 'HIGH'},
                    {'severity': 'MEDIUM'}
                ]
            },
            {
                'agent': 'AUTONOMOUS_THREAT_INTEL',
                'findings': [
                    {'severity': 'CRITICAL'}
                ]
            }
        ]
        
        all_findings = aggregate_findings(agent_results)
        
        assert len(all_findings) == 3
        severities = [f['severity'] for f in all_findings]
        assert 'CRITICAL' in severities
        assert 'HIGH' in severities
        assert 'MEDIUM' in severities
    
    def test_calculate_severity_distribution(self):
        """Test severity distribution calculation"""
        findings = [
            {'severity': 'CRITICAL'},
            {'severity': 'HIGH'},
            {'severity': 'HIGH'},
            {'severity': 'MEDIUM'},
            {'severity': 'LOW'},
            {'severity': 'LOW'},
            {'severity': 'LOW'}
        ]
        
        distribution = calculate_severity_distribution(findings)
        
        assert distribution['CRITICAL'] == 1
        assert distribution['HIGH'] == 2
        assert distribution['MEDIUM'] == 1
        assert distribution['LOW'] == 3
        assert distribution['INFO'] == 0
    
    def test_prioritize_findings(self):
        """Test finding prioritization with AI confidence scores"""
        findings = [
            {'severity': 'LOW', 'confidence': 'LOW', 'ai_analysis': {'confidence_score': 0.6}},
            {'severity': 'CRITICAL', 'confidence': 'HIGH', 'ai_analysis': {'confidence_score': 0.99}},
            {'severity': 'HIGH', 'confidence': 'MEDIUM', 'ai_analysis': {'confidence_score': 0.85}},
            {'severity': 'MEDIUM', 'confidence': 'HIGH', 'ai_analysis': {'confidence_score': 0.95}},
            {'severity': 'HIGH', 'confidence': 'HIGH', 'ai_analysis': {'confidence_score': 0.97}}
        ]
        
        # Assuming there's a prioritize_findings function
        from lambdas.aggregator.handler import prioritize_findings
        prioritized = prioritize_findings(findings)
        
        # Critical with highest AI confidence should be first
        assert prioritized[0]['severity'] == 'CRITICAL'
        assert prioritized[0]['confidence'] == 'HIGH'
        assert prioritized[0]['ai_analysis']['confidence_score'] == 0.99
        
        # Low severity with low confidence should be last
        assert prioritized[-1]['severity'] == 'LOW'
        assert prioritized[-1]['confidence'] == 'LOW'


class TestAggregatorMetrics:
    """Test metrics calculation in Aggregator"""
    
    def test_calculate_metrics(self):
        """Test metrics calculation for AI agents"""
        from lambdas.aggregator.handler import calculate_metrics
        
        agent_results = [
            {
                'agent': 'BEDROCK_UNIFIED',
                'status': 'success',
                'findings': [
                    {'severity': 'HIGH'},
                    {'severity': 'MEDIUM'}
                ],
                'execution_time': 600
            },
            {
                'agent': 'AUTONOMOUS_CODE_ANALYZER',
                'status': 'success',
                'findings': [
                    {'severity': 'CRITICAL'}
                ],
                'execution_time': 480
            }
        ]
        
        metrics = calculate_metrics(agent_results)
        
        assert metrics['total_agents'] == 2
        assert metrics['successful_agents'] == 2
        assert metrics['failed_agents'] == 0
        assert metrics['total_execution_time'] == 1080
        assert metrics['average_findings_per_agent'] == 1.5
        assert metrics['critical_findings_ratio'] == 1/3
    
    def test_calculate_ai_metrics(self):
        """Test AI-specific metrics calculation"""
        from lambdas.aggregator.handler import calculate_ai_metrics
        
        agent_results = [
            {
                'agent': 'BEDROCK_UNIFIED',
                'status': 'success',
                'ai_metrics': {
                    'tokens_used': 15000,
                    'model_calls': 5,
                    'average_confidence': 0.92
                }
            },
            {
                'agent': 'AUTONOMOUS_CODE_ANALYZER',
                'status': 'success',
                'ai_metrics': {
                    'tokens_used': 20000,
                    'model_calls': 8,
                    'average_confidence': 0.95
                }
            }
        ]
        
        ai_metrics = calculate_ai_metrics(agent_results)
        
        assert ai_metrics['total_tokens_used'] == 35000
        assert ai_metrics['total_model_calls'] == 13
        assert ai_metrics['average_confidence'] == 0.935


if __name__ == "__main__":
    pytest.main([__file__, "-v"])