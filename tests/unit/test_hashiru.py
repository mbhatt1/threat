import pytest
from unittest.mock import patch, MagicMock, call
from datetime import datetime, timedelta
import json
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from shared.hashiru import (
    HASHIRUCore, AWSPricingClient, SpotPricingOptimizer, 
    RepositoryAnalyzer, ExecutionPlanner
)


class TestHASHIRUCore:
    """Test cases for HASHIRUCore with AI-powered agents"""
    
    @patch('shared.hashiru.boto3.client')
    def test_initialization(self, mock_boto_client):
        """Test HASHIRUCore initialization"""
        core = HASHIRUCore(region='us-east-1')
        
        assert core.region == 'us-east-1'
        assert core.pricing_client is not None
        assert core.spot_optimizer is not None
        assert core.execution_planner is not None
    
    @patch('shared.hashiru.RepositoryAnalyzer')
    def test_analyze_repository(self, mock_analyzer_class):
        """Test repository analysis for AI agents"""
        # Setup mock
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {
            'total_lines': 1000,
            'languages': {'python': 800, 'javascript': 200},
            'recommended_agents': [
                {'agent': 'BEDROCK_UNIFIED', 'priority': 'critical'},
                {'agent': 'AUTONOMOUS_CODE_ANALYZER', 'priority': 'high'},
                {'agent': 'AUTONOMOUS_THREAT_INTEL', 'priority': 'high'}
            ]
        }
        mock_analyzer_class.return_value = mock_analyzer
        
        core = HASHIRUCore()
        result = core.analyze_repository('/path/to/repo')
        
        assert result['total_lines'] == 1000
        assert 'python' in result['languages']
        assert len(result['recommended_agents']) == 3
        assert result['recommended_agents'][0]['agent'] == 'BEDROCK_UNIFIED'
        mock_analyzer.analyze.assert_called_once()
    
    @patch('shared.hashiru.ExecutionPlanner')
    def test_create_execution_plan(self, mock_planner_class):
        """Test execution plan creation for AI agents"""
        mock_planner = MagicMock()
        mock_plan = {
            'tasks': [
                {'agent': 'BEDROCK_UNIFIED', 'priority': 1},
                {'agent': 'AUTONOMOUS_SUPPLY_CHAIN', 'priority': 2}
            ],
            'estimated_cost': 15.50,  # AI agents cost more
            'estimated_duration': 1800,  # AI agents take longer
            'execution_strategy': 'parallel'  # All AI agents run in parallel
        }
        mock_planner.create_plan.return_value = mock_plan
        mock_planner_class.return_value = mock_planner
        
        core = HASHIRUCore()
        context = {'repository_url': 'https://github.com/test/repo'}
        
        plan = core.create_execution_plan(
            repository_analysis={'recommended_agents': []},
            task_context=context
        )
        
        assert plan['estimated_cost'] == 15.50
        assert len(plan['tasks']) == 2
        assert plan['execution_strategy'] == 'parallel'
        mock_planner.create_plan.assert_called_once()


class TestAWSPricingClient:
    """Test cases for AWSPricingClient"""
    
    @patch('shared.hashiru.boto3.client')
    def test_get_fargate_pricing(self, mock_boto_client):
        """Test Fargate pricing retrieval for AI agents"""
        # Mock pricing API response
        mock_pricing = MagicMock()
        mock_pricing.get_products.return_value = {
            'PriceList': [json.dumps({
                'product': {'attributes': {'usagetype': 'USE1-Fargate-vCPU-Hours:perCPU'}},
                'terms': {
                    'OnDemand': {
                        'test_sku': {
                            'priceDimensions': {
                                'test_dim': {
                                    'pricePerUnit': {'USD': '0.04048'}
                                }
                            }
                        }
                    }
                }
            })]
        }
        mock_boto_client.return_value = mock_pricing
        
        client = AWSPricingClient()
        # AI agents need more resources
        pricing = client.get_fargate_pricing(vcpus=4, memory_gb=8)
        
        assert 'vcpu_per_hour' in pricing
        assert 'memory_gb_per_hour' in pricing
        assert pricing['vcpu_per_hour'] > 0
    
    @patch('shared.hashiru.boto3.client')
    def test_get_bedrock_pricing(self, mock_boto_client):
        """Test Bedrock pricing retrieval"""
        mock_pricing = MagicMock()
        # Bedrock pricing is per 1000 tokens
        mock_pricing.get_products.return_value = {
            'PriceList': [json.dumps({
                'product': {'attributes': {'modelId': 'anthropic.claude-3-sonnet'}},
                'terms': {
                    'OnDemand': {
                        'test_sku': {
                            'priceDimensions': {
                                'test_dim': {
                                    'pricePerUnit': {'USD': '0.003'}  # Per 1K input tokens
                                }
                            }
                        }
                    }
                }
            })]
        }
        mock_boto_client.return_value = mock_pricing
        
        client = AWSPricingClient()
        pricing = client.get_bedrock_pricing(model='claude-3-sonnet')
        
        assert 'per_1k_input_tokens' in pricing
        assert 'per_1k_output_tokens' in pricing
        assert pricing['per_1k_input_tokens'] > 0


class TestSpotPricingOptimizer:
    """Test cases for SpotPricingOptimizer"""
    
    def test_calculate_spot_savings_for_ai_agents(self):
        """Test Spot savings calculation for AI workloads"""
        optimizer = SpotPricingOptimizer()
        
        # AI agents need more resources
        cost = optimizer.calculate_task_cost(
            vcpus=4,
            memory_gb=8,
            estimated_runtime_seconds=1800,  # 30 minutes
            use_spot=True
        )
        
        on_demand_cost = optimizer.calculate_task_cost(
            vcpus=4,
            memory_gb=8,
            estimated_runtime_seconds=1800,
            use_spot=False
        )
        
        # Spot should be significantly cheaper
        assert cost < on_demand_cost
        assert cost < on_demand_cost * 0.5  # At least 50% savings
    
    def test_should_not_use_spot_for_ai_agents(self):
        """Test that AI agents don't use Spot due to interruption risk"""
        optimizer = SpotPricingOptimizer()
        
        # AI agents are always critical due to long processing times
        use_spot = optimizer.should_use_spot(
            task_priority='ai_agent',
            deadline_minutes=120,
            max_interruption_tolerance=0.01  # Very low tolerance
        )
        
        assert use_spot is False


class TestRepositoryAnalyzer:
    """Test cases for RepositoryAnalyzer with AI agents"""
    
    @patch('shared.hashiru.subprocess.run')
    @patch('os.walk')
    def test_analyze_recommends_ai_agents(self, mock_walk, mock_subprocess):
        """Test repository analysis recommends AI agents"""
        # Mock cloc output
        cloc_output = {
            "Python": {"nFiles": 10, "code": 1000},
            "JavaScript": {"nFiles": 5, "code": 500}
        }
        mock_subprocess.return_value = MagicMock(
            stdout=json.dumps(cloc_output),
            returncode=0
        )
        
        # Mock file walk
        mock_walk.return_value = [
            ('/repo', ['src'], ['README.md']),
            ('/repo/src', [], ['app.py', 'config.py'])
        ]
        
        analyzer = RepositoryAnalyzer('/repo')
        result = analyzer.analyze()
        
        assert 'languages' in result
        assert 'recommended_agents' in result
        
        # Should recommend AI agents
        agent_types = [r['agent'] for r in result['recommended_agents']]
        assert 'BEDROCK_UNIFIED' in agent_types
        assert any('AUTONOMOUS' in agent for agent in agent_types)
    
    def test_recommend_all_ai_agents_for_comprehensive_scan(self):
        """Test that all AI agents are recommended for comprehensive scanning"""
        analyzer = RepositoryAnalyzer('/repo')
        analyzer.analysis_results = {
            'total_lines': 10000,  # Large repo
            'languages': {'python': 5000, 'javascript': 3000, 'terraform': 2000},
            'security_patterns': {
                'has_dependencies': True,
                'has_infrastructure': True,
                'has_containers': True
            }
        }
        
        recommendations = analyzer._recommend_agents()
        
        # Should recommend all AI agents
        agent_types = [r['agent'] for r in recommendations]
        expected_agents = [
            'BEDROCK_UNIFIED',
            'AUTONOMOUS_DYNAMIC',
            'AUTONOMOUS_CODE_ANALYZER',
            'AUTONOMOUS_THREAT_INTEL',
            'AUTONOMOUS_INFRA_SECURITY',
            'AUTONOMOUS_SUPPLY_CHAIN'
        ]
        
        for agent in expected_agents:
            assert agent in agent_types
        
        # All should be high or critical priority
        for rec in recommendations:
            assert rec['priority'] in ['critical', 'high']
    
    def test_estimate_runtime_for_ai_agents(self):
        """Test runtime estimation for AI agents"""
        analyzer = RepositoryAnalyzer('/repo')
        analyzer.analysis_results = {'total_lines': 10000}
        
        # AI agents take longer than traditional tools
        runtime = analyzer._estimate_runtime('BEDROCK_UNIFIED')
        assert runtime >= 600  # At least 10 minutes
        assert runtime <= 3600  # Max 1 hour
        
        # Different AI agents have different runtimes
        code_analyzer_runtime = analyzer._estimate_runtime('AUTONOMOUS_CODE_ANALYZER')
        threat_intel_runtime = analyzer._estimate_runtime('AUTONOMOUS_THREAT_INTEL')
        
        # Code analyzer should take longer due to deep analysis
        assert code_analyzer_runtime >= threat_intel_runtime


class TestExecutionPlanner:
    """Test cases for ExecutionPlanner with AI agents"""
    
    def test_create_plan_all_parallel(self):
        """Test that all AI agents run in parallel"""
        planner = ExecutionPlanner()
        
        recommendations = [
            {'agent': 'BEDROCK_UNIFIED', 'priority': 'critical', 'estimated_runtime': 1800},
            {'agent': 'AUTONOMOUS_CODE_ANALYZER', 'priority': 'high', 'estimated_runtime': 2400},
            {'agent': 'AUTONOMOUS_THREAT_INTEL', 'priority': 'high', 'estimated_runtime': 1200},
            {'agent': 'AUTONOMOUS_SUPPLY_CHAIN', 'priority': 'high', 'estimated_runtime': 900}
        ]
        
        context = {
            'priority': 'normal',
            'deadline_minutes': 60
        }
        
        plan = planner.create_plan(recommendations, context)
        
        assert 'tasks' in plan
        assert 'estimated_cost' in plan
        assert 'estimated_duration' in plan
        assert 'execution_strategy' in plan
        
        # All AI agents should run in parallel
        assert plan['execution_strategy'] == 'parallel'
        assert len(plan['tasks']) == 4
        
        # Duration should be the max of all agents, not the sum
        assert plan['estimated_duration'] == 2400  # Max runtime
    
    def test_create_plan_cost_estimation(self):
        """Test cost estimation for AI agents"""
        planner = ExecutionPlanner()
        
        recommendations = [
            {'agent': 'BEDROCK_UNIFIED', 'priority': 'critical', 'estimated_runtime': 1800},
            {'agent': 'AUTONOMOUS_CODE_ANALYZER', 'priority': 'high', 'estimated_runtime': 1800}
        ]
        
        context = {'priority': 'normal'}
        
        plan = planner.create_plan(recommendations, context)
        
        # AI agents cost more due to:
        # 1. Higher compute requirements (4 vCPU, 8GB RAM)
        # 2. Bedrock API costs
        assert plan['estimated_cost'] > 10.0  # Should be significant
        assert plan['estimated_cost'] < 100.0  # But not excessive
    
    def test_create_plan_with_ai_agent_whitelist(self):
        """Test execution plan with AI agent whitelist"""
        planner = ExecutionPlanner()
        
        recommendations = [
            {'agent': 'BEDROCK_UNIFIED', 'priority': 'critical', 'estimated_runtime': 1800},
            {'agent': 'AUTONOMOUS_CODE_ANALYZER', 'priority': 'high', 'estimated_runtime': 2400},
            {'agent': 'AUTONOMOUS_SUPPLY_CHAIN', 'priority': 'high', 'estimated_runtime': 900}
        ]
        
        context = {
            'agents_whitelist': ['BEDROCK_UNIFIED', 'AUTONOMOUS_SUPPLY_CHAIN']
        }
        
        plan = planner.create_plan(recommendations, context)
        
        # Only whitelisted AI agents should be included
        agent_types = [task['agent'] for task in plan['tasks']]
        assert 'BEDROCK_UNIFIED' in agent_types
        assert 'AUTONOMOUS_SUPPLY_CHAIN' in agent_types
        assert 'AUTONOMOUS_CODE_ANALYZER' not in agent_types
    
    def test_optimize_for_cost_vs_speed(self):
        """Test optimization strategies for AI agents"""
        planner = ExecutionPlanner()
        
        recommendations = [
            {'agent': 'BEDROCK_UNIFIED', 'priority': 'critical', 'estimated_runtime': 1800},
            {'agent': 'AUTONOMOUS_CODE_ANALYZER', 'priority': 'medium', 'estimated_runtime': 2400},
            {'agent': 'AUTONOMOUS_THREAT_INTEL', 'priority': 'low', 'estimated_runtime': 1200}
        ]
        
        # Optimize for cost - should exclude low priority agents
        cost_optimized_plan = planner.create_plan(
            recommendations, 
            {'optimize_for': 'cost', 'budget_limit': 20.0}
        )
        
        # Should exclude low priority agents to save cost
        assert len(cost_optimized_plan['tasks']) < len(recommendations)
        
        # Optimize for thoroughness - should include all agents
        thorough_plan = planner.create_plan(
            recommendations,
            {'optimize_for': 'thoroughness'}
        )
        
        assert len(thorough_plan['tasks']) == len(recommendations)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])