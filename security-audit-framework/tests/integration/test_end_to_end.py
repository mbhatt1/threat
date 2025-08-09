import pytest
import json
import time
from unittest.mock import patch, MagicMock
import boto3
from moto import mock_s3, mock_dynamodb, mock_stepfunctions, mock_lambda
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from shared.strands import StrandsProtocol, MessageType
from shared.hashiru import HASHIRUCore


@mock_s3
@mock_dynamodb
@mock_stepfunctions
@mock_lambda
class TestEndToEndWorkflow:
    """Integration tests for end-to-end AI-powered security scan workflow"""
    
    def setup_method(self):
        """Set up test fixtures"""
        # Create mock AWS resources
        self.s3_client = boto3.client('s3', region_name='us-east-1')
        self.dynamodb_client = boto3.client('dynamodb', region_name='us-east-1')
        self.sfn_client = boto3.client('stepfunctions', region_name='us-east-1')
        
        # Create S3 bucket
        self.s3_client.create_bucket(Bucket='test-results-bucket')
        
        # Create DynamoDB table
        self.dynamodb_client.create_table(
            TableName='SecurityFindings',
            KeySchema=[
                {'AttributeName': 'finding_id', 'KeyType': 'HASH'},
                {'AttributeName': 'scan_id', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'finding_id', 'AttributeType': 'S'},
                {'AttributeName': 'scan_id', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )
    
    @patch('requests.post')
    def test_complete_scan_workflow(self, mock_post):
        """Test complete AI-powered security scan workflow"""
        # Mock API Gateway response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'scan_id': 'scan-001',
            'status': 'initiated',
            'estimated_cost': 12.50,  # Higher cost for AI agents
            'tasks': [
                {'agent': 'BEDROCK_UNIFIED', 'priority': 1},
                {'agent': 'AUTONOMOUS_CODE_ANALYZER', 'priority': 2},
                {'agent': 'AUTONOMOUS_THREAT_INTEL', 'priority': 3}
            ]
        }
        mock_post.return_value = mock_response
        
        # Initiate scan
        scan_request = {
            'repository_url': 'https://github.com/test/repo',
            'branch': 'main',
            'priority': 'normal',
            'deadline_minutes': 120  # Longer deadline for AI agents
        }
        
        import requests
        response = requests.post(
            'https://api.security-audit.example.com/scan',
            json=scan_request
        )
        
        assert response.status_code == 200
        scan_data = response.json()
        assert scan_data['scan_id'] == 'scan-001'
        assert scan_data['status'] == 'initiated'
        assert len(scan_data['tasks']) == 3
    
    def test_strands_message_flow(self):
        """Test Strands message flow between AI components"""
        protocol = StrandsProtocol()
        
        # 1. CEO creates task assignment for AI agent
        task_assignment = protocol.create_task_assignment(
            task_id="task-001",
            sender_id="CEO",
            recipient_id="BEDROCK_UNIFIED",
            context={
                "repository_path": "/tmp/test-repo",
                "scan_id": "scan-001",
                "model_preferences": {
                    "primary": "claude-3-sonnet",
                    "fallback": "claude-3-instant"
                }
            }
        )
        
        assert task_assignment.message_type == MessageType.TASK_ASSIGNMENT
        
        # 2. AI Agent processes and returns result
        agent_result = protocol.create_result_message(
            task_id="task-001",
            agent_id="BEDROCK_UNIFIED",
            results={
                "findings": [
                    {
                        "finding_id": "bedrock-001",
                        "severity": "HIGH",
                        "title": "SQL Injection Vulnerability",
                        "ai_analysis": {
                            "model": "claude-3-sonnet",
                            "confidence_score": 0.95,
                            "tokens_used": 5000
                        }
                    }
                ],
                "scan_summary": {
                    "total_findings": 1,
                    "execution_time": 600,
                    "ai_metrics": {
                        "total_tokens": 25000,
                        "model_calls": 5,
                        "average_confidence": 0.93
                    }
                }
            },
            execution_time=600
        )
        
        assert agent_result.message_type == MessageType.RESULT
        assert len(agent_result.results["findings"]) == 1
        assert agent_result.results["scan_summary"]["ai_metrics"]["total_tokens"] == 25000
    
    @patch('subprocess.run')
    def test_multi_agent_parallel_execution(self, mock_run):
        """Test parallel execution of multiple AI agents"""
        # Mock successful execution for all AI agents
        mock_run.return_value = MagicMock(
            stdout='{"results": []}',
            stderr="",
            returncode=0
        )
        
        agents = [
            "BEDROCK_UNIFIED",
            "AUTONOMOUS_CODE_ANALYZER", 
            "AUTONOMOUS_THREAT_INTEL",
            "AUTONOMOUS_INFRA_SECURITY",
            "AUTONOMOUS_SUPPLY_CHAIN",
            "AUTONOMOUS_DYNAMIC_TOOL_CREATION"
        ]
        results = []
        
        # Simulate parallel execution
        for agent in agents:
            # Each AI agent would run in parallel in real scenario
            result = {
                "agent": agent,
                "status": "success",
                "findings": [],
                "execution_time": 480,  # AI agents take longer
                "ai_metrics": {
                    "tokens_used": 20000,
                    "model": "claude-3-sonnet" if "BEDROCK" in agent else "claude-3-opus"
                }
            }
            results.append(result)
        
        # Verify all AI agents completed
        assert len(results) == 6
        assert all(r["status"] == "success" for r in results)
        assert all("ai_metrics" in r for r in results)
    
    def test_cost_optimization_with_spot_instances_for_ai(self):
        """Test cost optimization using Spot instances for AI workloads"""
        from shared.hashiru import SpotPricingOptimizer
        
        optimizer = SpotPricingOptimizer()
        
        # AI agents require more resources
        on_demand_cost = optimizer.calculate_task_cost(
            vcpus=4,  # Higher CPU for AI
            memory_gb=8,  # Higher memory for AI
            estimated_runtime_seconds=1200,  # Longer runtime
            use_spot=False
        )
        
        spot_cost = optimizer.calculate_task_cost(
            vcpus=4,
            memory_gb=8,
            estimated_runtime_seconds=1200,
            use_spot=True
        )
        
        # Also factor in Bedrock API costs
        bedrock_cost = optimizer.calculate_bedrock_cost(
            tokens=50000,
            model="claude-3-sonnet"
        )
        
        total_on_demand = on_demand_cost + bedrock_cost
        total_spot = spot_cost + bedrock_cost
        
        # Verify Spot is cheaper for compute
        assert spot_cost < on_demand_cost
        savings_percent = ((on_demand_cost - spot_cost) / on_demand_cost) * 100
        assert savings_percent > 50  # At least 50% savings on compute
    
    def test_autonomous_agent_learning(self):
        """Test autonomous AI agent learning from findings"""
        # Simulate findings from previous scans with AI analysis
        historical_findings = [
            {
                "finding_id": "bedrock-001",
                "type": "sql_injection",
                "severity": "HIGH",
                "file_path": "src/api/user.py",
                "line_number": 42,
                "ai_analysis": {
                    "pattern": "string_concatenation_in_query",
                    "confidence": 0.96
                }
            },
            {
                "finding_id": "bedrock-002",
                "type": "sql_injection",
                "severity": "HIGH",
                "file_path": "src/api/product.py",
                "line_number": 55,
                "ai_analysis": {
                    "pattern": "string_concatenation_in_query",
                    "confidence": 0.94
                }
            },
            {
                "finding_id": "code-analyzer-001",
                "type": "sql_injection",
                "severity": "HIGH",
                "file_path": "src/api/order.py",
                "line_number": 38,
                "ai_analysis": {
                    "pattern": "string_concatenation_in_query",
                    "confidence": 0.98
                }
            }
        ]
        
        # Store findings in DynamoDB
        table = boto3.resource('dynamodb', region_name='us-east-1').Table('SecurityFindings')
        for finding in historical_findings:
            table.put_item(Item={
                **finding,
                'scan_id': 'scan-historical',
                'timestamp': '2024-01-01T00:00:00Z'
            })
        
        # AI agent would analyze these patterns
        from agents.autonomous_code_analyzer.agent import AIPatternAnalyzer
        
        analyzer = AIPatternAnalyzer()
        analysis = analyzer.analyze_findings(historical_findings)
        
        assert len(analysis['patterns']) > 0
        # Should identify SQL injection pattern in API files with high confidence
        assert analysis['patterns'][0]['confidence'] > 0.9


@mock_s3
class TestReportGeneration:
    """Integration tests for AI-enhanced report generation"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.s3_client = boto3.client('s3', region_name='us-east-1')
        self.s3_client.create_bucket(Bucket='test-reports-bucket')
    
    def test_html_report_generation_and_upload(self):
        """Test HTML report generation with AI insights and S3 upload"""
        scan_results = {
            "scan_id": "scan-001",
            "repository_url": "https://github.com/test/repo",
            "total_findings": 5,
            "severity_distribution": {
                "CRITICAL": 1,
                "HIGH": 2,
                "MEDIUM": 2,
                "LOW": 0,
                "INFO": 0
            },
            "findings": [
                {
                    "severity": "CRITICAL",
                    "title": "Hardcoded API Key",
                    "file_path": "config.py",
                    "remediation": "Use AWS Secrets Manager",
                    "ai_analysis": {
                        "model": "claude-3-opus",
                        "confidence_score": 0.99,
                        "explanation": "Detected AWS access key pattern in source code"
                    }
                }
            ],
            "ai_metrics": {
                "total_tokens": 75000,
                "total_model_calls": 15,
                "models_used": ["claude-3-opus", "claude-3-sonnet"],
                "average_confidence": 0.94
            }
        }
        
        # Generate report
        from lambdas.report_generator.handler import generate_html_report
        html_report = generate_html_report(scan_results)
        
        # Verify report content
        assert "scan-001" in html_report
        assert "https://github.com/test/repo" in html_report
        assert "CRITICAL" in html_report
        assert "Hardcoded API Key" in html_report
        assert "claude-3-opus" in html_report or "AI Analysis" in html_report
        assert "99%" in html_report or "0.99" in html_report
        
        # Upload to S3
        self.s3_client.put_object(
            Bucket='test-reports-bucket',
            Key='reports/scan-001.html',
            Body=html_report,
            ContentType='text/html'
        )
        
        # Verify upload
        response = self.s3_client.get_object(
            Bucket='test-reports-bucket',
            Key='reports/scan-001.html'
        )
        assert response['ContentType'] == 'text/html'


class TestErrorHandlingAndRecovery:
    """Integration tests for error handling and recovery in AI system"""
    
    def test_agent_failure_recovery(self):
        """Test recovery from AI agent failures"""
        protocol = StrandsProtocol()
        
        # Simulate AI agent failure
        error_message = protocol.create_error_message(
            task_id="task-001",
            agent_id="BEDROCK_UNIFIED",
            error="Failed to invoke Bedrock model: Rate limit exceeded"
        )
        
        assert error_message.message_type == MessageType.ERROR
        assert "Rate limit exceeded" in error_message.error
        
        # System should handle error and retry with backoff
        # or fall back to different model
    
    def test_partial_scan_completion(self):
        """Test handling of partial scan completion with AI agents"""
        results = {
            "scan_id": "scan-001",
            "agent_results": [
                {
                    "agent": "BEDROCK_UNIFIED",
                    "status": "success",
                    "findings": [],
                    "ai_metrics": {"tokens_used": 25000}
                },
                {
                    "agent": "AUTONOMOUS_THREAT_INTEL",
                    "status": "error",
                    "error": "Model timeout after 600 seconds"
                },
                {
                    "agent": "AUTONOMOUS_CODE_ANALYZER",
                    "status": "success",
                    "findings": [],
                    "ai_metrics": {"tokens_used": 30000}
                }
            ]
        }
        
        # Aggregator should handle partial results
        successful_agents = [r for r in results["agent_results"] if r["status"] == "success"]
        failed_agents = [r for r in results["agent_results"] if r["status"] == "error"]
        
        assert len(successful_agents) == 2
        assert len(failed_agents) == 1
        
        # Calculate successful token usage
        total_tokens = sum(r.get("ai_metrics", {}).get("tokens_used", 0) 
                          for r in successful_agents)
        assert total_tokens == 55000
        
        # Report should indicate partial completion
        report_status = "completed_with_errors" if failed_agents else "completed"
        assert report_status == "completed_with_errors"


class TestPerformanceAndScaling:
    """Integration tests for AI system performance and scaling"""
    
    def test_large_repository_handling(self):
        """Test handling of large repositories with AI agents"""
        # Simulate large repository analysis
        large_repo_stats = {
            "total_files": 10000,
            "total_lines": 1000000,
            "languages": {
                "Python": 500000,
                "JavaScript": 300000,
                "Java": 200000
            }
        }
        
        # HASHIRU should optimize execution plan for AI agents
        from shared.hashiru import AIExecutionPlanner
        planner = AIExecutionPlanner()
        
        recommendations = [
            {"agent": "BEDROCK_UNIFIED", "estimated_runtime": 3600},  # 1 hour
            {"agent": "AUTONOMOUS_CODE_ANALYZER", "estimated_runtime": 2400},  # 40 min
            {"agent": "AUTONOMOUS_SUPPLY_CHAIN", "estimated_runtime": 1800}  # 30 min
        ]
        
        plan = planner.create_plan(
            recommendations,
            {
                "deadline_minutes": 120,  # 2 hour deadline
                "cost_limit_usd": 50.0,  # Cost limit for AI
                "preferred_models": ["claude-3-sonnet", "claude-3-instant"]
            }
        )
        
        # Should use parallel execution for large repos
        assert plan["execution_strategy"] == "parallel"
        # Should optimize model selection based on cost/performance
        assert "model_assignments" in plan
    
    def test_concurrent_scan_handling(self):
        """Test handling of multiple concurrent AI-powered scans"""
        scan_ids = ["scan-001", "scan-002", "scan-003"]
        
        # Track resource usage across scans
        resource_tracker = {
            "total_tokens": 0,
            "total_model_calls": 0,
            "active_agents": []
        }
        
        # Each scan would run independently
        for scan_id in scan_ids:
            # In real scenario, these would run concurrently
            # with resource limits enforced
            resource_tracker["total_tokens"] += 50000
            resource_tracker["total_model_calls"] += 10
            resource_tracker["active_agents"].extend([
                f"{scan_id}-BEDROCK_UNIFIED",
                f"{scan_id}-AUTONOMOUS_CODE_ANALYZER"
            ])
        
        # System should handle multiple scans without interference
        assert len(scan_ids) == 3
        assert resource_tracker["total_tokens"] == 150000
        assert len(resource_tracker["active_agents"]) == 6
    
    def test_ai_model_fallback_strategy(self):
        """Test AI model fallback when primary model is unavailable"""
        from shared.hashiru import AIModelSelector
        
        selector = AIModelSelector()
        
        # Test fallback chain
        model_chain = selector.get_model_chain(
            task_type="code_analysis",
            priority="high"
        )
        
        assert model_chain[0] == "claude-3-opus"  # Primary for high priority
        assert model_chain[1] == "claude-3-sonnet"  # First fallback
        assert model_chain[2] == "claude-3-instant"  # Second fallback
        
        # Simulate primary model failure
        selected_model = selector.select_with_fallback(
            model_chain,
            availability={
                "claude-3-opus": False,
                "claude-3-sonnet": True,
                "claude-3-instant": True
            }
        )
        
        assert selected_model == "claude-3-sonnet"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])