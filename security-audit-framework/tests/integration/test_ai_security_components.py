"""
Integration tests for AI Security Components
Tests the newly added AI security features
"""
import pytest
import asyncio
import json
from unittest.mock import Mock, patch, AsyncMock
import sys
import os

# Add the source directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from ai_models.sql_injection_detector import SQLInjectionDetector
from ai_models.threat_intelligence import AISecurityIntelligence
from ai_models.root_cause_analyzer import AIRootCauseAnalyzer
from ai_models.pure_ai_detector import PureAIVulnerabilityDetector
from ai_models.ai_security_sandbox import AISecuritySandbox
from shared.ai_orchestrator import AIOrchestrator


class TestAISecurityComponents:
    """Test suite for AI Security Components"""
    
    @pytest.fixture
    def mock_bedrock_client(self):
        """Mock Bedrock client for testing"""
        mock = Mock()
        mock.invoke_model.return_value = {
            'body': Mock(read=Mock(return_value=json.dumps({
                'content': [{
                    'text': json.dumps({
                        'analysis': 'test analysis',
                        'confidence': 0.95,
                        'vulnerabilities': []
                    })
                }]
            }).encode()))
        }
        return mock
    
    @pytest.fixture
    def mock_dynamodb_client(self):
        """Mock DynamoDB client for testing"""
        return Mock()
    
    @pytest.fixture
    def mock_s3_client(self):
        """Mock S3 client for testing"""
        return Mock()
    
    @pytest.mark.asyncio
    async def test_sql_injection_detector(self, mock_bedrock_client):
        """Test SQL Injection Detector"""
        detector = SQLInjectionDetector(bedrock_client=mock_bedrock_client)
        
        # Test with potentially malicious query
        result = await detector.analyze_query(
            "SELECT * FROM users WHERE id = '1' OR '1'='1'",
            context={'application': 'test_app'}
        )
        
        assert 'risk_score' in result
        assert 'vulnerabilities' in result
        assert 'recommendations' in result
        assert 'ml_confidence' in result
    
    @pytest.mark.asyncio
    async def test_threat_intelligence(self, mock_bedrock_client, mock_dynamodb_client):
        """Test AI Security Intelligence"""
        intelligence = AISecurityIntelligence(
            bedrock_client=mock_bedrock_client,
            dynamodb_client=mock_dynamodb_client
        )
        
        # Test threat analysis
        findings = [
            {
                'type': 'SQL_INJECTION',
                'severity': 'HIGH',
                'description': 'SQL injection vulnerability found'
            }
        ]
        
        result = await intelligence.analyze_threats(
            findings=findings,
            scan_id='test-scan-123'
        )
        
        assert 'threat_assessment' in result
        assert 'predicted_exploits' in result
        assert 'mitigation_priority' in result
        assert 'attack_patterns' in result
    
    @pytest.mark.asyncio
    async def test_root_cause_analyzer(self, mock_bedrock_client):
        """Test AI Root Cause Analyzer"""
        analyzer = AIRootCauseAnalyzer(bedrock_client=mock_bedrock_client)
        
        # Test root cause analysis
        incidents = [
            {
                'type': 'SECURITY_BREACH',
                'timestamp': '2024-01-01T00:00:00Z',
                'details': 'Unauthorized access detected'
            }
        ]
        
        result = await analyzer.analyze_incidents(
            incidents=incidents,
            historical_data=[]
        )
        
        assert 'root_causes' in result
        assert 'contributing_factors' in result
        assert 'prevention_measures' in result
        assert 'incident_timeline' in result
    
    @pytest.mark.asyncio
    async def test_pure_ai_detector(self, mock_bedrock_client):
        """Test Pure AI Vulnerability Detector"""
        detector = PureAIVulnerabilityDetector(bedrock_client=mock_bedrock_client)
        
        # Test with sample code
        code_sample = """
        def get_user(user_id):
            query = f"SELECT * FROM users WHERE id = {user_id}"
            return db.execute(query)
        """
        
        result = await detector.detect_vulnerabilities(
            code=code_sample,
            language='python'
        )
        
        assert 'vulnerabilities' in result
        assert 'ai_confidence' in result
        assert 'analysis_passes' in result
        assert result['analysis_passes'] == 4  # 4-pass analysis
    
    @pytest.mark.asyncio
    async def test_ai_security_sandbox(self, mock_bedrock_client):
        """Test AI Security Sandbox"""
        sandbox = AISecuritySandbox(bedrock_client=mock_bedrock_client)
        
        # Test sandbox execution
        test_scenario = {
            'vulnerability_type': 'XSS',
            'payload': '<script>alert("test")</script>',
            'target_code': 'function renderHTML(input) { return input; }'
        }
        
        result = await sandbox.test_vulnerability(
            scenario=test_scenario,
            safe_mode=True
        )
        
        assert 'execution_result' in result
        assert 'risk_assessment' in result
        assert 'containment_status' in result
        assert result['containment_status'] == 'SAFE'
    
    @pytest.mark.asyncio
    async def test_ai_orchestrator_integration(self, mock_bedrock_client, mock_dynamodb_client, mock_s3_client):
        """Test AI Orchestrator with new components"""
        orchestrator = AIOrchestrator(
            bedrock_client=mock_bedrock_client,
            dynamodb_client=mock_dynamodb_client,
            s3_client=mock_s3_client
        )
        
        # Test SQL injection detection through orchestrator
        sql_result = await orchestrator.sql_injection_detector.analyze_query(
            "SELECT * FROM users WHERE id = 1",
            context={'source': 'test'}
        )
        assert sql_result is not None
        
        # Test threat intelligence through orchestrator
        threat_result = await orchestrator.threat_intelligence.analyze_threats(
            findings=[],
            scan_id='test-123'
        )
        assert threat_result is not None
        
        # Test root cause analysis through orchestrator
        root_cause_result = await orchestrator.root_cause_analyzer.analyze_incidents(
            incidents=[],
            historical_data=[]
        )
        assert root_cause_result is not None
        
        # Test pure AI detection through orchestrator
        pure_ai_result = await orchestrator.pure_ai_detector.detect_vulnerabilities(
            code="test code",
            language="python"
        )
        assert pure_ai_result is not None
        
        # Test sandbox through orchestrator
        sandbox_result = await orchestrator.security_sandbox.test_vulnerability(
            scenario={},
            safe_mode=True
        )
        assert sandbox_result is not None
    
    @pytest.mark.asyncio
    async def test_end_to_end_ai_security_flow(self, mock_bedrock_client, mock_dynamodb_client, mock_s3_client):
        """Test end-to-end flow with all AI security components"""
        orchestrator = AIOrchestrator(
            bedrock_client=mock_bedrock_client,
            dynamodb_client=mock_dynamodb_client,
            s3_client=mock_s3_client
        )
        
        # Simulate a complete security analysis flow
        
        # 1. Detect SQL injection
        sql_detection = await orchestrator.sql_injection_detector.analyze_query(
            "SELECT * FROM users WHERE id = '1' OR '1'='1'",
            context={'app': 'test'}
        )
        
        # 2. Analyze threat based on detection
        if sql_detection.get('risk_score', 0) > 0.5:
            threat_analysis = await orchestrator.threat_intelligence.analyze_threats(
                findings=[{
                    'type': 'SQL_INJECTION',
                    'severity': 'HIGH',
                    'details': sql_detection
                }],
                scan_id='test-scan'
            )
            
            # 3. Analyze root cause
            root_cause = await orchestrator.root_cause_analyzer.analyze_incidents(
                incidents=[{
                    'type': 'SQL_INJECTION',
                    'details': sql_detection,
                    'threat_analysis': threat_analysis
                }],
                historical_data=[]
            )
            
            # 4. Test in sandbox
            sandbox_test = await orchestrator.security_sandbox.test_vulnerability(
                scenario={
                    'vulnerability': sql_detection,
                    'exploit_method': threat_analysis.get('predicted_exploits', [])
                },
                safe_mode=True
            )
            
            # Verify complete flow
            assert sql_detection is not None
            assert threat_analysis is not None
            assert root_cause is not None
            assert sandbox_test is not None
            assert sandbox_test['containment_status'] == 'SAFE'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])