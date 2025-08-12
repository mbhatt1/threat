"""
Unit tests for AI Security Test Generator
"""
import pytest
import asyncio
import json
from unittest.mock import Mock, patch, AsyncMock
import sys
import os

# Add the source directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from ai_models.security_test_generator import (
    AISecurityTestGenerator,
    SecurityTestCase,
    PenetrationScenario,
    TestGenerationResult
)


class TestAISecurityTestGenerator:
    """Test suite for AI Security Test Generator"""
    
    @pytest.fixture
    def mock_bedrock_client(self):
        """Mock Bedrock client for testing"""
        mock = Mock()
        
        # Mock test case generation response
        test_case_response = {
            'body': Mock(read=Mock(return_value=json.dumps({
                'content': [{
                    'text': json.dumps([
                        {
                            'test_name': 'test_sql_injection_auth',
                            'test_type': 'unit',
                            'vulnerability_type': 'SQL_INJECTION',
                            'test_description': 'Test SQL injection in auth',
                            'test_code': 'def test_sql_injection():\n    pass',
                            'expected_result': 'Should reject malicious input',
                            'severity': 'CRITICAL',
                            'confidence': 0.95,
                            'prerequisites': ['Setup database'],
                            'cleanup_steps': ['Reset database']
                        }
                    ])
                }]
            }).encode()))
        }
        
        # Mock penetration scenario response
        pen_test_response = {
            'body': Mock(read=Mock(return_value=json.dumps({
                'content': [{
                    'text': json.dumps([
                        {
                            'scenario_name': 'SQL Injection Auth Bypass',
                            'attack_vector': 'Login form',
                            'target_vulnerability': 'SQL_INJECTION',
                            'attack_steps': [
                                {
                                    'step': 1,
                                    'action': 'Send malicious payload',
                                    'tool': 'Burp Suite',
                                    'expected_response': 'Unauthorized access',
                                    'detection_risk': 'medium'
                                }
                            ],
                            'success_indicators': ['Bypass authentication'],
                            'detection_evasion': ['Use encoding'],
                            'impact_assessment': {
                                'confidentiality': 'High',
                                'integrity': 'High',
                                'availability': 'Low',
                                'business_impact': 'Data breach'
                            },
                            'mitigation_validation': {
                                'test_after_fix': 'Retry injection',
                                'expected_result': 'Access denied'
                            },
                            'risk_score': 9.5
                        }
                    ])
                }]
            }).encode()))
        }
        
        # Mock fuzzing test response
        fuzzing_response = {
            'body': Mock(read=Mock(return_value=json.dumps({
                'content': [{
                    'text': json.dumps({
                        'fuzzing_tests': [
                            {
                                'test_name': 'Fuzz user input',
                                'target_input': 'username',
                                'fuzzing_patterns': ['<script>', '\' OR 1=1--', '../../../etc/passwd'],
                                'expected_behavior': 'Reject invalid input',
                                'vulnerability_indicator': 'Error or unexpected behavior'
                            }
                        ]
                    })
                }]
            }).encode()))
        }
        
        # Return different responses based on call count
        mock.invoke_model.side_effect = [
            test_case_response,
            pen_test_response,
            fuzzing_response
        ]
        
        return mock
    
    @pytest.mark.asyncio
    async def test_generate_tests_complete_flow(self, mock_bedrock_client):
        """Test complete test generation flow"""
        generator = AISecurityTestGenerator(bedrock_client=mock_bedrock_client)
        
        vulnerabilities = [
            {
                'type': 'SQL_INJECTION',
                'severity': 'CRITICAL',
                'description': 'SQL injection in login',
                'file_path': 'src/auth.py',
                'line_number': 42
            }
        ]
        
        code_context = {
            'repository': 'test-repo',
            'language': 'python',
            'framework': 'django',
            'tech_stack': ['python', 'django', 'postgresql']
        }
        
        result = await generator.generate_tests(
            vulnerabilities=vulnerabilities,
            code_context=code_context,
            test_types=['unit', 'penetration', 'fuzzing']
        )
        
        # Verify result structure
        assert isinstance(result, TestGenerationResult)
        assert len(result.test_cases) > 0
        assert len(result.penetration_scenarios) > 0
        assert result.ai_confidence > 0
        assert 'coverage_percentage' in result.coverage_analysis
        assert 'test_distribution' in result.coverage_analysis
        
        # Verify test case
        test_case = result.test_cases[0]
        assert test_case.test_name == 'test_sql_injection_auth'
        assert test_case.test_type == 'unit'
        assert test_case.vulnerability_type == 'SQL_INJECTION'
        assert test_case.severity == 'CRITICAL'
        assert test_case.confidence == 0.95
        
        # Verify penetration scenario
        pen_scenario = result.penetration_scenarios[0]
        assert pen_scenario.scenario_name == 'SQL Injection Auth Bypass'
        assert pen_scenario.attack_vector == 'Login form'
        assert pen_scenario.risk_score == 9.5
        assert len(pen_scenario.attack_steps) > 0
    
    @pytest.mark.asyncio
    async def test_generate_test_cases_only(self, mock_bedrock_client):
        """Test generating only test cases"""
        generator = AISecurityTestGenerator(bedrock_client=mock_bedrock_client)
        
        test_cases = await generator._generate_test_cases(
            vulnerabilities=[{'type': 'XSS', 'severity': 'HIGH'}],
            code_context={'language': 'javascript'}
        )
        
        assert len(test_cases) > 0
        assert all(isinstance(tc, SecurityTestCase) for tc in test_cases)
        
    @pytest.mark.asyncio
    async def test_generate_penetration_scenarios(self, mock_bedrock_client):
        """Test generating penetration scenarios"""
        generator = AISecurityTestGenerator(bedrock_client=mock_bedrock_client)
        
        # Skip first call to get to penetration scenario response
        mock_bedrock_client.invoke_model.side_effect = [
            mock_bedrock_client.invoke_model.side_effect[1]  # pen_test_response
        ]
        
        scenarios = await generator._generate_penetration_scenarios(
            vulnerabilities=[{'type': 'SQL_INJECTION', 'severity': 'CRITICAL'}],
            code_context={'app_type': 'web application'}
        )
        
        assert len(scenarios) > 0
        assert all(isinstance(s, PenetrationScenario) for s in scenarios)
        assert scenarios[0].risk_score == 9.5
        
    def test_analyze_test_coverage(self):
        """Test coverage analysis"""
        generator = AISecurityTestGenerator()
        
        vulnerabilities = [
            {'type': 'SQL_INJECTION'},
            {'type': 'XSS'},
            {'type': 'CSRF'}
        ]
        
        test_cases = [
            SecurityTestCase(
                test_id='1',
                test_name='test1',
                test_type='unit',
                vulnerability_type='SQL_INJECTION',
                test_description='',
                test_code='',
                expected_result='',
                severity='HIGH',
                confidence=0.9
            )
        ]
        
        pen_scenarios = [
            PenetrationScenario(
                scenario_id='1',
                scenario_name='XSS Attack',
                attack_vector='',
                target_vulnerability='XSS',
                attack_steps=[],
                success_indicators=[],
                detection_evasion=[],
                impact_assessment={},
                mitigation_validation={},
                risk_score=8.0
            )
        ]
        
        loop = asyncio.new_event_loop()
        coverage = loop.run_until_complete(
            generator._analyze_test_coverage(vulnerabilities, test_cases, pen_scenarios)
        )
        loop.close()
        
        assert coverage['total_vulnerabilities'] == 3
        assert coverage['total_test_cases'] == 1
        assert coverage['total_penetration_scenarios'] == 1
        assert coverage['vulnerability_coverage']['coverage_percentage'] == 66.67  # 2 out of 3
        assert 'CSRF' in coverage['vulnerability_coverage']['uncovered']
        
    def test_generate_fuzzing_code(self):
        """Test fuzzing code generation"""
        generator = AISecurityTestGenerator()
        
        # Test Python code generation
        python_code = generator._generate_fuzzing_code(
            'user_input',
            '<script>alert(1)</script>',
            {'language': 'python'}
        )
        assert 'def test_fuzzing_user_input' in python_code
        assert '<script>alert(1)</script>' in python_code
        
        # Test JavaScript code generation
        js_code = generator._generate_fuzzing_code(
            'user.name',
            '\' OR 1=1--',
            {'language': 'javascript'}
        )
        assert 'test(\'Fuzzing user.name\'' in js_code
        assert '\' OR 1=1--' in js_code
        
    def test_estimate_execution_time(self):
        """Test execution time estimation"""
        generator = AISecurityTestGenerator()
        
        test_cases = [
            SecurityTestCase(
                test_id=str(i),
                test_name=f'test{i}',
                test_type=test_type,
                vulnerability_type='',
                test_description='',
                test_code='',
                expected_result='',
                severity='MEDIUM',
                confidence=0.8
            )
            for i, test_type in enumerate(['unit'] * 5 + ['integration'] * 3 + ['fuzzing'] * 2)
        ]
        
        scenarios = [PenetrationScenario(
            scenario_id='1',
            scenario_name='Pen Test',
            attack_vector='',
            target_vulnerability='',
            attack_steps=[],
            success_indicators=[],
            detection_evasion=[],
            impact_assessment={},
            mitigation_validation={},
            risk_score=7.0
        )] * 2
        
        time_estimate = generator._estimate_execution_time(test_cases, scenarios)
        
        # 5 unit (2.5 min) + 3 integration (6 min) + 2 fuzzing (2 min) + 2 pen tests (60 min)
        # Total: 70.5 minutes = 1.2 hours
        assert '1.2 hours' in time_estimate
        
    def test_identify_required_tools(self):
        """Test tool identification"""
        generator = AISecurityTestGenerator()
        
        test_cases = [
            SecurityTestCase(
                test_id='1',
                test_name='test_fuzz',
                test_type='fuzzing',
                vulnerability_type='',
                test_description='',
                test_code='',
                expected_result='',
                severity='HIGH',
                confidence=0.9
            )
        ]
        
        scenarios = [
            PenetrationScenario(
                scenario_id='1',
                scenario_name='SQL Injection',
                attack_vector='',
                target_vulnerability='',
                attack_steps=[
                    {'tool': 'sqlmap'},
                    {'tool': 'manual'}
                ],
                success_indicators=[],
                detection_evasion=[],
                impact_assessment={},
                mitigation_validation={},
                risk_score=9.0
            )
        ]
        
        tools = generator._identify_required_tools(test_cases, scenarios)
        
        assert 'pytest' in tools
        assert 'unittest' in tools
        assert 'AFL++' in tools  # For fuzzing
        assert 'libFuzzer' in tools  # For fuzzing
        assert 'Burp Suite' in tools  # For pen testing
        assert 'OWASP ZAP' in tools  # For pen testing
        assert 'sqlmap' in tools  # From attack steps
        assert 'manual' not in tools  # Should be filtered out
        
    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling in test generation"""
        mock_client = Mock()
        mock_client.invoke_model.side_effect = Exception("Bedrock API error")
        
        generator = AISecurityTestGenerator(bedrock_client=mock_client)
        
        result = await generator.generate_tests(
            vulnerabilities=[{'type': 'XSS'}],
            code_context={'language': 'python'}
        )
        
        # Should return empty results on error
        assert len(result.test_cases) == 0
        assert len(result.penetration_scenarios) == 0
        assert result.ai_confidence == 0.0