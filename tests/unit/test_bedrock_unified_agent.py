import pytest
import json
import os
from unittest.mock import patch, MagicMock, call
import sys
from datetime import datetime

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from agents.bedrock_unified.agent import BedrockUnifiedSecurityScanner


class TestBedrockUnifiedAgent:
    """Test cases for Bedrock Unified Security Scanner"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.agent = BedrockUnifiedSecurityScanner()
    
    @patch('agents.bedrock_unified.agent.boto3.client')
    def test_initialization(self, mock_boto_client):
        """Test agent initialization"""
        agent = BedrockUnifiedSecurityScanner()
        
        assert agent.model_id == 'anthropic.claude-3-sonnet-20240229-v1:0'
        assert agent.max_workers == 10
        mock_boto_client.assert_called()
    
    @patch('agents.bedrock_unified.agent.boto3.client')
    async def test_analyze_code_security(self, mock_boto_client):
        """Test AI-powered code security analysis"""
        # Mock Bedrock response
        mock_bedrock = MagicMock()
        mock_response = {
            'body': MagicMock(read=lambda: json.dumps({
                'content': [{
                    'text': json.dumps({
                        'findings': [{
                            'type': 'sql_injection',
                            'severity': 'critical',
                            'title': 'SQL Injection vulnerability',
                            'description': 'User input directly concatenated in SQL query',
                            'file_path': 'app.py',
                            'line_number': 42,
                            'confidence': 95,
                            'cwe_id': 'CWE-89'
                        }]
                    })
                }]
            }).encode())
        }
        mock_bedrock.invoke_model.return_value = mock_response
        mock_boto_client.return_value = mock_bedrock
        
        agent = BedrockUnifiedSecurityScanner()
        
        # Test code content
        test_file = {
            'path': 'app.py',
            'content': 'query = "SELECT * FROM users WHERE id = " + user_input'
        }
        
        findings = await agent._analyze_code_security([test_file])
        
        assert len(findings) == 1
        assert findings[0]['type'] == 'sql_injection'
        assert findings[0]['severity'] == 'critical'
        assert findings[0]['line_number'] == 42
        assert findings[0]['cwe_id'] == 'CWE-89'
    
    @patch('agents.bedrock_unified.agent.boto3.client')
    async def test_analyze_secrets(self, mock_boto_client):
        """Test AI-powered secrets detection"""
        mock_bedrock = MagicMock()
        mock_response = {
            'body': MagicMock(read=lambda: json.dumps({
                'content': [{
                    'text': json.dumps({
                        'secrets': [{
                            'type': 'aws_access_key',
                            'severity': 'critical',
                            'title': 'AWS Access Key exposed',
                            'file_path': 'config.py',
                            'line_number': 15,
                            'pattern_matched': 'AKIA[0-9A-Z]{16}',
                            'remediation': 'Remove hardcoded credential and use AWS IAM roles'
                        }]
                    })
                }]
            }).encode())
        }
        mock_bedrock.invoke_model.return_value = mock_response
        mock_boto_client.return_value = mock_bedrock
        
        agent = BedrockUnifiedSecurityScanner()
        
        test_file = {
            'path': 'config.py',
            'content': 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        }
        
        secrets = await agent._analyze_secrets([test_file])
        
        assert len(secrets) == 1
        assert secrets[0]['type'] == 'aws_access_key'
        assert secrets[0]['severity'] == 'critical'
        assert 'remediation' in secrets[0]
    
    @patch('agents.bedrock_unified.agent.boto3.client')
    async def test_analyze_dependencies(self, mock_boto_client):
        """Test AI-powered dependency analysis"""
        mock_bedrock = MagicMock()
        mock_response = {
            'body': MagicMock(read=lambda: json.dumps({
                'content': [{
                    'text': json.dumps({
                        'vulnerable_dependencies': [{
                            'package': 'requests',
                            'current_version': '2.25.0',
                            'vulnerability': 'CVE-2023-32681',
                            'severity': 'high',
                            'fixed_version': '2.31.0',
                            'description': 'Unintended leak of Proxy-Authorization header'
                        }]
                    })
                }]
            }).encode())
        }
        mock_bedrock.invoke_model.return_value = mock_response
        mock_boto_client.return_value = mock_bedrock
        
        agent = BedrockUnifiedSecurityScanner()
        
        test_files = [{
            'name': 'requirements.txt',
            'content': 'requests==2.25.0\nflask==2.0.1'
        }]
        
        vulns = await agent._analyze_dependencies(test_files)
        
        assert len(vulns) == 1
        assert vulns[0]['package'] == 'requests'
        assert vulns[0]['severity'] == 'high'
        assert vulns[0]['fixed_version'] == '2.31.0'
    
    @patch('agents.bedrock_unified.agent.boto3.client')
    async def test_generate_attack_chains(self, mock_boto_client):
        """Test AI-powered attack chain generation"""
        mock_bedrock = MagicMock()
        mock_response = {
            'body': MagicMock(read=lambda: json.dumps({
                'content': [{
                    'text': json.dumps({
                        'attack_chains': [{
                            'name': 'Database Compromise via SQL Injection',
                            'likelihood': 'high',
                            'impact': 'critical',
                            'steps': [
                                'SQL injection in login form',
                                'Database access gained',
                                'User credentials extracted',
                                'Privilege escalation to admin'
                            ],
                            'mitigations': [
                                'Use parameterized queries',
                                'Implement input validation',
                                'Apply principle of least privilege'
                            ]
                        }]
                    })
                }]
            }).encode())
        }
        mock_bedrock.invoke_model.return_value = mock_response
        mock_boto_client.return_value = mock_bedrock
        
        agent = BedrockUnifiedSecurityScanner()
        
        test_findings = [{
            'type': 'sql_injection',
            'severity': 'critical',
            'file_path': 'login.py'
        }]
        
        chains = await agent._generate_attack_chains(test_findings)
        
        assert len(chains) == 1
        assert chains[0]['name'] == 'Database Compromise via SQL Injection'
        assert chains[0]['likelihood'] == 'high'
        assert len(chains[0]['steps']) == 4
        assert len(chains[0]['mitigations']) == 3
    
    @patch('agents.bedrock_unified.agent.boto3.client')
    async def test_parallel_file_analysis(self, mock_boto_client):
        """Test parallel processing of multiple files"""
        mock_bedrock = MagicMock()
        mock_response = {
            'body': MagicMock(read=lambda: json.dumps({
                'content': [{
                    'text': json.dumps({
                        'findings': []
                    })
                }]
            }).encode())
        }
        mock_bedrock.invoke_model.return_value = mock_response
        mock_boto_client.return_value = mock_bedrock
        
        agent = BedrockUnifiedSecurityScanner()
        
        # Create multiple test files
        test_files = [
            {'path': f'file{i}.py', 'content': f'# Test file {i}'} 
            for i in range(20)
        ]
        
        # Should process in parallel
        findings = await agent._analyze_code_security(test_files)
        
        # Verify parallel processing (max_workers = 10)
        assert mock_bedrock.invoke_model.call_count >= 1
    
    @patch('agents.bedrock_unified.agent.boto3.client')
    async def test_comprehensive_scan(self, mock_boto_client):
        """Test comprehensive security scan across all domains"""
        # Mock S3 client
        mock_s3 = MagicMock()
        
        # Mock Bedrock client with different responses
        mock_bedrock = MagicMock()
        mock_bedrock.invoke_model.return_value = {
            'body': MagicMock(read=lambda: json.dumps({
                'content': [{
                    'text': json.dumps({
                        'findings': [],
                        'secrets': [],
                        'vulnerable_dependencies': [],
                        'infrastructure_issues': [],
                        'api_vulnerabilities': [],
                        'container_issues': [],
                        'business_logic_flaws': []
                    })
                }]
            }).encode())
        }
        
        def mock_client(service_name):
            if service_name == 's3':
                return mock_s3
            return mock_bedrock
        
        mock_boto_client.side_effect = mock_client
        
        agent = BedrockUnifiedSecurityScanner()
        
        scan_config = {
            'scan_id': 'test-123',
            'deep_analysis': True
        }
        
        result = await agent.analyze('/tmp/test-repo', scan_config)
        
        assert result['scan_id'] == 'test-123'
        assert result['agent'] == 'bedrock_unified'
        assert 'total_findings' in result
        assert 'scan_summary' in result
        assert 'attack_chains' in result
        assert 'remediation_plan' in result
    
    def test_severity_scoring(self):
        """Test severity scoring logic"""
        agent = BedrockUnifiedSecurityScanner()
        
        findings = [
            {'severity': 'critical'},
            {'severity': 'critical'},
            {'severity': 'high'},
            {'severity': 'medium'},
            {'severity': 'low'}
        ]
        
        score = agent._calculate_risk_score(findings)
        
        # Critical findings should heavily impact score
        assert score >= 80  # High risk
        
        # No findings should be low risk
        assert agent._calculate_risk_score([]) < 20
    
    @patch.dict(os.environ, {'BEDROCK_MODEL_ID': 'anthropic.claude-3-opus-20240229-v1:0'})
    def test_model_configuration(self):
        """Test model configuration from environment"""
        agent = BedrockUnifiedSecurityScanner()
        
        assert agent.model_id == 'anthropic.claude-3-opus-20240229-v1:0'


class TestBedrockPromptEngineering:
    """Test cases for prompt engineering"""
    
    def test_code_analysis_prompt(self):
        """Test code analysis prompt generation"""
        agent = BedrockUnifiedSecurityScanner()
        
        test_code = """
        def login(username, password):
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            return db.execute(query)
        """
        
        prompt = agent._create_code_analysis_prompt('login.py', test_code)
        
        # Verify prompt contains key instructions
        assert 'security vulnerabilities' in prompt.lower()
        assert 'sql injection' in prompt.lower()
        assert 'cwe' in prompt.lower()
        assert 'severity' in prompt.lower()
        assert 'json' in prompt.lower()
    
    def test_secrets_detection_prompt(self):
        """Test secrets detection prompt generation"""
        agent = BedrockUnifiedSecurityScanner()
        
        test_content = """
        API_KEY = "sk-1234567890abcdef"
        DATABASE_URL = "postgresql://user:pass@localhost/db"
        """
        
        prompt = agent._create_secrets_prompt('config.py', test_content)
        
        assert 'secrets' in prompt.lower()
        assert 'credentials' in prompt.lower()
        assert 'api key' in prompt.lower()
        assert 'remediation' in prompt.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])