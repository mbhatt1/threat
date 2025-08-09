import pytest
import json
from datetime import datetime
from unittest.mock import patch, MagicMock
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from shared.strands import (
    StrandsProtocol, StrandsMessage, MessageType, SecurityFinding,
    TaskContext, AgentCapability, CostOptimization
)


class TestStrandsProtocol:
    """Test cases for the Strands protocol"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.protocol = StrandsProtocol()
    
    def test_create_task_assignment(self):
        """Test creating a task assignment message"""
        context = {
            "repository_url": "https://github.com/test/repo",
            "branch": "main"
        }
        
        message = self.protocol.create_task_assignment(
            task_id="task-001",
            sender_id="CEO",
            recipient_id="SAST",
            context=context
        )
        
        assert message.message_type == MessageType.TASK_ASSIGNMENT
        assert message.task_id == "task-001"
        assert message.sender_id == "CEO"
        assert message.recipient_id == "SAST"
        assert message.context == context
        assert message.timestamp is not None
        assert message.message_id is not None
    
    def test_create_result_message(self):
        """Test creating a result message"""
        results = {
            "findings_count": 5,
            "severity_high": 2,
            "severity_medium": 3
        }
        
        message = self.protocol.create_result_message(
            task_id="task-001",
            agent_id="SAST",
            results=results,
            execution_time=300
        )
        
        assert message.message_type == MessageType.RESULT
        assert message.task_id == "task-001"
        assert message.sender_id == "SAST"
        assert message.results == results
        assert message.execution_time == 300
    
    def test_create_error_message(self):
        """Test creating an error message"""
        error = "Failed to clone repository"
        
        message = self.protocol.create_error_message(
            task_id="task-001",
            agent_id="SAST",
            error=error
        )
        
        assert message.message_type == MessageType.ERROR
        assert message.task_id == "task-001"
        assert message.sender_id == "SAST"
        assert message.error == error
    
    def test_validate_message_valid(self):
        """Test validating a valid message"""
        message = self.protocol.create_task_assignment(
            task_id="task-001",
            sender_id="CEO",
            recipient_id="SAST",
            context={"test": "data"}
        )
        
        assert self.protocol.validate_message(message) is True
    
    def test_validate_message_invalid_type(self):
        """Test validating a message with invalid type"""
        message = StrandsMessage(
            message_id="msg-001",
            message_type="INVALID_TYPE",  # Invalid type
            task_id="task-001",
            sender_id="CEO",
            timestamp=datetime.utcnow().isoformat()
        )
        
        assert self.protocol.validate_message(message) is False
    
    def test_validate_message_missing_required_fields(self):
        """Test validating a message with missing required fields"""
        # Missing task_id
        message = StrandsMessage(
            message_id="msg-001",
            message_type=MessageType.TASK_ASSIGNMENT,
            sender_id="CEO",
            timestamp=datetime.utcnow().isoformat()
        )
        
        assert self.protocol.validate_message(message) is False
    
    def test_message_serialization(self):
        """Test message serialization and deserialization"""
        original = self.protocol.create_task_assignment(
            task_id="task-001",
            sender_id="CEO",
            recipient_id="SAST",
            context={"test": "data"}
        )
        
        # Serialize
        json_str = json.dumps(original.dict())
        
        # Deserialize
        deserialized = StrandsMessage(**json.loads(json_str))
        
        assert deserialized.message_id == original.message_id
        assert deserialized.message_type == original.message_type
        assert deserialized.task_id == original.task_id
        assert deserialized.context == original.context


class TestSecurityFinding:
    """Test cases for SecurityFinding model"""
    
    def test_security_finding_creation(self):
        """Test creating a security finding"""
        finding = SecurityFinding(
            finding_id="finding-001",
            type="sql_injection",
            severity="HIGH",
            confidence="HIGH",
            title="SQL Injection Vulnerability",
            description="User input not sanitized",
            file_path="src/api/user.py",
            line_number=42,
            code_snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
            remediation="Use parameterized queries",
            cwe_id="CWE-89",
            owasp_category="A03:2021"
        )
        
        assert finding.finding_id == "finding-001"
        assert finding.severity == "HIGH"
        assert finding.line_number == 42
        assert finding.cwe_id == "CWE-89"
    
    def test_security_finding_optional_fields(self):
        """Test security finding with optional fields"""
        finding = SecurityFinding(
            finding_id="finding-002",
            type="hardcoded_secret",
            severity="CRITICAL",
            confidence="MEDIUM",
            title="Hardcoded API Key",
            description="API key found in source code",
            file_path="config.py"
        )
        
        assert finding.line_number is None
        assert finding.code_snippet is None
        assert finding.remediation is None
        assert finding.cwe_id is None


class TestTaskContext:
    """Test cases for TaskContext model"""
    
    def test_task_context_creation(self):
        """Test creating a task context"""
        context = TaskContext(
            repository_url="https://github.com/test/repo",
            branch="main",
            commit_sha="abc123",
            scan_type="full",
            priority="high",
            deadline_minutes=60,
            cost_limit_usd=10.0,
            agents_whitelist=["SAST", "SECRETS"],
            configuration={
                "exclude_paths": ["test/", "docs/"],
                "severity_threshold": "MEDIUM"
            }
        )
        
        assert context.repository_url == "https://github.com/test/repo"
        assert context.priority == "high"
        assert context.cost_limit_usd == 10.0
        assert "SAST" in context.agents_whitelist
        assert context.configuration["exclude_paths"] == ["test/", "docs/"]


class TestAgentCapability:
    """Test cases for AgentCapability model"""
    
    def test_agent_capability_creation(self):
        """Test creating an agent capability"""
        capability = AgentCapability(
            agent_id="SAST",
            agent_type="security_scanner",
            name="Static Application Security Testing",
            description="Scans source code for vulnerabilities",
            supported_languages=["python", "javascript", "java"],
            average_runtime_seconds=300,
            resource_requirements={
                "cpu": "1 vCPU",
                "memory": "2 GB",
                "storage": "10 GB"
            },
            cost_per_scan_usd=0.50
        )
        
        assert capability.agent_id == "SAST"
        assert "python" in capability.supported_languages
        assert capability.average_runtime_seconds == 300
        assert capability.cost_per_scan_usd == 0.50


class TestCostOptimization:
    """Test cases for CostOptimization model"""
    
    def test_cost_optimization_creation(self):
        """Test creating a cost optimization"""
        optimization = CostOptimization(
            optimization_id="opt-001",
            optimization_type="spot_instance",
            description="Use Spot instances for non-critical scans",
            estimated_savings_percent=70,
            implementation_complexity="low",
            prerequisites=["ECS cluster with Spot capacity provider"],
            trade_offs=["Potential task interruptions"]
        )
        
        assert optimization.optimization_type == "spot_instance"
        assert optimization.estimated_savings_percent == 70
        assert optimization.implementation_complexity == "low"
        assert "Potential task interruptions" in optimization.trade_offs


if __name__ == "__main__":
    pytest.main([__file__, "-v"])