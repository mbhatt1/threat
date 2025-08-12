"""
Strands Framework - Core message schema and utilities for agent communication
"""
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
import json
import uuid


class AgentType(str, Enum):
    """Supported agent types in the security audit framework"""
    SAST = "SAST"
    DAST = "DAST"
    IAC = "IAC"
    SECRETS = "SECRETS"
    DEPENDENCY = "DEPENDENCY"
    CUSTOM = "CUSTOM"
    AUTONOMOUS = "AUTONOMOUS"
    CEO = "CEO"


class TaskStatus(str, Enum):
    """Task execution status"""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class MessageType(str, Enum):
    """Types of messages in the Strands protocol"""
    TASK_ASSIGNMENT = "TASK_ASSIGNMENT"
    RESULT = "RESULT"
    ERROR = "ERROR"
    STATUS_UPDATE = "STATUS_UPDATE"
    CAPABILITY_ANNOUNCEMENT = "CAPABILITY_ANNOUNCEMENT"


class FindingSeverity(str, Enum):
    """Security finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingConfidence(str, Enum):
    """Confidence level for security findings"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class StrandsConfig:
    """Configuration for agent execution"""
    ai_analysis_depth: Optional[str] = "comprehensive"
    ai_severity_threshold: Optional[str] = "high"
    max_runtime_seconds: int = 3600
    custom_config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class StrandsPayload:
    """Payload for agent tasks"""
    repository_url: str
    commit_hash: str
    credentials_secret_arn: str
    config: StrandsConfig
    repository_path: Optional[str] = None  # EFS mount path for repository
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "repository_url": self.repository_url,
            "commit_hash": self.commit_hash,
            "credentials_secret_arn": self.credentials_secret_arn,
            "config": self.config.to_dict()
        }
        if self.repository_path:
            result["repository_path"] = self.repository_path
        return result


@dataclass
class StrandsMetrics:
    """Execution metrics for tasks"""
    execution_time_seconds: float
    cost_usd: float
    memory_used_mb: Optional[int] = None
    cpu_utilization_percent: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class StrandsResults:
    """Results from agent execution"""
    output_s3_path: str
    error_log_s3_path: Optional[str] = None
    metrics: Optional[StrandsMetrics] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {"output_s3_path": self.output_s3_path}
        if self.error_log_s3_path:
            result["error_log_s3_path"] = self.error_log_s3_path
        if self.metrics:
            result["metrics"] = self.metrics.to_dict()
        return result


@dataclass
class TaskContext:
    """Context for task assignments"""
    repository_url: str
    branch: Optional[str] = "main"
    commit_sha: Optional[str] = None
    scan_type: Optional[str] = "full"
    priority: Optional[str] = "normal"
    deadline_minutes: Optional[int] = None
    cost_limit_usd: Optional[float] = None
    agents_whitelist: Optional[List[str]] = None
    configuration: Optional[Dict[str, Any]] = None
    action: Optional[str] = None  # For specific actions like 'create_dynamic_tool'
    
    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class StrandsMessage:
    """Standard Strands message for inter-agent communication"""
    message_id: str
    message_type: MessageType
    task_id: str
    sender_id: str
    timestamp: str
    recipient_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    results: Optional[Dict[str, Any]] = None
    execution_time: Optional[float] = None
    error: Optional[str] = None
    
    # Legacy fields for backward compatibility
    scan_id: Optional[str] = None
    agent_type: Optional[AgentType] = None
    status: Optional[TaskStatus] = None
    timestamp_utc: Optional[str] = None
    payload: Optional[StrandsPayload] = None
    
    def dict(self) -> Dict[str, Any]:
        """Convert message to dictionary"""
        data = {
            "message_id": self.message_id,
            "message_type": self.message_type.value if isinstance(self.message_type, Enum) else self.message_type,
            "task_id": self.task_id,
            "sender_id": self.sender_id,
            "timestamp": self.timestamp
        }
        
        # Add optional fields
        if self.recipient_id:
            data["recipient_id"] = self.recipient_id
        if self.context:
            data["context"] = self.context
        if self.results:
            data["results"] = self.results
        if self.execution_time is not None:
            data["execution_time"] = self.execution_time
        if self.error:
            data["error"] = self.error
            
        # Add legacy fields if present
        if self.scan_id:
            data["scan_id"] = self.scan_id
        if self.agent_type:
            data["agent_type"] = self.agent_type.value if isinstance(self.agent_type, Enum) else self.agent_type
        if self.status:
            data["status"] = self.status.value if isinstance(self.status, Enum) else self.status
        if self.timestamp_utc:
            data["timestamp_utc"] = self.timestamp_utc
        if self.payload:
            data["payload"] = self.payload.to_dict()
            
        return data
    
    def to_json(self) -> str:
        """Convert message to JSON string"""
        return json.dumps(self.dict(), indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'StrandsMessage':
        """Create StrandsMessage from JSON string"""
        data = json.loads(json_str)
        
        # Convert string enums back to enum types
        if "message_type" in data:
            data["message_type"] = MessageType(data["message_type"])
        if "agent_type" in data:
            data["agent_type"] = AgentType(data["agent_type"])
        if "status" in data:
            data["status"] = TaskStatus(data["status"])
            
        # Parse payload if present
        if "payload" in data:
            config = StrandsConfig(**data["payload"]["config"])
            data["payload"] = StrandsPayload(
                repository_url=data["payload"]["repository_url"],
                commit_hash=data["payload"]["commit_hash"],
                credentials_secret_arn=data["payload"]["credentials_secret_arn"],
                config=config,
                repository_path=data["payload"].get("repository_path")
            )
            
        return cls(**data)
    
    @classmethod
    def create_new(cls, scan_id: str, agent_type: AgentType, payload: StrandsPayload) -> 'StrandsMessage':
        """Create a new Strands message with generated IDs and timestamp (legacy method)"""
        return cls(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.TASK_ASSIGNMENT,
            scan_id=scan_id,
            task_id=str(uuid.uuid4()),
            agent_type=agent_type,
            status=TaskStatus.PENDING,
            timestamp_utc=datetime.utcnow().isoformat() + "Z",
            timestamp=datetime.utcnow().isoformat() + "Z",
            payload=payload,
            sender_id="SYSTEM"
        )


class StrandsProtocol:
    """Protocol handler for Strands messages"""
    
    def create_task_assignment(self, task_id: str, sender_id: str, recipient_id: str,
                             context: Dict[str, Any]) -> StrandsMessage:
        """Create a task assignment message"""
        return StrandsMessage(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.TASK_ASSIGNMENT,
            task_id=task_id,
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            context=context
        )
    
    def create_result_message(self, task_id: str, agent_id: str, results: Dict[str, Any],
                            execution_time: float) -> StrandsMessage:
        """Create a result message"""
        return StrandsMessage(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.RESULT,
            task_id=task_id,
            sender_id=agent_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            results=results,
            execution_time=execution_time
        )
    
    def create_error_message(self, task_id: str, agent_id: str, error: str) -> StrandsMessage:
        """Create an error message"""
        return StrandsMessage(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.ERROR,
            task_id=task_id,
            sender_id=agent_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            error=error
        )
    
    def validate_message(self, message: StrandsMessage) -> bool:
        """Validate a Strands message"""
        # Check required fields
        if not all([message.message_id, message.task_id, message.sender_id, message.timestamp]):
            return False
            
        # Check message type is valid
        try:
            MessageType(message.message_type)
        except (ValueError, TypeError):
            return False
            
        # Check message type specific requirements
        if message.message_type == MessageType.TASK_ASSIGNMENT:
            if not message.recipient_id or not message.context:
                return False
        elif message.message_type == MessageType.RESULT:
            if not message.results:
                return False
        elif message.message_type == MessageType.ERROR:
            if not message.error:
                return False
                
        return True


@dataclass
class SecurityFinding:
    """Standard schema for security findings"""
    finding_id: str
    type: str
    severity: str  # Can be FindingSeverity or string
    confidence: str  # Can be FindingConfidence or string
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None  # For compatibility with tests
    start_line: Optional[int] = None  # Original field
    end_line: Optional[int] = None    # Original field
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None  # Changed from remediation_suggestion
    remediation_suggestion: Optional[str] = None  # Keep for backward compatibility
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cve_id: Optional[str] = None
    dependency_name: Optional[str] = None
    dependency_version: Optional[str] = None
    
    def __post_init__(self):
        """Handle field mappings for compatibility"""
        # Map line_number to start_line if not set
        if self.line_number is not None and self.start_line is None:
            self.start_line = self.line_number
            self.end_line = self.line_number
        # Map remediation_suggestion to remediation if not set
        if self.remediation_suggestion and not self.remediation:
            self.remediation = self.remediation_suggestion
        elif self.remediation and not self.remediation_suggestion:
            self.remediation_suggestion = self.remediation
    
    def to_dict(self) -> Dict[str, Any]:
        data = {}
        for k, v in asdict(self).items():
            if v is not None:
                if isinstance(v, Enum):
                    data[k] = v.value
                else:
                    data[k] = v
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityFinding':
        """Create SecurityFinding from dictionary"""
        # Don't convert severity/confidence to enums to maintain flexibility
        return cls(**data)


@dataclass
class AgentCapability:
    """Description of an agent's capabilities"""
    agent_id: str
    agent_type: str
    name: str
    description: str
    supported_languages: List[str]
    average_runtime_seconds: int
    resource_requirements: Dict[str, str]
    cost_per_scan_usd: float
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CostOptimization:
    """Cost optimization recommendations"""
    optimization_id: str
    optimization_type: str
    description: str
    estimated_savings_percent: int
    implementation_complexity: str
    prerequisites: List[str]
    trade_offs: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FindingsReport:
    """Container for multiple security findings"""
    
    def __init__(self, scan_id: str, repository_url: str, commit_hash: str):
        self.scan_id = scan_id
        self.repository_url = repository_url
        self.commit_hash = commit_hash
        self.findings: List[SecurityFinding] = []
        self.scan_timestamp = datetime.utcnow().isoformat() + "Z"
    
    def add_finding(self, finding: SecurityFinding) -> None:
        """Add a finding to the report"""
        self.findings.append(finding)
    
    def to_json(self) -> str:
        """Convert report to JSON string"""
        return json.dumps({
            "scan_id": self.scan_id,
            "repository_url": self.repository_url,
            "commit_hash": self.commit_hash,
            "scan_timestamp": self.scan_timestamp,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings]
        }, indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'FindingsReport':
        """Create FindingsReport from JSON string"""
        data = json.loads(json_str)
        report = cls(
            scan_id=data["scan_id"],
            repository_url=data["repository_url"],
            commit_hash=data["commit_hash"]
        )
        report.scan_timestamp = data["scan_timestamp"]
        report.findings = [SecurityFinding.from_dict(f) for f in data["findings"]]
        return report
    
    def get_findings_by_severity(self, severity: FindingSeverity) -> List[SecurityFinding]:
        """Get all findings of a specific severity"""
        severity_value = severity.value if isinstance(severity, Enum) else severity
        return [f for f in self.findings if f.severity == severity_value]
    
    def get_summary_stats(self) -> Dict[str, int]:
        """Get summary statistics of findings"""
        stats = {
            "total": len(self.findings),
            "critical": len(self.get_findings_by_severity(FindingSeverity.CRITICAL)),
            "high": len(self.get_findings_by_severity(FindingSeverity.HIGH)),
            "medium": len(self.get_findings_by_severity(FindingSeverity.MEDIUM)),
            "low": len(self.get_findings_by_severity(FindingSeverity.LOW)),
            "info": len(self.get_findings_by_severity(FindingSeverity.INFO))
        }
        return stats