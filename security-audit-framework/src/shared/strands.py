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


class TaskStatus(str, Enum):
    """Task execution status"""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


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
class StrandsMessage:
    """Standard Strands message for inter-agent communication"""
    scan_id: str
    task_id: str
    agent_type: AgentType
    status: TaskStatus
    timestamp_utc: str
    payload: StrandsPayload
    results: Optional[StrandsResults] = None
    
    @classmethod
    def create_new(cls, scan_id: str, agent_type: AgentType, payload: StrandsPayload) -> 'StrandsMessage':
        """Create a new Strands message with generated IDs and timestamp"""
        return cls(
            scan_id=scan_id,
            task_id=str(uuid.uuid4()),
            agent_type=agent_type,
            status=TaskStatus.PENDING,
            timestamp_utc=datetime.utcnow().isoformat() + "Z",
            payload=payload
        )
    
    def to_json(self) -> str:
        """Convert message to JSON string"""
        data = {
            "scan_id": self.scan_id,
            "task_id": self.task_id,
            "agent_type": self.agent_type.value,
            "status": self.status.value,
            "timestamp_utc": self.timestamp_utc,
            "payload": self.payload.to_dict()
        }
        if self.results:
            data["results"] = self.results.to_dict()
        return json.dumps(data, indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'StrandsMessage':
        """Create StrandsMessage from JSON string"""
        data = json.loads(json_str)
        
        # Parse config
        config_data = data["payload"]["config"]
        config = StrandsConfig(**config_data)
        
        # Parse payload
        payload = StrandsPayload(
            repository_url=data["payload"]["repository_url"],
            commit_hash=data["payload"]["commit_hash"],
            credentials_secret_arn=data["payload"]["credentials_secret_arn"],
            config=config,
            repository_path=data["payload"].get("repository_path")
        )
        
        # Parse results if present
        results = None
        if "results" in data and data["results"]:
            metrics = None
            if "metrics" in data["results"]:
                metrics = StrandsMetrics(**data["results"]["metrics"])
            
            results = StrandsResults(
                output_s3_path=data["results"]["output_s3_path"],
                error_log_s3_path=data["results"].get("error_log_s3_path"),
                metrics=metrics
            )
        
        return cls(
            scan_id=data["scan_id"],
            task_id=data["task_id"],
            agent_type=AgentType(data["agent_type"]),
            status=TaskStatus(data["status"]),
            timestamp_utc=data["timestamp_utc"],
            payload=payload,
            results=results
        )


@dataclass
class SecurityFinding:
    """Standard schema for security findings"""
    finding_id: str
    type: str
    severity: FindingSeverity
    confidence: FindingConfidence
    message: str
    file_path: str
    start_line: int
    end_line: int
    code_snippet: Optional[str] = None
    remediation_suggestion: Optional[str] = None
    cve_id: Optional[str] = None
    dependency_name: Optional[str] = None
    dependency_version: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {k: v.value if isinstance(v, Enum) else v 
                for k, v in asdict(self).items() if v is not None}
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityFinding':
        """Create SecurityFinding from dictionary"""
        # Convert string values back to enums
        if "severity" in data:
            data["severity"] = FindingSeverity(data["severity"])
        if "confidence" in data:
            data["confidence"] = FindingConfidence(data["confidence"])
        return cls(**data)


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
        return [f for f in self.findings if f.severity == severity]
    
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