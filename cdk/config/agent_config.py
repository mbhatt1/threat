#!/usr/bin/env python3
"""
Agent Configuration - Centralized configuration for all security agents
"""
from typing import Dict, List, Any


class AgentConfig:
    """Configuration for security agents"""
    
    # Agent definitions with their specific configurations
    AGENTS = {
        "sast": {
            "name": "Static Application Security Testing",
            "type": "code-analysis",
            "cpu": 2048,
            "memory": 4096,
            "timeout_minutes": 30,
            "priority": "high",
            "capabilities": ["code-scanning", "vulnerability-detection", "pattern-matching"],
            "languages": ["python", "javascript", "java", "go", "rust", "c++"],
            "env_vars": {
                "SCAN_DEPTH": "deep",
                "MAX_FILE_SIZE_MB": "50",
                "PARALLEL_WORKERS": "10"
            }
        },
        "dependency": {
            "name": "Dependency Scanner",
            "type": "supply-chain",
            "cpu": 1024,
            "memory": 2048,
            "timeout_minutes": 20,
            "priority": "medium",
            "capabilities": ["dependency-scanning", "license-checking", "vulnerability-matching"],
            "package_managers": ["npm", "pip", "maven", "gradle", "cargo", "go.mod"],
            "env_vars": {
                "CHECK_LICENSES": "true",
                "MAX_DEPTH": "10",
                "INCLUDE_DEV_DEPS": "true"
            }
        },
        "secrets": {
            "name": "Secrets Scanner",
            "type": "security",
            "cpu": 1024,
            "memory": 2048,
            "timeout_minutes": 15,
            "priority": "critical",
            "capabilities": ["secret-detection", "entropy-analysis", "pattern-matching"],
            "patterns": ["api-keys", "passwords", "tokens", "certificates", "private-keys"],
            "env_vars": {
                "ENTROPY_THRESHOLD": "4.5",
                "SCAN_HISTORY": "false",
                "MAX_FILE_SIZE_MB": "100"
            }
        },
        "container": {
            "name": "Container Security Scanner",
            "type": "infrastructure",
            "cpu": 2048,
            "memory": 4096,
            "timeout_minutes": 25,
            "priority": "high",
            "capabilities": ["image-scanning", "layer-analysis", "cve-detection"],
            "registries": ["ecr", "docker-hub", "gcr", "acr"],
            "env_vars": {
                "SCAN_LAYERS": "true",
                "CHECK_BASE_IMAGES": "true",
                "MAX_IMAGE_SIZE_GB": "5"
            }
        },
        "iac": {
            "name": "Infrastructure as Code Scanner",
            "type": "infrastructure",
            "cpu": 1024,
            "memory": 2048,
            "timeout_minutes": 20,
            "priority": "medium",
            "capabilities": ["terraform-scanning", "cloudformation-scanning", "kubernetes-scanning"],
            "frameworks": ["terraform", "cloudformation", "kubernetes", "helm", "ansible"],
            "env_vars": {
                "CHECK_BEST_PRACTICES": "true",
                "POLICY_ENGINE": "opa",
                "CUSTOM_POLICIES_PATH": "/policies"
            }
        },
        "threat-intel": {
            "name": "Threat Intelligence Agent",
            "type": "intelligence",
            "cpu": 2048,
            "memory": 4096,
            "timeout_minutes": 30,
            "priority": "high",
            "capabilities": ["threat-analysis", "ioc-matching", "risk-scoring"],
            "data_sources": ["cve", "nvd", "mitre-attack", "custom-feeds"],
            "env_vars": {
                "UPDATE_INTERVAL_HOURS": "6",
                "THREAT_SCORE_THRESHOLD": "7",
                "ENABLE_ML_ANALYSIS": "true"
            }
        },
        "supply-chain": {
            "name": "Supply Chain Security Agent",
            "type": "supply-chain",
            "cpu": 2048,
            "memory": 4096,
            "timeout_minutes": 25,
            "priority": "high",
            "capabilities": ["sbom-generation", "provenance-checking", "integrity-verification"],
            "standards": ["spdx", "cyclonedx", "in-toto"],
            "env_vars": {
                "GENERATE_SBOM": "true",
                "VERIFY_SIGNATURES": "true",
                "CHECK_PROVENANCE": "true"
            }
        },
        "infra-security": {
            "name": "Infrastructure Security Agent",
            "type": "infrastructure",
            "cpu": 2048,
            "memory": 4096,
            "timeout_minutes": 30,
            "priority": "high",
            "capabilities": ["cloud-scanning", "compliance-checking", "drift-detection"],
            "cloud_providers": ["aws", "azure", "gcp"],
            "env_vars": {
                "SCAN_INTERVAL_MINUTES": "60",
                "CHECK_COMPLIANCE": "true",
                "FRAMEWORKS": "cis,nist,pci-dss"
            }
        },
        "code-analyzer": {
            "name": "AI Code Analyzer",
            "type": "ai-powered",
            "cpu": 4096,
            "memory": 8192,
            "timeout_minutes": 45,
            "priority": "medium",
            "capabilities": ["ai-analysis", "pattern-learning", "predictive-detection"],
            "models": ["claude-3-sonnet", "claude-3-opus"],
            "env_vars": {
                "AI_MODEL": "anthropic.claude-3-sonnet-20240229-v1:0",
                "BATCH_SIZE": "10",
                "CONFIDENCE_THRESHOLD": "0.85"
            }
        }
    }
    
    # Agent communication patterns
    COMMUNICATION = {
        "patterns": {
            "broadcast": {
                "description": "One-to-many communication",
                "use_cases": ["critical-findings", "policy-updates", "scan-completion"],
                "mechanism": "sns"
            },
            "queue": {
                "description": "Asynchronous work distribution",
                "use_cases": ["scan-requests", "result-processing", "remediation"],
                "mechanism": "sqs"
            },
            "direct": {
                "description": "Synchronous agent-to-agent",
                "use_cases": ["coordination", "dependency-resolution", "validation"],
                "mechanism": "api"
            }
        },
        "priorities": {
            "critical": {
                "queue": "priority-queue",
                "timeout_seconds": 300,
                "max_retries": 1
            },
            "high": {
                "queue": "agent-request-queue",
                "timeout_seconds": 900,
                "max_retries": 2
            },
            "medium": {
                "queue": "agent-request-queue",
                "timeout_seconds": 1800,
                "max_retries": 3
            },
            "low": {
                "queue": "agent-request-queue",
                "timeout_seconds": 3600,
                "max_retries": 3
            }
        }
    }
    
    # EFS mount configurations
    EFS_MOUNTS = {
        "repositories": {
            "path": "/mnt/efs/repos",
            "read_only": True,
            "description": "Shared repository storage"
        },
        "policies": {
            "path": "/mnt/efs/policies",
            "read_only": True,
            "description": "Custom security policies"
        },
        "models": {
            "path": "/mnt/efs/models",
            "read_only": True,
            "description": "AI models and training data"
        },
        "cache": {
            "path": "/mnt/efs/cache",
            "read_only": False,
            "description": "Shared cache for scan results"
        }
    }
    
    # IAM permissions required by agents
    IAM_PERMISSIONS = {
        "common": [
            "s3:GetObject",
            "s3:PutObject",
            "s3:ListBucket",
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:Query",
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:SendMessage",
            "sns:Publish",
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "cloudwatch:PutMetricData"
        ],
        "ai-powered": [
            "bedrock:InvokeModel",
            "bedrock:InvokeModelWithResponseStream"
        ],
        "infrastructure": [
            "ec2:Describe*",
            "ecs:Describe*",
            "iam:Get*",
            "iam:List*"
        ],
        "supply-chain": [
            "ecr:GetAuthorizationToken",
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage"
        ]
    }
    
    # Resource limits and quotas
    RESOURCE_LIMITS = {
        "max_concurrent_scans": 50,
        "max_scan_duration_minutes": 60,
        "max_file_size_mb": 100,
        "max_repository_size_gb": 10,
        "max_retries": 3,
        "max_queue_messages": 1000
    }
    
    # Monitoring and alerting thresholds
    MONITORING = {
        "metrics": {
            "scan_duration": {
                "unit": "seconds",
                "warning_threshold": 1800,
                "critical_threshold": 3600
            },
            "error_rate": {
                "unit": "percentage",
                "warning_threshold": 5,
                "critical_threshold": 10
            },
            "queue_depth": {
                "unit": "count",
                "warning_threshold": 100,
                "critical_threshold": 500
            },
            "memory_utilization": {
                "unit": "percentage",
                "warning_threshold": 80,
                "critical_threshold": 95
            }
        },
        "dashboards": {
            "agent_performance": {
                "widgets": ["scan_duration", "success_rate", "throughput"],
                "refresh_interval_seconds": 300
            },
            "system_health": {
                "widgets": ["error_rate", "queue_depth", "resource_utilization"],
                "refresh_interval_seconds": 60
            }
        }
    }
    
    @classmethod
    def get_agent_config(cls, agent_name: str) -> Dict[str, Any]:
        """Get configuration for a specific agent"""
        return cls.AGENTS.get(agent_name, {})
    
    @classmethod
    def get_agent_env_vars(cls, agent_name: str) -> Dict[str, str]:
        """Get environment variables for a specific agent"""
        base_env = {
            "AGENT_NAME": agent_name,
            "LOG_LEVEL": "INFO",
            "METRICS_ENABLED": "true"
        }
        
        agent_config = cls.get_agent_config(agent_name)
        agent_env = agent_config.get("env_vars", {})
        
        return {**base_env, **agent_env}
    
    @classmethod
    def get_agent_resource_requirements(cls, agent_name: str) -> Dict[str, int]:
        """Get resource requirements for a specific agent"""
        agent_config = cls.get_agent_config(agent_name)
        return {
            "cpu": agent_config.get("cpu", 1024),
            "memory": agent_config.get("memory", 2048),
            "timeout_minutes": agent_config.get("timeout_minutes", 30)
        }
    
    @classmethod
    def get_agent_iam_permissions(cls, agent_name: str) -> List[str]:
        """Get IAM permissions required by an agent"""
        agent_config = cls.get_agent_config(agent_name)
        agent_type = agent_config.get("type", "")
        
        permissions = cls.IAM_PERMISSIONS.get("common", []).copy()
        
        if agent_type in cls.IAM_PERMISSIONS:
            permissions.extend(cls.IAM_PERMISSIONS[agent_type])
        
        return permissions
    
    @classmethod
    def get_communication_config(cls, priority: str) -> Dict[str, Any]:
        """Get communication configuration for a given priority"""
        return cls.COMMUNICATION.get("priorities", {}).get(priority, {})