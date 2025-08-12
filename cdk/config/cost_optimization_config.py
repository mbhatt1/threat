#!/usr/bin/env python3
"""
Cost Optimization Configuration for AI Security Audit Framework
"""
from typing import Dict, List, Any


class CostOptimizationConfig:
    """Configuration for cost optimization strategies"""
    
    # Fargate Spot configuration for non-critical workloads
    FARGATE_SPOT_CONFIG = {
        "enabled_agents": [
            "dependency",
            "iac",
            "secrets"
        ],
        "spot_percentage": 70,  # Use 70% spot instances
        "on_demand_base": 30    # Keep 30% on-demand for stability
    }
    
    # Lambda optimization settings
    LAMBDA_OPTIMIZATION = {
        "memory_configurations": {
            "ceo_agent": 1024,         # Reduced from 3008
            "aggregator": 512,         # Reduced from 1024
            "report_generator": 1024,  # Reduced from 2048
            "sns_handler": 256,        # Minimal memory
            "data_transformer": 512    # Reduced from 1024
        },
        "reserved_concurrency": {
            "ceo_agent": 10,
            "aggregator": 20,
            "report_generator": 5
        },
        "provisioned_concurrency": {
            "enabled": False,  # Disable for cost savings
            "configurations": {}
        }
    }
    
    # S3 lifecycle policies for cost optimization
    S3_LIFECYCLE_POLICIES = {
        "scan_results": {
            "transition_to_ia_days": 30,      # Move to Infrequent Access after 30 days
            "transition_to_glacier_days": 90,  # Move to Glacier after 90 days
            "expiration_days": 365            # Delete after 1 year
        },
        "reports": {
            "transition_to_ia_days": 7,       # Move to IA quickly
            "transition_to_glacier_days": 30,  # Archive reports after 30 days
            "expiration_days": 730            # Keep for 2 years
        },
        "athena_results": {
            "expiration_days": 7              # Delete Athena results quickly
        },
        "metrics": {
            "transition_to_ia_days": 1,       # Move metrics to IA after 1 day
            "expiration_days": 30             # Keep metrics for 30 days
        }
    }
    
    # DynamoDB optimization
    DYNAMODB_OPTIMIZATION = {
        "billing_mode": "PAY_PER_REQUEST",  # Use on-demand for variable workloads
        "point_in_time_recovery": {
            "enabled_tables": ["scan_metadata", "remediation_tracking"],  # Only critical tables
            "disabled_tables": ["ai_decisions", "ai_scans", "ai_findings"]
        },
        "contributor_insights": {
            "enabled": False  # Disable to save costs
        }
    }
    
    # ECS/Fargate optimization
    ECS_OPTIMIZATION = {
        "task_cpu_memory_configs": {
            # Optimized CPU/memory combinations for cost
            "light": {"cpu": 256, "memory": 512},      # For simple agents
            "medium": {"cpu": 512, "memory": 1024},    # For standard agents
            "heavy": {"cpu": 1024, "memory": 2048},    # For complex processing
            "ai_powered": {"cpu": 2048, "memory": 4096} # For AI agents (reduced from 4096/8192)
        },
        "agent_configurations": {
            "sast": "heavy",
            "dependency": "medium",
            "secrets": "light",
            "container": "heavy",
            "iac": "medium",
            "threat-intel": "heavy",
            "supply-chain": "medium",
            "infra-security": "medium",
            "code-analyzer": "ai_powered"
        }
    }
    
    # CloudWatch optimization
    CLOUDWATCH_OPTIMIZATION = {
        "log_retention_days": {
            "lambda": 7,      # Keep Lambda logs for 7 days
            "ecs": 14,        # Keep ECS logs for 14 days
            "api_gateway": 3  # Keep API logs for 3 days
        },
        "metric_filters": {
            "enabled": True,
            "only_errors": True  # Only create metric filters for errors
        },
        "dashboard_refresh": {
            "interval_minutes": 5,  # Refresh every 5 minutes instead of 1
            "auto_refresh": False   # Disable auto-refresh by default
        }
    }
    
    # Bedrock/AI optimization
    AI_OPTIMIZATION = {
        "model_selection": {
            "default": "anthropic.claude-3-haiku-20240307-v1:0",  # Use Haiku for cost savings
            "critical_analysis": "anthropic.claude-3-sonnet-20240229-v1:0",
            "disabled_models": ["anthropic.claude-3-opus-20240229-v1:0"]  # Too expensive
        },
        "batch_processing": {
            "enabled": True,
            "batch_size": 10,
            "max_concurrent_requests": 5
        },
        "caching": {
            "enabled": True,
            "ttl_hours": 24  # Cache AI responses for 24 hours
        }
    }
    
    # Network optimization
    NETWORK_OPTIMIZATION = {
        "nat_gateway": {
            "use_nat_instances": True,  # Use NAT instances instead of NAT gateways
            "single_nat": True          # Use single NAT for all AZs in non-prod
        },
        "vpc_endpoints": {
            "enabled_services": ["s3", "dynamodb"],  # Only essential endpoints
            "disabled_services": ["sns", "sqs"]      # Use internet gateway
        }
    }
    
    # Scheduled scaling
    SCHEDULED_SCALING = {
        "enabled": True,
        "schedules": {
            "business_hours": {
                "start": "08:00",
                "end": "18:00",
                "timezone": "US/Eastern",
                "scale_factor": 1.0  # Normal capacity
            },
            "off_hours": {
                "scale_factor": 0.3  # 30% capacity during off hours
            },
            "weekend": {
                "scale_factor": 0.2  # 20% capacity on weekends
            }
        }
    }
    
    # Cost allocation tags
    COST_ALLOCATION_TAGS = {
        "mandatory_tags": [
            "Project",
            "Environment",
            "CostCenter",
            "Owner",
            "Purpose"
        ],
        "optional_tags": [
            "DataClassification",
            "ExpirationDate",
            "AutoShutdown"
        ],
        "tag_enforcement": {
            "block_untagged_resources": False,  # Warning only in dev/staging
            "alert_on_missing_tags": True
        }
    }
    
    @classmethod
    def get_optimized_lambda_config(cls, function_name: str) -> Dict[str, Any]:
        """Get optimized Lambda configuration"""
        return {
            "memory_size": cls.LAMBDA_OPTIMIZATION["memory_configurations"].get(function_name, 512),
            "reserved_concurrent_executions": cls.LAMBDA_OPTIMIZATION["reserved_concurrency"].get(function_name, None),
            "timeout": 300,  # 5 minutes max
            "architecture": "arm64"  # Use Graviton2 for cost savings
        }
    
    @classmethod
    def get_optimized_ecs_config(cls, agent_name: str) -> Dict[str, int]:
        """Get optimized ECS task configuration"""
        config_type = cls.ECS_OPTIMIZATION["agent_configurations"].get(agent_name, "medium")
        return cls.ECS_OPTIMIZATION["task_cpu_memory_configs"][config_type]
    
    @classmethod
    def should_use_spot(cls, agent_name: str) -> bool:
        """Check if agent should use Fargate Spot"""
        return agent_name in cls.FARGATE_SPOT_CONFIG["enabled_agents"]
    
    @classmethod
    def get_s3_lifecycle_rules(cls, bucket_type: str) -> Dict[str, Any]:
        """Get S3 lifecycle rules for a bucket type"""
        return cls.S3_LIFECYCLE_POLICIES.get(bucket_type, {})
    
    @classmethod
    def get_log_retention_days(cls, service: str) -> int:
        """Get CloudWatch log retention days for a service"""
        return cls.CLOUDWATCH_OPTIMIZATION["log_retention_days"].get(service, 7)