#!/usr/bin/env python3
"""
Multi-region deployment configuration for AI Security Audit Framework
"""
from typing import Dict, List, Any


class MultiRegionConfig:
    """Configuration for multi-region deployments"""
    
    # Primary region configuration
    PRIMARY_REGION = "us-east-1"
    
    # Secondary regions for failover and global distribution
    SECONDARY_REGIONS = [
        "us-west-2",  # US West
        "eu-west-1",  # Europe (Ireland)
        "ap-southeast-1",  # Asia Pacific (Singapore)
    ]
    
    # Region-specific configurations
    REGION_CONFIG = {
        "us-east-1": {
            "name": "US East (N. Virginia)",
            "availability_zones": ["us-east-1a", "us-east-1b", "us-east-1c"],
            "vpc_cidr": "10.0.0.0/16",
            "is_primary": True,
            "features": {
                "quicksight": True,  # QuickSight primary region
                "security_lake": True,
                "athena_workgroup": "primary"
            }
        },
        "us-west-2": {
            "name": "US West (Oregon)",
            "availability_zones": ["us-west-2a", "us-west-2b", "us-west-2c"],
            "vpc_cidr": "10.1.0.0/16",
            "is_primary": False,
            "features": {
                "quicksight": False,
                "security_lake": True,
                "athena_workgroup": "us-west-2"
            }
        },
        "eu-west-1": {
            "name": "Europe (Ireland)",
            "availability_zones": ["eu-west-1a", "eu-west-1b", "eu-west-1c"],
            "vpc_cidr": "10.2.0.0/16",
            "is_primary": False,
            "features": {
                "quicksight": False,
                "security_lake": True,
                "athena_workgroup": "eu-west-1"
            }
        },
        "ap-southeast-1": {
            "name": "Asia Pacific (Singapore)",
            "availability_zones": ["ap-southeast-1a", "ap-southeast-1b", "ap-southeast-1c"],
            "vpc_cidr": "10.3.0.0/16",
            "is_primary": False,
            "features": {
                "quicksight": False,
                "security_lake": True,
                "athena_workgroup": "ap-southeast-1"
            }
        }
    }
    
    # Cross-region replication settings
    REPLICATION_CONFIG = {
        "s3_buckets": {
            "scan_results": {
                "enable_replication": True,
                "replication_regions": ["us-west-2", "eu-west-1"],
                "lifecycle_policy": {
                    "transition_days": 30,
                    "expiration_days": 365
                }
            },
            "security_lake": {
                "enable_replication": True,
                "replication_regions": ["us-west-2"],
                "lifecycle_policy": {
                    "transition_days": 90,
                    "expiration_days": 730  # 2 years for compliance
                }
            },
            "metrics": {
                "enable_replication": False,  # Metrics stay regional
                "lifecycle_policy": {
                    "transition_days": 7,
                    "expiration_days": 90
                }
            }
        },
        "dynamodb_tables": {
            "scan_metadata": {
                "enable_global_tables": True,
                "replica_regions": ["us-west-2", "eu-west-1"]
            },
            "security_explanations": {
                "enable_global_tables": True,
                "replica_regions": ["us-west-2"]
            },
            "business_context": {
                "enable_global_tables": False  # Keep business context regional
            }
        }
    }
    
    # Disaster recovery configuration
    DISASTER_RECOVERY = {
        "rpo_minutes": 15,  # Recovery Point Objective
        "rto_minutes": 60,  # Recovery Time Objective
        "backup_retention_days": 30,
        "enable_point_in_time_recovery": True,
        "cross_region_backup": {
            "enabled": True,
            "target_regions": ["us-west-2"]
        }
    }
    
    @classmethod
    def get_deployment_regions(cls, environment: str) -> List[str]:
        """Get regions to deploy to based on environment"""
        if environment == "dev":
            return [cls.PRIMARY_REGION]
        elif environment == "staging":
            return [cls.PRIMARY_REGION, "us-west-2"]
        elif environment == "prod":
            return [cls.PRIMARY_REGION] + cls.SECONDARY_REGIONS
        else:
            return [cls.PRIMARY_REGION]
    
    @classmethod
    def get_region_config(cls, region: str) -> Dict[str, Any]:
        """Get configuration for a specific region"""
        return cls.REGION_CONFIG.get(region, {})
    
    @classmethod
    def is_primary_region(cls, region: str) -> bool:
        """Check if region is the primary region"""
        return region == cls.PRIMARY_REGION
    
    @classmethod
    def get_replication_targets(cls, bucket_name: str) -> List[str]:
        """Get replication target regions for a bucket"""
        config = cls.REPLICATION_CONFIG.get("s3_buckets", {}).get(bucket_name, {})
        if config.get("enable_replication"):
            return config.get("replication_regions", [])
        return []
    
    @classmethod
    def get_global_table_regions(cls, table_name: str) -> List[str]:
        """Get regions for DynamoDB global table"""
        config = cls.REPLICATION_CONFIG.get("dynamodb_tables", {}).get(table_name, {})
        if config.get("enable_global_tables"):
            return [cls.PRIMARY_REGION] + config.get("replica_regions", [])
        return [cls.PRIMARY_REGION]
    
    @classmethod
    def get_vpc_cidr(cls, region: str) -> str:
        """Get VPC CIDR for a region"""
        return cls.get_region_config(region).get("vpc_cidr", "10.0.0.0/16")
    
    @classmethod
    def get_availability_zones(cls, region: str) -> List[str]:
        """Get availability zones for a region"""
        return cls.get_region_config(region).get("availability_zones", [])
    
    @classmethod
    def should_deploy_feature(cls, region: str, feature: str) -> bool:
        """Check if a feature should be deployed in a region"""
        features = cls.get_region_config(region).get("features", {})
        return features.get(feature, False)