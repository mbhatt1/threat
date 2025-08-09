"""
ECS Stack - ECS Cluster and Task Definitions for AI-Powered Security Agents
"""
from aws_cdk import (
    Stack,
    aws_ecs as ecs,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_logs as logs,
    aws_ecr_assets as ecr_assets,
    aws_s3 as s3,
    aws_efs as efs,
    Duration,
    RemovalPolicy
)
from constructs import Construct
import os


class EcsStack(Stack):
    """ECS Cluster and Task Definitions for AI-powered security agents"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 vpc: ec2.Vpc,
                 task_execution_role: iam.Role,
                 autonomous_task_role: iam.Role,
                 bedrock_unified_task_role: iam.Role,
                 results_bucket: s3.Bucket,
                 efs_filesystem: efs.FileSystem,
                 efs_access_point: efs.AccessPoint,
                 ecs_security_group: ec2.SecurityGroup,
                 remediation_lambda_arn: str = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Create ECS Cluster
        self.cluster = ecs.Cluster(
            self, "SecurityAgentCluster",
            vpc=vpc,
            cluster_name="security-audit-cluster",
            container_insights=True,  # Enable CloudWatch Container Insights
            enable_fargate_capacity_providers=True
        )
        
        # Add Fargate Spot capacity provider for cost optimization
        self.cluster.add_capacity_provider("FARGATE_SPOT")
        
        # CloudWatch Log Group for ECS tasks
        self.log_group = logs.LogGroup(
            self, "ECSLogGroup",
            log_group_name="/ecs/security-agents",
            retention=logs.RetentionDays.TWO_WEEKS,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        # Build Docker images from source
        autonomous_image = ecr_assets.DockerImageAsset(
            self, "AutonomousImage",
            directory=os.path.join("..", "src", "agents", "autonomous"),
            build_args={
                "BUILDKIT_INLINE_CACHE": "1"
            }
        )
        
        bedrock_unified_image = ecr_assets.DockerImageAsset(
            self, "BedrockUnifiedImage",
            directory=os.path.join("..", "src", "agents", "bedrock_unified"),
            build_args={
                "BUILDKIT_INLINE_CACHE": "1"
            }
        )
        
        autonomous_code_analyzer_image = ecr_assets.DockerImageAsset(
            self, "AutonomousCodeAnalyzerImage",
            directory=os.path.join("..", "src", "agents", "autonomous_code_analyzer"),
            build_args={
                "BUILDKIT_INLINE_CACHE": "1"
            }
        )
        
        autonomous_threat_intel_image = ecr_assets.DockerImageAsset(
            self, "AutonomousThreatIntelImage",
            directory=os.path.join("..", "src", "agents", "autonomous_threat_intel"),
            build_args={
                "BUILDKIT_INLINE_CACHE": "1"
            }
        )
        
        autonomous_infra_security_image = ecr_assets.DockerImageAsset(
            self, "AutonomousInfraSecurityImage",
            directory=os.path.join("..", "src", "agents", "autonomous_infra_security"),
            build_args={
                "BUILDKIT_INLINE_CACHE": "1"
            }
        )
        
        autonomous_supply_chain_image = ecr_assets.DockerImageAsset(
            self, "AutonomousSupplyChainImage",
            directory=os.path.join("..", "src", "agents", "autonomous_supply_chain"),
            build_args={
                "BUILDKIT_INLINE_CACHE": "1"
            }
        )
        
        # Configure EFS volume for all task definitions
        efs_volume_config = ecs.Volume(
            name="efs-repository",
            efs_volume_configuration=ecs.EfsVolumeConfiguration(
                file_system_id=efs_filesystem.file_system_id,
                transit_encryption="ENABLED",
                authorization_config=ecs.AuthorizationConfig(
                    access_point_id=efs_access_point.access_point_id,
                    iam="ENABLED"
                )
            )
        )
        
        # Autonomous Task Definition
        self.autonomous_task_definition = ecs.FargateTaskDefinition(
            self, "AutonomousTaskDefinition",
            execution_role=task_execution_role,
            task_role=autonomous_task_role,
            cpu=2048,  # 2 vCPU
            memory_limit_mib=4096,  # 4 GB
            runtime_platform=ecs.RuntimePlatform(
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
                cpu_architecture=ecs.CpuArchitecture.X86_64
            ),
            volumes=[efs_volume_config]
        )
        
        autonomous_container = self.autonomous_task_definition.add_container(
            "autonomous-agent",
            image=ecs.ContainerImage.from_docker_image_asset(autonomous_image),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="autonomous",
                log_group=self.log_group
            ),
            environment={
                "RESULTS_BUCKET": results_bucket.bucket_name,
                "FINDINGS_TABLE": "SecurityFindings",
                "RULES_BUCKET": results_bucket.bucket_name,
                "LEARNING_INTERVAL_HOURS": "24",
                "AWS_REGION": self.region,
                "REPOSITORY_PATH": "/mnt/efs/repos"
            },
            memory_limit_mib=4096,
            cpu=2048
        )
        
        # Mount EFS volume
        autonomous_container.add_mount_points(
            ecs.MountPoint(
                container_path="/mnt/efs",
                source_volume="efs-repository",
                read_only=True
            )
        )
        
        # Bedrock Unified Task Definition
        self.bedrock_unified_task_definition = ecs.FargateTaskDefinition(
            self, "BedrockUnifiedTaskDefinition",
            execution_role=task_execution_role,
            task_role=bedrock_unified_task_role,
            cpu=4096,  # 4 vCPU - needs more power for AI processing
            memory_limit_mib=8192,  # 8 GB
            runtime_platform=ecs.RuntimePlatform(
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
                cpu_architecture=ecs.CpuArchitecture.X86_64
            ),
            volumes=[efs_volume_config],
            ephemeral_storage_gib=100  # More storage for AI model processing
        )
        
        bedrock_unified_container = self.bedrock_unified_task_definition.add_container(
            "bedrock-unified-agent",
            image=ecs.ContainerImage.from_docker_image_asset(bedrock_unified_image),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="bedrock-unified",
                log_group=self.log_group
            ),
            environment={
                "RESULTS_BUCKET": results_bucket.bucket_name,
                "AWS_REGION": self.region,
                "REPOSITORY_PATH": "/mnt/efs/repos",
                "BEDROCK_MODEL_ID": "anthropic.claude-3-sonnet-20240229-v1:0",
                "BEDROCK_REGION": self.region,
                "MAX_PARALLEL_SCANS": "10",
                "SCAN_TIMEOUT_MINUTES": "30"
            },
            memory_limit_mib=8192,
            cpu=4096
        )
        
        # Mount EFS volume
        bedrock_unified_container.add_mount_points(
            ecs.MountPoint(
                container_path="/mnt/efs",
                source_volume="efs-repository",
                read_only=True
            )
        )
        
        # Autonomous Code Analyzer Task Definition
        self.autonomous_code_analyzer_task_definition = ecs.FargateTaskDefinition(
            self, "AutonomousCodeAnalyzerTaskDefinition",
            execution_role=task_execution_role,
            task_role=autonomous_task_role,  # Reuse autonomous role for now
            cpu=4096,  # 4 vCPU - needs power for AI analysis
            memory_limit_mib=8192,  # 8 GB
            runtime_platform=ecs.RuntimePlatform(
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
                cpu_architecture=ecs.CpuArchitecture.X86_64
            ),
            volumes=[efs_volume_config],
            ephemeral_storage_gib=100
        )
        
        autonomous_code_analyzer_container = self.autonomous_code_analyzer_task_definition.add_container(
            "autonomous-code-analyzer-agent",
            image=ecs.ContainerImage.from_docker_image_asset(autonomous_code_analyzer_image),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="autonomous-code-analyzer",
                log_group=self.log_group
            ),
            environment={
                "RESULTS_BUCKET": results_bucket.bucket_name,
                "AWS_REGION": self.region,
                "REPOSITORY_PATH": "/mnt/efs/repos",
                "BEDROCK_MODEL_ID": "anthropic.claude-3-sonnet-20240229-v1:0",
                "MAX_WORKERS": "20"
            },
            memory_limit_mib=8192,
            cpu=4096
        )
        
        autonomous_code_analyzer_container.add_mount_points(
            ecs.MountPoint(
                container_path="/mnt/efs",
                source_volume="efs-repository",
                read_only=True
            )
        )
        
        # Autonomous Threat Intelligence Task Definition
        self.autonomous_threat_intel_task_definition = ecs.FargateTaskDefinition(
            self, "AutonomousThreatIntelTaskDefinition",
            execution_role=task_execution_role,
            task_role=autonomous_task_role,
            cpu=2048,  # 2 vCPU
            memory_limit_mib=4096,  # 4 GB
            runtime_platform=ecs.RuntimePlatform(
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
                cpu_architecture=ecs.CpuArchitecture.X86_64
            ),
            volumes=[efs_volume_config]
        )
        
        autonomous_threat_intel_container = self.autonomous_threat_intel_task_definition.add_container(
            "autonomous-threat-intel-agent",
            image=ecs.ContainerImage.from_docker_image_asset(autonomous_threat_intel_image),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="autonomous-threat-intel",
                log_group=self.log_group
            ),
            environment={
                "RESULTS_BUCKET": results_bucket.bucket_name,
                "AWS_REGION": self.region,
                "REPOSITORY_PATH": "/mnt/efs/repos",
                "BEDROCK_MODEL_ID": "anthropic.claude-3-opus-20240229-v1:0",
                "THREAT_DB_TABLE": "ThreatIntelligence"
            },
            memory_limit_mib=4096,
            cpu=2048
        )
        
        autonomous_threat_intel_container.add_mount_points(
            ecs.MountPoint(
                container_path="/mnt/efs",
                source_volume="efs-repository",
                read_only=True
            )
        )
        
        # Autonomous Infrastructure Security Task Definition
        self.autonomous_infra_security_task_definition = ecs.FargateTaskDefinition(
            self, "AutonomousInfraSecurityTaskDefinition",
            execution_role=task_execution_role,
            task_role=autonomous_task_role,
            cpu=2048,  # 2 vCPU
            memory_limit_mib=4096,  # 4 GB
            runtime_platform=ecs.RuntimePlatform(
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
                cpu_architecture=ecs.CpuArchitecture.X86_64
            ),
            volumes=[efs_volume_config]
        )
        
        autonomous_infra_security_container = self.autonomous_infra_security_task_definition.add_container(
            "autonomous-infra-security-agent",
            image=ecs.ContainerImage.from_docker_image_asset(autonomous_infra_security_image),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="autonomous-infra-security",
                log_group=self.log_group
            ),
            environment={
                "RESULTS_BUCKET": results_bucket.bucket_name,
                "AWS_REGION": self.region,
                "REPOSITORY_PATH": "/mnt/efs/repos",
                "BEDROCK_MODEL_ID": "anthropic.claude-3-sonnet-20240229-v1:0",
                "MAX_WORKERS": "15"
            },
            memory_limit_mib=4096,
            cpu=2048
        )
        
        autonomous_infra_security_container.add_mount_points(
            ecs.MountPoint(
                container_path="/mnt/efs",
                source_volume="efs-repository",
                read_only=True
            )
        )
        
        # Autonomous Supply Chain Security Task Definition
        self.autonomous_supply_chain_task_definition = ecs.FargateTaskDefinition(
            self, "AutonomousSupplyChainTaskDefinition",
            execution_role=task_execution_role,
            task_role=autonomous_task_role,
            cpu=2048,  # 2 vCPU
            memory_limit_mib=4096,  # 4 GB
            runtime_platform=ecs.RuntimePlatform(
                operating_system_family=ecs.OperatingSystemFamily.LINUX,
                cpu_architecture=ecs.CpuArchitecture.X86_64
            ),
            volumes=[efs_volume_config]
        )
        
        autonomous_supply_chain_container = self.autonomous_supply_chain_task_definition.add_container(
            "autonomous-supply-chain-agent",
            image=ecs.ContainerImage.from_docker_image_asset(autonomous_supply_chain_image),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="autonomous-supply-chain",
                log_group=self.log_group
            ),
            environment={
                "RESULTS_BUCKET": results_bucket.bucket_name,
                "AWS_REGION": self.region,
                "REPOSITORY_PATH": "/mnt/efs/repos",
                "BEDROCK_MODEL_ID": "anthropic.claude-3-opus-20240229-v1:0",
                "SUPPLY_CHAIN_TABLE": "SupplyChainIntelligence",
                "MAX_WORKERS": "10"
            },
            memory_limit_mib=4096,
            cpu=2048
        )
        
        autonomous_supply_chain_container.add_mount_points(
            ecs.MountPoint(
                container_path="/mnt/efs",
                source_volume="efs-repository",
                read_only=True
            )
        )
        
        # Add health checks to all containers
        all_containers = [
            autonomous_container,
            bedrock_unified_container,
            autonomous_code_analyzer_container,
            autonomous_threat_intel_container,
            autonomous_infra_security_container,
            autonomous_supply_chain_container
        ]
        
        for container in all_containers:
            container.add_ulimits(ecs.Ulimit(
                hard_limit=65536,
                name=ecs.UlimitName.NOFILE,
                soft_limit=65536
            ))