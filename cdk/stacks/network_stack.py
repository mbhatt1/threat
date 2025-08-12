"""
Network Stack - VPC and networking resources
"""
from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_efs as efs,
    RemovalPolicy
)
from constructs import Construct


class NetworkStack(Stack):
    """VPC and networking infrastructure for Security Audit Framework"""
    
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Create VPC with public and private subnets
        self.vpc = ec2.Vpc(
            self, "SecurityAuditVPC",
            max_azs=2,  # Use 2 AZs for HA
            nat_gateways=1,  # Single NAT Gateway for cost optimization
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24
                )
            ],
            enable_dns_hostnames=True,
            enable_dns_support=True
        )
        
        # VPC Flow Logs for security monitoring
        self.vpc.add_flow_log(
            "VPCFlowLog",
            traffic_type=ec2.FlowLogTrafficType.ALL,
            destination=ec2.FlowLogDestination.to_cloud_watch_logs()
        )
        
        # Security group for Lambda functions
        self.lambda_security_group = ec2.SecurityGroup(
            self, "LambdaSecurityGroup",
            vpc=self.vpc,
            description="Security group for Lambda functions",
            allow_all_outbound=True
        )
        
        # Security group for ECS tasks
        self.ecs_security_group = ec2.SecurityGroup(
            self, "ECSSecurityGroup",
            vpc=self.vpc,
            description="Security group for ECS tasks",
            allow_all_outbound=True
        )
        
        # VPC Endpoints for AWS services (cost optimization)
        # S3 Gateway endpoint
        self.vpc.add_gateway_endpoint(
            "S3Endpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3
        )
        
        # DynamoDB Gateway endpoint
        self.vpc.add_gateway_endpoint(
            "DynamoDBEndpoint",
            service=ec2.GatewayVpcEndpointAwsService.DYNAMODB
        )
        
        # Interface endpoints for other services
        # ECR endpoints for pulling Docker images
        self.vpc.add_interface_endpoint(
            "ECREndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR,
            private_dns_enabled=True
        )
        
        self.vpc.add_interface_endpoint(
            "ECRDockerEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
            private_dns_enabled=True
        )
        
        # Secrets Manager endpoint
        self.vpc.add_interface_endpoint(
            "SecretsManagerEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
            private_dns_enabled=True
        )
        
        # CloudWatch Logs endpoint
        self.vpc.add_interface_endpoint(
            "CloudWatchLogsEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            private_dns_enabled=True
        )
        
        # EFS Security Group
        self.efs_security_group = ec2.SecurityGroup(
            self, "EFSSecurityGroup",
            vpc=self.vpc,
            description="Security group for EFS mount targets",
            allow_all_outbound=False
        )
        
        # Allow NFS traffic from Lambda and ECS security groups
        self.efs_security_group.add_ingress_rule(
            peer=self.lambda_security_group,
            connection=ec2.Port.tcp(2049),
            description="Allow NFS from Lambda functions"
        )
        
        self.efs_security_group.add_ingress_rule(
            peer=self.ecs_security_group,
            connection=ec2.Port.tcp(2049),
            description="Allow NFS from ECS tasks"
        )
        
        # Create EFS filesystem for repository storage
        self.efs_filesystem = efs.FileSystem(
            self, "RepositoryStorage",
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            security_group=self.efs_security_group,
            encrypted=True,
            lifecycle_policy=efs.LifecyclePolicy.AFTER_30_DAYS,  # Move to IA after 30 days
            performance_mode=efs.PerformanceMode.GENERAL_PURPOSE,
            throughput_mode=efs.ThroughputMode.BURSTING,
            enable_automatic_backups=True,
            removal_policy=RemovalPolicy.DESTROY  # For dev/test - use RETAIN for production
        )
        
        # Create EFS access point for repository data
        self.efs_access_point = efs.AccessPoint(
            self, "RepositoryAccessPoint",
            file_system=self.efs_filesystem,
            path="/repos",
            create_acl=efs.Acl(
                owner_uid="1000",
                owner_gid="1000",
                permissions="755"
            ),
            posix_user=efs.PosixUser(
                uid="1000",
                gid="1000"
            )
        )
        
        # Grant access to Lambda and ECS security groups
        self.lambda_security_group.add_egress_rule(
            peer=self.efs_security_group,
            connection=ec2.Port.tcp(2049),
            description="Allow NFS to EFS"
        )
        
        self.ecs_security_group.add_egress_rule(
            peer=self.efs_security_group,
            connection=ec2.Port.tcp(2049),
            description="Allow NFS to EFS"
        )