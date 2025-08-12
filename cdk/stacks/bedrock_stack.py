"""
AWS CDK Stack for Bedrock AI Security Scanner
"""
from aws_cdk import (
    Stack,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_ecs as ecs,
    aws_ec2 as ec2,
    aws_logs as logs,
    Duration,
    RemovalPolicy
)
from constructs import Construct


class BedrockSecurityStack(Stack):
    """Stack for Bedrock-powered AI security scanning"""
    
    def __init__(self, scope: Construct, construct_id: str, 
                 vpc: ec2.Vpc,
                 ecs_cluster: ecs.Cluster,
                 results_bucket,
                 scan_table,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # IAM role for Bedrock access
        bedrock_execution_role = iam.Role(
            self, "BedrockExecutionRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("lambda.amazonaws.com"),
                iam.ServicePrincipal("ecs-tasks.amazonaws.com")
            ),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ]
        )
        
        # Add Bedrock permissions
        bedrock_execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream"
                ],
                resources=[
                    f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0",
                    f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-3-opus-20240229-v1:0",
                    f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-instant-v1"
                ]
            )
        )
        
        # S3 permissions
        results_bucket.grant_read_write(bedrock_execution_role)
        
        # DynamoDB permissions
        scan_table.grant_read_write_data(bedrock_execution_role)
        
        # Lambda function for Bedrock unified scanner
        self.bedrock_scanner_lambda = lambda_.Function(
            self, "BedrockUnifiedScanner",
            runtime=lambda_.Runtime.PYTHON_3_11,
            code=lambda_.Code.from_asset("src/agents/bedrock_unified"),
            handler="agent.handler",
            role=bedrock_execution_role,
            timeout=Duration.minutes(15),  # Max Lambda timeout
            memory_size=10240,  # 10GB memory for large file processing
            environment={
                "BEDROCK_MODEL_ID": "anthropic.claude-3-sonnet-20240229-v1:0",
                "RESULTS_BUCKET": results_bucket.bucket_name,
                "SCAN_TABLE": scan_table.table_name,
                "MAX_WORKERS": "10"
            },
            reserved_concurrent_executions=10  # Limit concurrent executions
        )
        
        # ECS Task Definition for long-running scans
        self.bedrock_task_definition = ecs.FargateTaskDefinition(
            self, "BedrockScannerTaskDef",
            memory_limit_mib=30720,  # 30GB memory
            cpu=4096,  # 4 vCPU
            execution_role=bedrock_execution_role,
            task_role=bedrock_execution_role,
            family="bedrock-ai-scanner"
        )
        
        # Add container for Bedrock scanner
        bedrock_container = self.bedrock_task_definition.add_container(
            "bedrock-scanner",
            image=ecs.ContainerImage.from_asset(
                "src/agents/bedrock_unified",
                platform=ecs.Platform.LINUX_AMD64
            ),
            environment={
                "BEDROCK_MODEL_ID": "anthropic.claude-3-sonnet-20240229-v1:0",
                "RESULTS_BUCKET": results_bucket.bucket_name,
                "SCAN_TABLE": scan_table.table_name,
                "MAX_WORKERS": "20",  # More workers for ECS
                "EXECUTION_MODE": "ECS"
            },
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="bedrock-scanner",
                log_retention=logs.RetentionDays.ONE_WEEK
            ),
            memory_limit_mib=30720,
            cpu=4096
        )
        
        # Create ECS service for processing large repositories
        self.bedrock_service = ecs.FargateService(
            self, "BedrockScannerService",
            cluster=ecs_cluster,
            task_definition=self.bedrock_task_definition,
            desired_count=0,  # Scale on demand
            assign_public_ip=False,
            security_groups=[self._create_security_group(vpc)],
            service_name="bedrock-ai-scanner"
        )
        
        # Auto-scaling for ECS service
        scaling = self.bedrock_service.auto_scale_task_count(
            min_capacity=0,
            max_capacity=10
        )
        
        # Scale based on SQS queue depth (if using queue)
        # scaling.scale_on_metric(...)
        
        # Lambda for quick scans (small repos)
        self.quick_scan_lambda = lambda_.Function(
            self, "BedrockQuickScan",
            runtime=lambda_.Runtime.PYTHON_3_11,
            code=lambda_.Code.from_asset("src/agents/bedrock_sast"),
            handler="agent.handler",
            role=bedrock_execution_role,
            timeout=Duration.minutes(5),
            memory_size=3008,
            environment={
                "BEDROCK_MODEL_ID": "anthropic.claude-instant-v1",  # Faster model for quick scans
                "RESULTS_BUCKET": results_bucket.bucket_name
            }
        )
        
        # Lambda for specialized AI analysis
        self.specialized_scanners = {}
        
        # Create specialized AI scanners
        scanner_configs = [
            {
                "name": "BedrockSecrets",
                "description": "AI-powered secrets detection",
                "prompt_focus": "credentials, keys, tokens, passwords"
            },
            {
                "name": "BedrockDependency", 
                "description": "AI-powered dependency analysis",
                "prompt_focus": "package vulnerabilities, supply chain risks"
            },
            {
                "name": "BedrockBusinessLogic",
                "description": "AI-powered business logic analysis", 
                "prompt_focus": "authorization, workflows, state management"
            },
            {
                "name": "BedrockInfrastructure",
                "description": "AI-powered IaC analysis",
                "prompt_focus": "misconfigurations, exposed resources, IAM policies"
            }
        ]
        
        for config in scanner_configs:
            scanner = lambda_.Function(
                self, config["name"],
                runtime=lambda_.Runtime.PYTHON_3_11,
                code=lambda_.Code.from_asset("src/agents/bedrock_unified"),
                handler="agent.handler",
                role=bedrock_execution_role,
                timeout=Duration.minutes(10),
                memory_size=3008,
                environment={
                    "BEDROCK_MODEL_ID": "anthropic.claude-3-sonnet-20240229-v1:0",
                    "RESULTS_BUCKET": results_bucket.bucket_name,
                    "SCAN_TABLE": scan_table.table_name,
                    "SCANNER_TYPE": config["name"],
                    "PROMPT_FOCUS": config["prompt_focus"]
                },
                description=config["description"]
            )
            self.specialized_scanners[config["name"]] = scanner
    
    def _create_security_group(self, vpc: ec2.Vpc) -> ec2.SecurityGroup:
        """Create security group for Bedrock scanner"""
        sg = ec2.SecurityGroup(
            self, "BedrockScannerSG",
            vpc=vpc,
            description="Security group for Bedrock AI scanner",
            allow_all_outbound=True
        )
        
        # No inbound rules needed - only outbound to Bedrock API
        return sg