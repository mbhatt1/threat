"""
IAM Stack - Roles and policies for AI-Powered Security Audit Framework
"""
from aws_cdk import (
    Stack,
    aws_iam as iam,
    aws_s3 as s3,
    aws_dynamodb as dynamodb
)
from constructs import Construct


class IAMStack(Stack):
    """IAM roles and policies for AI-Powered Security Audit Framework"""
    
    def __init__(self, scope: Construct, construct_id: str, 
                 results_bucket: s3.Bucket, scan_table: dynamodb.Table, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # ECS Task Execution Role (for pulling images and writing logs)
        self.task_execution_role = iam.Role(
            self, "ECSTaskExecutionRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonECSTaskExecutionRolePolicy")
            ]
        )
        
        # Add permissions for pulling from ECR
        self.task_execution_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage"
            ],
            resources=["*"]
        ))
        
        # EFS permissions for task execution role
        self.task_execution_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:DescribeMountTargets"
            ],
            resources=["*"]
        ))
        
        # Autonomous Agent Task Role
        self.autonomous_task_role = iam.Role(
            self, "AutonomousTaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description="Role for Autonomous ML-powered security agent"
        )
        
        # Grant S3 access to Autonomous role
        results_bucket.grant_read_write(self.autonomous_task_role, "raw/*/autonomous/*")
        results_bucket.grant_read_write(self.autonomous_task_role, "rules/*")
        results_bucket.grant_read(self.autonomous_task_role, "raw/*")  # Read all findings
        
        # Grant DynamoDB access for learning
        self.autonomous_task_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem"
            ],
            resources=[
                f"arn:aws:dynamodb:{self.region}:{self.account}:table/SecurityFindings",
                f"arn:aws:dynamodb:{self.region}:{self.account}:table/SecurityFindings/*"
            ]
        ))
        
        # Bedrock Unified Security Scanner Task Role
        self.bedrock_unified_task_role = iam.Role(
            self, "BedrockUnifiedTaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description="Role for Bedrock AI-powered unified security scanner"
        )
        
        # Grant S3 access to Bedrock Unified role
        results_bucket.grant_read_write(self.bedrock_unified_task_role, "raw/*/bedrock/*")
        results_bucket.grant_read_write(self.bedrock_unified_task_role, "analysis/*")
        
        # Grant Bedrock model access
        self.bedrock_unified_task_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream"
            ],
            resources=[
                f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-3-sonnet*",
                f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-3-opus*",
                f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-instant*"
            ]
        ))
        
        # Grant Secrets Manager access for Git credentials
        for role in [self.autonomous_task_role, self.bedrock_unified_task_role]:
            role.add_to_policy(iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["secretsmanager:GetSecretValue"],
                resources=["arn:aws:secretsmanager:*:*:secret:git-credentials-*"]
            ))
        
        # Lambda Role (shared by all Lambda functions)
        self.lambda_role = iam.Role(
            self, "LambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            ],
            description="Shared role for Lambda functions"
        )
        
        # Grant Lambda permissions
        scan_table.grant_read_write_data(self.lambda_role)
        results_bucket.grant_read_write(self.lambda_role)
        
        # Bedrock access for AI-powered CEO agent
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream"
            ],
            resources=[
                f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-3-sonnet*",
                f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-3-opus*"
            ]
        ))
        
        # Cost Explorer and Pricing API access for HASHIRU
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ce:GetCostAndUsage",
                "ce:GetCostForecast",
                "ce:GetAnomalies",
                "ce:GetAnomalyMonitors",
                "ce:CreateAnomalyMonitor",
                "ce:GetRightsizingRecommendation",
                "ce:GetReservationPurchaseRecommendation",
                "ce:GetCostCategories",
                "ce:GetTags",
                "pricing:GetProducts",
                "pricing:DescribeServices",
                "budgets:DescribeBudget",
                "budgets:DescribeBudgets",
                "cloudwatch:GetMetricStatistics",
                "sts:GetCallerIdentity"
            ],
            resources=["*"]
        ))
        
        # Security Hub access
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "securityhub:BatchImportFindings",
                "securityhub:GetFindings",
                "securityhub:UpdateFindings"
            ],
            resources=["*"]
        ))
        
        # SNS and SES permissions for notifications
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "sns:Publish",
                "ses:SendEmail",
                "ses:SendRawEmail"
            ],
            resources=["*"]
        ))
        
        # QuickSight access
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "quicksight:CreateIngestion",
                "quicksight:DescribeDataSet",
                "quicksight:CreateDataSet",
                "quicksight:UpdateDataSet"
            ],
            resources=["*"]
        ))
        
        # DynamoDB access for findings and learning tables
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:BatchWriteItem"
            ],
            resources=[
                f"arn:aws:dynamodb:{self.region}:{self.account}:table/*"
            ]
        ))
        
        # ECS access for running tasks
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ecs:RunTask",
                "ecs:StopTask",
                "ecs:DescribeTasks"
            ],
            resources=["*"]
        ))
        
        # Pass role permissions
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["iam:PassRole"],
            resources=[
                self.task_execution_role.role_arn,
                self.autonomous_task_role.role_arn,
                self.bedrock_unified_task_role.role_arn
            ]
        ))
        
        # Secrets Manager access
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["secretsmanager:GetSecretValue"],
            resources=["arn:aws:secretsmanager:*:*:secret:*"]
        ))
        
        # AI Security Analyzer Lambda Role
        self.ai_security_role = iam.Role(
            self, "AISecurityAnalyzerRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            ],
            description="Role for AI Security Analyzer Lambda function"
        )
        
        # Grant AI Security Analyzer permissions
        scan_table.grant_read_write_data(self.ai_security_role)
        results_bucket.grant_read_write(self.ai_security_role)
        
        # Enhanced Bedrock access for AI Security components
        self.ai_security_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream"
            ],
            resources=[
                f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-3-sonnet*",
                f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-3-opus*",
                f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-3-haiku*",
                f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-instant*"
            ]
        ))
        
        # DynamoDB access for AI Security components
        self.ai_security_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:BatchWriteItem",
                "dynamodb:BatchGetItem"
            ],
            resources=[
                f"arn:aws:dynamodb:{self.region}:{self.account}:table/*"
            ]
        ))
        
        # S3 access for AI model storage and results
        self.ai_security_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            resources=[
                results_bucket.bucket_arn,
                f"{results_bucket.bucket_arn}/*"
            ]
        ))
        
        # CloudWatch Logs for monitoring
        self.ai_security_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            resources=["arn:aws:logs:*:*:*"]
        ))
        
        # Security Hub integration
        self.ai_security_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "securityhub:BatchImportFindings",
                "securityhub:GetFindings",
                "securityhub:UpdateFindings"
            ],
            resources=["*"]
        ))
        
        # Step Functions State Machine Role
        self.state_machine_role = iam.Role(
            self, "StateMachineRole",
            assumed_by=iam.ServicePrincipal("states.amazonaws.com"),
            description="Role for Step Functions state machine"
        )
        
        # Grant permissions to invoke Lambda functions
        self.state_machine_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["lambda:InvokeFunction"],
            resources=[
                f"arn:aws:lambda:{self.region}:{self.account}:function:*"
            ]
        ))
        
        # Grant permissions to run ECS tasks
        self.state_machine_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ecs:RunTask",
                "ecs:StopTask",
                "ecs:DescribeTasks"
            ],
            resources=["*"]
        ))
        
        # Grant permissions to pass roles to ECS tasks
        self.state_machine_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["iam:PassRole"],
            resources=[
                self.task_execution_role.role_arn,
                self.autonomous_task_role.role_arn,
                self.bedrock_unified_task_role.role_arn
            ]
        ))
        
        # Grant SNS publish permissions
        self.state_machine_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["sns:Publish"],
            resources=["*"]
        ))
        
        # API Gateway Role
        self.api_gateway_role = iam.Role(
            self, "APIGatewayRole",
            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
            description="Role for API Gateway"
        )
        
        # Grant API Gateway permission to invoke Step Functions
        self.api_gateway_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["states:StartExecution"],
            resources=[
                f"arn:aws:states:{self.region}:{self.account}:stateMachine:*"
            ]
        ))