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
        
        # Add permissions for pulling from ECR with specific resources
        self.task_execution_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ecr:GetAuthorizationToken"
            ],
            resources=["*"]  # GetAuthorizationToken requires wildcard
        ))
        
        self.task_execution_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage"
            ],
            resources=[
                f"arn:aws:ecr:{self.region}:{self.account}:repository/security-audit/*",
                f"arn:aws:ecr:{self.region}:{self.account}:repository/cdk-*"
            ]
        ))
        
        # EFS permissions for task execution role with specific resources
        self.task_execution_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite"
            ],
            resources=[
                f"arn:aws:elasticfilesystem:{self.region}:{self.account}:file-system/*"
            ],
            conditions={
                "StringEquals": {
                    "elasticfilesystem:AccessPointArn": f"arn:aws:elasticfilesystem:{self.region}:{self.account}:access-point/*"
                }
            }
        ))
        
        self.task_execution_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "elasticfilesystem:DescribeMountTargets"
            ],
            resources=[
                f"arn:aws:elasticfilesystem:{self.region}:{self.account}:file-system/*"
            ]
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
                resources=[f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:git-credentials-*"]
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
        # Note: Most Cost Explorer APIs require wildcard permissions
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
                "sts:GetCallerIdentity"
            ],
            resources=["*"],  # These services require wildcard
            conditions={
                "StringEquals": {
                    "aws:RequestedRegion": self.region
                }
            }
        ))
        
        # Budgets access with specific resources
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "budgets:DescribeBudget",
                "budgets:DescribeBudgets"
            ],
            resources=[
                f"arn:aws:budgets::{self.account}:budget/*"
            ]
        ))
        
        # CloudWatch metrics with specific namespace
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "cloudwatch:GetMetricStatistics"
            ],
            resources=["*"],
            conditions={
                "StringEquals": {
                    "cloudwatch:namespace": ["AWS/Lambda", "AWS/ECS", "AWS/EC2", "AWS/S3"]
                }
            }
        ))
        
        # Security Hub access with regional restriction
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "securityhub:BatchImportFindings",
                "securityhub:GetFindings",
                "securityhub:UpdateFindings"
            ],
            resources=[
                f"arn:aws:securityhub:{self.region}:{self.account}:hub/default",
                f"arn:aws:securityhub:{self.region}:{self.account}:product/*"
            ]
        ))
        
        # SNS permissions for notifications with specific topics
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "sns:Publish"
            ],
            resources=[
                f"arn:aws:sns:{self.region}:{self.account}:*security*"
            ]
        ))
        
        # SES permissions for email notifications
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ses:SendEmail",
                "ses:SendRawEmail"
            ],
            resources=[
                f"arn:aws:ses:{self.region}:{self.account}:identity/*"
            ],
            conditions={
                "StringEquals": {
                    "ses:FromAddress": "security-scans@example.com"
                }
            }
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
        
        # Secrets Manager access with specific prefixes
        self.lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["secretsmanager:GetSecretValue"],
            resources=[
                f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:security-audit/*",
                f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:git-credentials-*"
            ]
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
        
        # QuickSight Dashboard Lambda Role
        self.quicksight_dashboard_role = iam.Role(
            self, "QuickSightDashboardRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            ],
            description="Role for QuickSight Dashboard Lambda function"
        )
        
        # Grant QuickSight Dashboard Lambda permissions
        scan_table.grant_read_write_data(self.quicksight_dashboard_role)
        results_bucket.grant_read_write(self.quicksight_dashboard_role)
        
        # QuickSight permissions for dashboard creation and management
        self.quicksight_dashboard_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                # Data source permissions
                "quicksight:CreateDataSource",
                "quicksight:DescribeDataSource",
                "quicksight:DescribeDataSourcePermissions",
                "quicksight:PassDataSource",
                "quicksight:UpdateDataSource",
                "quicksight:DeleteDataSource",
                "quicksight:UpdateDataSourcePermissions",
                # Dataset permissions
                "quicksight:CreateDataSet",
                "quicksight:DescribeDataSet",
                "quicksight:DescribeDataSetPermissions",
                "quicksight:PassDataSet",
                "quicksight:DescribeIngestion",
                "quicksight:ListIngestions",
                "quicksight:UpdateDataSet",
                "quicksight:DeleteDataSet",
                "quicksight:CreateIngestion",
                "quicksight:CancelIngestion",
                "quicksight:UpdateDataSetPermissions",
                # Analysis permissions
                "quicksight:CreateAnalysis",
                "quicksight:DescribeAnalysis",
                "quicksight:DescribeAnalysisPermissions",
                "quicksight:UpdateAnalysis",
                "quicksight:DeleteAnalysis",
                "quicksight:QueryAnalysis",
                "quicksight:RestoreAnalysis",
                "quicksight:UpdateAnalysisPermissions",
                # Dashboard permissions
                "quicksight:CreateDashboard",
                "quicksight:DescribeDashboard",
                "quicksight:ListDashboardVersions",
                "quicksight:UpdateDashboardPermissions",
                "quicksight:QueryDashboard",
                "quicksight:UpdateDashboard",
                "quicksight:DeleteDashboard",
                "quicksight:DescribeDashboardPermissions",
                "quicksight:UpdateDashboardPublishedVersion",
                # Template permissions
                "quicksight:CreateTemplate",
                "quicksight:DescribeTemplate",
                "quicksight:UpdateTemplate",
                "quicksight:DeleteTemplate",
                "quicksight:UpdateTemplatePermissions",
                "quicksight:DescribeTemplatePermissions",
                # Embed URL permissions
                "quicksight:GenerateEmbedUrlForAnonymousUser",
                "quicksight:GenerateEmbedUrlForRegisteredUser",
                # Other necessary permissions
                "quicksight:ListUserGroups",
                "quicksight:DescribeAccountSettings",
                "quicksight:DescribeUser"
            ],
            resources=["*"]
        ))
        
        # Athena permissions for QuickSight data source
        self.quicksight_dashboard_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "athena:GetDatabase",
                "athena:GetDataCatalog",
                "athena:GetTableMetadata",
                "athena:ListDatabases",
                "athena:ListTableMetadata",
                "athena:StartQueryExecution",
                "athena:StopQueryExecution",
                "athena:GetQueryExecution",
                "athena:GetQueryResults",
                "athena:GetWorkGroup"
            ],
            resources=["*"]
        ))
        
        # Glue catalog permissions for Athena
        self.quicksight_dashboard_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "glue:GetDatabase",
                "glue:GetDatabases",
                "glue:GetTable",
                "glue:GetTables",
                "glue:GetPartitions"
            ],
            resources=["*"]
        ))
        
        # S3 permissions for Athena query results
        self.quicksight_dashboard_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:PutObject",
                "s3:GetObjectVersion"
            ],
            resources=[
                results_bucket.bucket_arn,
                f"{results_bucket.bucket_arn}/*"
            ]
        ))
        
        # CEO Agent Lambda Role
        self.ceo_agent_role = iam.Role(
            self, "CEOAgentRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            ],
            description="Role for CEO Agent Lambda function"
        )
        
        # Grant CEO Agent permissions
        scan_table.grant_read_write_data(self.ceo_agent_role)
        results_bucket.grant_read_write(self.ceo_agent_role)
        
        # Bedrock access for AI-powered CEO agent
        self.ceo_agent_role.add_to_policy(iam.PolicyStatement(
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
        
        # Cost Explorer access for budget management
        self.ceo_agent_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ce:GetCostAndUsage",
                "ce:GetCostForecast",
                "pricing:GetProducts",
                "pricing:DescribeServices"
            ],
            resources=["*"]
        ))
        
        # ECS permissions for CEO agent to orchestrate tasks
        self.ceo_agent_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ecs:RunTask",
                "ecs:StopTask",
                "ecs:DescribeTasks"
            ],
            resources=["*"]
        ))
        
        # Pass role permissions for ECS tasks
        self.ceo_agent_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["iam:PassRole"],
            resources=[
                self.task_execution_role.role_arn,
                self.autonomous_task_role.role_arn,
                self.bedrock_unified_task_role.role_arn
            ]
        ))
        
        # EFS permissions for repository access
        self.ceo_agent_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:DescribeMountTargets"
            ],
            resources=["*"]
        ))
        
        # Secrets Manager access for Git credentials
        self.ceo_agent_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["secretsmanager:GetSecretValue"],
            resources=[
                f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:git-credentials-*",
                f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:security-audit/*"
            ]
        ))
        
        # Aggregator Lambda Role
        self.aggregator_role = iam.Role(
            self, "AggregatorRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            ],
            description="Role for Aggregator Lambda function"
        )
        
        # Grant Aggregator permissions
        scan_table.grant_read_write_data(self.aggregator_role)
        results_bucket.grant_read_write(self.aggregator_role)
        
        # DynamoDB access for deduplication
        self.aggregator_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:BatchWriteItem"
            ],
            resources=[
                f"arn:aws:dynamodb:{self.region}:{self.account}:table/*"
            ]
        ))
        
        # Report Generator Lambda Role
        self.report_generator_role = iam.Role(
            self, "ReportGeneratorRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            ],
            description="Role for Report Generator Lambda function"
        )
        
        # Grant Report Generator permissions
        scan_table.grant_read_write_data(self.report_generator_role)
        results_bucket.grant_read_write(self.report_generator_role)
        
        # SES permissions for email reports
        self.report_generator_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ses:SendEmail",
                "ses:SendRawEmail"
            ],
            resources=["*"]
        ))
        
        # SNS permissions for notifications
        self.report_generator_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["sns:Publish"],
            resources=["*"]
        ))
        
        # Lambda invoke permissions for QuickSight dashboard generation
        self.report_generator_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["lambda:InvokeFunction"],
            resources=[
                f"arn:aws:lambda:{self.region}:{self.account}:function:*"
            ]
        ))
        
        # Remediation Lambda Role
        self.remediation_lambda_role = iam.Role(
            self, "RemediationLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            ],
            description="Role for Remediation Lambda function"
        )
        
        # Grant Remediation Lambda permissions
        scan_table.grant_read_write_data(self.remediation_lambda_role)
        results_bucket.grant_read_write(self.remediation_lambda_role)
        
        # IAM permissions for remediation actions
        self.remediation_lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "iam:UpdateAccessKey",
                "iam:DeleteAccessKey",
                "iam:TagUser",
                "iam:TagRole"
            ],
            resources=["*"],
            conditions={
                "StringEquals": {
                    "aws:RequestedRegion": self.region
                }
            }
        ))
        
        # Secrets Manager permissions for rotation
        self.remediation_lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "secretsmanager:RotateSecret",
                "secretsmanager:UpdateSecretVersionStage"
            ],
            resources=["*"]
        ))
        
        # SNS permissions for alerts
        self.remediation_lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["sns:Publish"],
            resources=["*"]
        ))
        
        # Athena Setup Lambda Role
        self.athena_setup_role = iam.Role(
            self, "AthenaSetupRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            ],
            description="Role for Athena Setup Lambda function"
        )
        
        # Grant Athena Setup permissions
        scan_table.grant_read_write_data(self.athena_setup_role)
        results_bucket.grant_read_write(self.athena_setup_role)
        
        # Athena permissions
        self.athena_setup_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "athena:*"
            ],
            resources=["*"]
        ))
        
        # Glue permissions for database and table operations
        self.athena_setup_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "glue:CreateDatabase",
                "glue:GetDatabase",
                "glue:GetDatabases",
                "glue:UpdateDatabase",
                "glue:DeleteDatabase",
                "glue:CreateTable",
                "glue:GetTable",
                "glue:GetTables",
                "glue:UpdateTable",
                "glue:DeleteTable",
                "glue:BatchCreatePartition",
                "glue:CreatePartition",
                "glue:GetPartition",
                "glue:GetPartitions",
                "glue:UpdatePartition",
                "glue:DeletePartition",
                "glue:BatchDeletePartition"
            ],
            resources=["*"]
        ))
        
        # S3 permissions for Athena query results and data access
        self.athena_setup_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:PutObject",
                "s3:GetObjectVersion",
                "s3:ListBucketMultipartUploads",
                "s3:AbortMultipartUpload",
                "s3:ListMultipartUploadParts"
            ],
            resources=[
                results_bucket.bucket_arn,
                f"{results_bucket.bucket_arn}/*"
            ]
        ))
        
        # Data Transformer Lambda Role
        self.data_transformer_role = iam.Role(
            self, "DataTransformerRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            ],
            description="Role for Data Transformer Lambda function"
        )
        
        # Grant Data Transformer permissions
        scan_table.grant_read_write_data(self.data_transformer_role)
        results_bucket.grant_read_write(self.data_transformer_role)
        
        # S3 permissions for reading agent outputs and writing Athena data
        self.data_transformer_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket"
            ],
            resources=[
                results_bucket.bucket_arn,
                f"{results_bucket.bucket_arn}/*"
            ]
        ))
        
        # DynamoDB permissions for scan metadata
        self.data_transformer_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "dynamodb:GetItem",
                "dynamodb:UpdateItem"
            ],
            resources=[
                scan_table.table_arn
            ]
        ))