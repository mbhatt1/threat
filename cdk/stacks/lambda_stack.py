"""
Lambda Stack - Lambda functions for orchestration and processing
"""
from aws_cdk import (
    Stack,
    aws_lambda as lambda_,
    aws_lambda_python_alpha as lambda_python,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_s3 as s3,
    aws_dynamodb as dynamodb,
    aws_logs as logs,
    aws_efs as efs,
    aws_lambda_destinations as lambda_destinations,
    aws_kms as kms,
    Duration,
    RemovalPolicy,
    Size
)
from constructs import Construct
import os


class LambdaStack(Stack):
    """Lambda functions for Security Audit Framework"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 vpc: ec2.Vpc,
                 ceo_agent_role: iam.Role,
                 aggregator_role: iam.Role,
                 report_generator_role: iam.Role,
                 quicksight_dashboard_role: iam.Role,
                 remediation_lambda_role: iam.Role,
                 ai_security_role: iam.Role,
                 athena_setup_role: iam.Role,
                 data_transformer_role: iam.Role,
                 results_bucket: s3.Bucket,
                 scan_table: dynamodb.Table,
                 remediation_table: dynamodb.Table,
                 alert_topic_arn: str,
                 efs_filesystem: efs.FileSystem,
                 efs_access_point: efs.AccessPoint,
                 lambda_security_group: ec2.SecurityGroup,
                 kms_key=None,  # KMS key for environment variable encryption
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Lambda Layer for shared code
        shared_layer = lambda_python.PythonLayerVersion(
            self, "SharedLayer",
            entry=os.path.join("..", "src", "shared"),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_11],
            description="Shared code for Security Audit Framework",
            layer_version_name="security-audit-shared"
        )
        
        # Environment variables common to all Lambda functions
        common_env = {
            "RESULTS_BUCKET": results_bucket.bucket_name,
            "SCAN_TABLE": scan_table.table_name,
            "AWS_REGION": self.region,
            "PYTHONPATH": "/opt/python",
            "EXPLANATIONS_TABLE": f"security-explanations-{self.account}-{self.region}",
            "BUSINESS_CONTEXT_TABLE": f"security-business-context-{self.account}-{self.region}",
            "METRICS_BUCKET": f"security-audit-metrics-{self.account}-{self.region}",
            "SECURITY_LAKE_BUCKET": "aws-security-data-lake",
            "SECURITY_LAKE_PREFIX": "ext/SecurityAudit"
        }
        
        # CEO Agent Lambda with EFS mount
        self.ceo_agent_lambda = lambda_python.PythonFunction(
            self, "CEOAgentLambda",
            entry=os.path.join("..", "src", "lambdas", "ceo_agent"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            role=ceo_agent_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[lambda_security_group],
            environment={
                **common_env,
                "MAX_BUDGET_PER_SCAN": "10.0",
                "EFS_MOUNT_PATH": "/mnt/efs",
                "REPOSITORY_PATH": "/mnt/efs/repos"
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(5),
            memory_size=1024,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="HASHIRU CEO Agent - Plans and orchestrates security scans",
            filesystem=lambda_.FileSystem.from_efs_access_point(
                efs_access_point,
                "/mnt/efs"
            )
        )
        
        # Grant git binary execution permissions
        self.ceo_agent_lambda.add_environment("GIT_PYTHON_GIT_EXECUTABLE", "/opt/bin/git")
        
        # Repository Cloner Lambda
        self.repository_cloner_lambda = lambda_python.PythonFunction(
            self, "RepositoryClonerLambda",
            entry=os.path.join("..", "src", "lambdas", "repository_cloner"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.handler",
            index="handler.py",
            role=ceo_agent_role,  # Reuse CEO agent role as it has similar permissions
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[lambda_security_group],
            environment={
                **common_env,
                "EFS_MOUNT_PATH": "/mnt/efs",
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(10),  # Allow more time for large repos
            memory_size=2048,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="Clones Git repositories for security scanning",
            filesystem=lambda_.FileSystem.from_efs_access_point(
                efs_access_point,
                "/mnt/efs"
            )
        )
        
        # Grant permissions to access git binary
        self.repository_cloner_lambda.add_environment("GIT_PYTHON_GIT_EXECUTABLE", "/usr/bin/git")
        
        # Aggregator Lambda
        self.aggregator_lambda = lambda_python.PythonFunction(
            self, "AggregatorLambda",
            entry=os.path.join("..", "src", "lambdas", "aggregator"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            role=aggregator_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            environment=common_env,
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(5),
            memory_size=512,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="Aggregates and deduplicates findings from security agents"
        )
        
        # Report Generator Lambda
        self.report_generator_lambda = lambda_python.PythonFunction(
            self, "ReportGeneratorLambda",
            entry=os.path.join("..", "src", "lambdas", "report_generator"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            role=report_generator_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            environment={
                **common_env,
                "REPORT_EXPIRY_DAYS": "7",
                "SES_SENDER_EMAIL": "security-scans@example.com"  # Update with your verified email
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(10),
            memory_size=1024,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="Generates reports and sends notifications"
        )
        
        # QuickSight Dashboard Generator Lambda
        self.quicksight_dashboard_lambda = lambda_python.PythonFunction(
            self, "QuickSightDashboardLambda",
            entry=os.path.join("..", "src", "lambdas", "quicksight_dashboard"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            role=quicksight_dashboard_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            environment={
                **common_env,
                "AWS_ACCOUNT_ID": self.account,
                "ATHENA_DATABASE": "security_audit_findings",
                "QUICKSIGHT_USER_ARN": f"arn:aws:quicksight:{self.region}:{self.account}:user/default/Admin",
                "QUICKSIGHT_NAMESPACE": "default"
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(5),
            memory_size=512,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="Generates QuickSight dashboards for security scan visualization"
        )
        
        # Add QuickSight Lambda name to report generator environment
        self.report_generator_lambda.add_environment(
            "QUICKSIGHT_LAMBDA_NAME", self.quicksight_dashboard_lambda.function_name
        )
        
        # Add Athena setup Lambda name to report generator environment
        self.report_generator_lambda.add_environment(
            "ATHENA_SETUP_LAMBDA_NAME", self.athena_setup_lambda.function_name
        )
        
        # Grant report generator permission to invoke QuickSight Lambda
        self.quicksight_dashboard_lambda.grant_invoke(report_generator_role)
        
        # Grant report generator permission to invoke Athena setup Lambda
        self.athena_setup_lambda.grant_invoke(report_generator_role)
        
        # Add data transformer Lambda name to aggregator environment
        self.aggregator_lambda.add_environment(
            "DATA_TRANSFORMER_LAMBDA_NAME", self.data_transformer_lambda.function_name
        )
        
        # Grant aggregator permission to invoke data transformer
        self.data_transformer_lambda.grant_invoke(aggregator_role)
        
        # Remediation Lambda for automatic security response
        self.remediation_lambda = lambda_python.PythonFunction(
            self, "RemediationLambda",
            entry=os.path.join("..", "src", "lambdas", "remediation"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            role=remediation_lambda_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            environment={
                **common_env,
                "REMEDIATION_TABLE": remediation_table.table_name,
                "ALERT_TOPIC_ARN": alert_topic_arn,
                "APPROVED_ACTIONS": "rotate_secret,disable_key,tag_resource",
                "AUTO_REMEDIATE": "false"  # Require manual approval by default
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(5),
            memory_size=512,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="Handles automatic remediation of critical security findings"
        )
        
        # Grant remediation table permissions
        remediation_table.grant_read_write_data(remediation_lambda_role)
        
        # Make remediation Lambda accessible to secrets agent
        self.remediation_lambda_arn = self.remediation_lambda.function_arn
        
        # AI Security Analyzer Lambda
        # Create a code asset that includes both the lambda and ai_models directories
        ai_analyzer_code = lambda_.Code.from_asset(
            os.path.join("..", "src"),
            bundling=lambda_.BundlingOptions(
                image=lambda_.Runtime.PYTHON_3_11.bundling_image,
                command=[
                    "bash", "-c",
                    "pip install -r lambdas/ai_security_analyzer/requirements.txt -t /asset-output && " +
                    "cp -r lambdas/ai_security_analyzer/handler.py /asset-output/ && " +
                    "cp -r ai_models /asset-output/"
                ]
            )
        )
        
        self.ai_security_analyzer_lambda = lambda_.Function(
            self, "AISecurityAnalyzerLambda",
            code=ai_analyzer_code,
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            role=ai_security_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            environment={
                **common_env,
                "BEDROCK_MODEL_ID": "anthropic.claude-3-sonnet-20240229-v1:0",  # Hephaestus default
                "MAX_CONCURRENT_REQUESTS": "10",
                "ANALYSIS_TIMEOUT": "300",
                "HEPHAESTUS_MAX_FILES": "20",  # Limit files per batch for Hephaestus
                "HEPHAESTUS_DEFAULT_ITERATIONS": "2"  # Default cognitive iterations
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(15),
            memory_size=3008,  # Increased for Hephaestus cognitive analysis
            ephemeral_storage_size=Size.gibibytes(5),  # 5GB for processing large repos
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="AI-powered security analysis using AWS Bedrock with Hephaestus Cognitive AI"
        )
        
        # Make AI Security Analyzer Lambda accessible
        self.ai_security_analyzer_lambda_arn = self.ai_security_analyzer_lambda.function_arn
        
        # Athena Setup Lambda
        self.athena_setup_lambda = lambda_python.PythonFunction(
            self, "AthenaSetupLambda",
            entry=os.path.join("..", "src", "lambdas", "athena_setup"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            role=athena_setup_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            environment={
                **common_env,
                "ATHENA_DATABASE": "security_audit_findings",
                "ATHENA_RESULTS_LOCATION": f"s3://{results_bucket.bucket_name}/athena-results/"
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(5),
            memory_size=512,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="Sets up Athena tables and views for security findings analysis"
        )
        
        # Data Transformer Lambda
        self.data_transformer_lambda = lambda_python.PythonFunction(
            self, "DataTransformerLambda",
            entry=os.path.join("..", "src", "lambdas", "data_transformer"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            role=data_transformer_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            environment={
                **common_env,
                "ATHENA_DATABASE": "security_audit_findings"
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(5),
            memory_size=1024,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="Transforms agent findings to Athena-compatible format"
        )
        # Grant S3 permissions to invoke data transformer
        results_bucket.grant_read(self.data_transformer_lambda)
        
        # Note: S3 event notifications should be configured after stack deployment
        # to avoid circular dependencies. Alternatively, use EventBridge rules.
        
        # Attack Path Analysis Lambda
        self.attack_path_lambda = lambda_python.PythonFunction(
            self, "AttackPathLambda",
            entry=os.path.join("..", "src", "lambdas", "attack_path"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            role=ai_security_role,  # Reuse AI security role
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[lambda_security_group],
            environment={
                **common_env,
                "BEDROCK_MODEL_ID": "anthropic.claude-3-sonnet-20240229-v1:0",
                "MAX_PATH_DEPTH": "10"
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(10),
            memory_size=1024,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="Analyzes potential attack paths from security findings"
        )
        
        # Conditional Trigger Lambda
        self.conditional_trigger_lambda = lambda_python.PythonFunction(
            self, "ConditionalTriggerLambda",
            entry=os.path.join("..", "src", "lambdas", "conditional_trigger"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            role=ceo_agent_role,  # Use CEO agent role as lambda_role is not defined
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[lambda_security_group],
            environment={
                **common_env,
                "TRIGGER_RULES_TABLE": "ConditionalTriggerRules"
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(5),
            memory_size=512,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="Conditionally triggers security scans based on rules"
        )
        
        # Learning Lambda for ML model updates
        self.learning_lambda = lambda_python.PythonFunction(
            self, "LearningLambda",
            entry=os.path.join("..", "src", "lambdas", "learning"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            role=ai_security_role,  # Needs AI capabilities
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[lambda_security_group],
            environment={
                **common_env,
                "LEARNING_MODEL_BUCKET": results_bucket.bucket_name,
                "LEARNING_MODEL_PREFIX": "ml-models/",
                "TRAINING_DATA_TABLE": "SecurityFindingsTraining"
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.minutes(15),
            memory_size=2048,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="Updates ML models based on security findings feedback"
        )
        
        # SNS Handler Lambda
        self.sns_handler_lambda = lambda_.Function(
            self, "SNSHandlerLambda",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("../src/lambdas/sns_handler"),
            environment={
                "STATE_MACHINE_ARN": "",  # Will be set after step function creation
                "SCAN_TABLE_NAME": scan_table.table_name,
                "AI_SECURITY_ANALYZER_LAMBDA_ARN": self.ai_security_analyzer_lambda.function_arn
            },
            environment_encryption=kms_key,  # Encrypt environment variables with KMS
            timeout=Duration.seconds(60),
            memory_size=512,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.ONE_WEEK,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            security_groups=[lambda_security_group],
            description="Processes SNS messages to trigger security scans"
        )
        
        # Grant permissions for SNS handler
        scan_table.grant_read_write_data(self.sns_handler_lambda)
        self.ai_security_analyzer_lambda.grant_invoke(self.sns_handler_lambda)
        
        # ECR Scanning Enabler Lambda
        self.ecr_scanning_lambda = lambda_python.PythonFunction(
            self, "ECRScanningEnablerLambda",
            entry=os.path.join("..", "src", "lambdas", "ecr_scanning_enabler"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            environment={
                "LOG_LEVEL": "INFO"
            },
            environment_encryption=kms_key,
            timeout=Duration.minutes(2),
            memory_size=512,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.ONE_WEEK,
            description="Enables vulnerability scanning on ECR repositories"
        )
        
        # Grant ECR permissions
        self.ecr_scanning_lambda.add_to_role_policy(iam.PolicyStatement(
            actions=[
                "ecr:PutImageScanningConfiguration",
                "ecr:StartImageScan",
                "ecr:DescribeImageScanFindings",
                "ecr:PutLifecyclePolicy"
            ],
            resources=["*"]
        ))
        
        # Add concurrent execution limits to prevent runaway costs
        self.ceo_agent_lambda.add_function_url(
            auth_type=lambda_.FunctionUrlAuthType.AWS_IAM
        )
        
        # Set reserved concurrent executions
        ceo_agent_alias = self.ceo_agent_lambda.add_alias("live")
        ceo_agent_alias.configure_provisioned_concurrent_executions(0)  # No provisioned concurrency
        
        # Add Lambda insights for monitoring
        for fn in [self.ceo_agent_lambda, self.aggregator_lambda, self.report_generator_lambda,
                   self.quicksight_dashboard_lambda, self.remediation_lambda]:
            fn.add_layers(
                lambda_.LayerVersion.from_layer_version_arn(
                    self, f"{fn.node.id}-insights",
                    f"arn:aws:lambda:{self.region}:580247275435:layer:LambdaInsightsExtension:21"
                )
            )