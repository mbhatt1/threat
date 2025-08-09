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
    Duration,
    RemovalPolicy
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
                 results_bucket: s3.Bucket,
                 scan_table: dynamodb.Table,
                 remediation_table: dynamodb.Table,
                 alert_topic_arn: str,
                 efs_filesystem: efs.FileSystem,
                 efs_access_point: efs.AccessPoint,
                 lambda_security_group: ec2.SecurityGroup,
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
            "PYTHONPATH": "/opt/python"
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
                "ATHENA_DATABASE": "security_scans",
                "QUICKSIGHT_USER_ARN": f"arn:aws:quicksight:{self.region}:{self.account}:user/default/Admin",
                "QUICKSIGHT_NAMESPACE": "default"
            },
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
        
        # Grant report generator permission to invoke QuickSight Lambda
        self.quicksight_dashboard_lambda.grant_invoke(report_generator_role)
        
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
        self.ai_security_analyzer_lambda = lambda_python.PythonFunction(
            self, "AISecurityAnalyzerLambda",
            entry=os.path.join("..", "src", "lambdas", "ai_security_analyzer"),
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            index="handler.py",
            role=ai_security_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            environment={
                **common_env,
                "BEDROCK_MODEL_ID": "anthropic.claude-3-haiku-20240307-v1:0",
                "MAX_CONCURRENT_REQUESTS": "10",
                "ANALYSIS_TIMEOUT": "300"
            },
            timeout=Duration.minutes(15),
            memory_size=1024,
            layers=[shared_layer],
            log_retention=logs.RetentionDays.TWO_WEEKS,
            description="AI-powered security analysis using AWS Bedrock"
        )
        
        # Make AI Security Analyzer Lambda accessible
        self.ai_security_analyzer_lambda_arn = self.ai_security_analyzer_lambda.function_arn
        
        # SNS Handler Lambda
        self.sns_handler_lambda = lambda_.Function(
            self, "SNSHandlerLambda",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("../src/lambdas/sns_handler"),
            environment={
                "STATE_MACHINE_ARN": "",  # Will be set after step function creation
                "SCAN_TABLE_NAME": scan_table.table_name
            },
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