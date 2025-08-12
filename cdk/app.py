#!/usr/bin/env python3
"""
CDK Application for AI-Based Security Audit Framework with Multiple Autonomous Agents
"""
import os
import aws_cdk as cdk

from stacks.network_stack import NetworkStack
from stacks.storage_stack import StorageStack
from stacks.iam_stack import IAMStack
from stacks.lambda_stack import LambdaStack
from stacks.ecs_stack import EcsStack
from stacks.step_function_stack import StepFunctionStack
from stacks.api_stack import APIStack
from stacks.sns_stack import SnsStack
from stacks.monitoring_stack import MonitoringStack
from stacks.bedrock_stack import BedrockSecurityStack
from stacks.security_services_stack import SecurityServicesStack
from stacks.parameters_stack import ParametersStack
from stacks.security_hardening_stack import SecurityHardeningStack
from stacks.certificate_stack import CertificateStack
from stacks.eventbridge_stack import EventBridgeStack
from stacks.quicksight_stack import QuickSightStack
from stacks.athena_stack import AthenaStack

app = cdk.App()

# Environment configuration
env = cdk.Environment(
    account=os.getenv('CDK_DEFAULT_ACCOUNT'),
    region=os.getenv('CDK_DEFAULT_REGION', 'us-east-1')
)

# Stack configurations
stack_prefix = app.node.try_get_context("stack_prefix") or "AISecurityAudit"

# Network infrastructure
network_stack = NetworkStack(
    app, f"{stack_prefix}-Network",
    env=env,
    description="Network infrastructure for AI Security Audit Framework"
)

# Storage resources
storage_stack = StorageStack(
    app, f"{stack_prefix}-Storage",
    env=env,
    description="Storage resources for scan results and AI intelligence"
)

# IAM roles and policies
iam_stack = IAMStack(
    app, f"{stack_prefix}-IAM",
    results_bucket=storage_stack.results_bucket,
    scan_table=storage_stack.scan_table,
    env=env,
    description="IAM roles for AI-powered security agents"
)

# Lambda functions for orchestration and processing
lambda_stack = LambdaStack(
    app, f"{stack_prefix}-Lambda",
    vpc=network_stack.vpc,
    ceo_agent_role=iam_stack.ceo_agent_role,
    aggregator_role=iam_stack.aggregator_role,
    report_generator_role=iam_stack.report_generator_role,
    quicksight_dashboard_role=iam_stack.quicksight_dashboard_role,
    remediation_lambda_role=iam_stack.remediation_lambda_role,
    ai_security_role=iam_stack.ai_security_role,
    athena_setup_role=iam_stack.athena_setup_role,
    data_transformer_role=iam_stack.data_transformer_role,
    results_bucket=storage_stack.results_bucket,
    scan_table=storage_stack.scan_table,
    remediation_table=storage_stack.remediation_table,
    alert_topic_arn="",  # Will be set later to avoid circular dependency
    efs_filesystem=network_stack.efs_filesystem,
    efs_access_point=network_stack.efs_access_point,
    lambda_security_group=network_stack.lambda_security_group,
    kms_key=storage_stack.kms_key,  # Pass KMS key for environment variable encryption
    env=env,
    description="Lambda functions for AI security orchestration"
)
lambda_stack.add_dependency(network_stack)
lambda_stack.add_dependency(storage_stack)
lambda_stack.add_dependency(iam_stack)

# SNS topics for event-driven architecture
sns_stack = SnsStack(
    app, f"{stack_prefix}-SNS",
    sns_handler_lambda=lambda_stack.sns_handler_lambda,
    env=env,
    description="SNS topics for AI security scan triggers"
)
sns_stack.add_dependency(lambda_stack)

# Now update the Lambda environment with the actual topic ARN
lambda_stack.remediation_lambda.add_environment(
    "ALERT_TOPIC_ARN", sns_stack.scan_request_topic.topic_arn
)

# ECS Stack for all Autonomous AI Agents
ecs_stack = EcsStack(
    app, f"{stack_prefix}-ECS",
    vpc=network_stack.vpc,
    task_execution_role=iam_stack.task_execution_role,
    autonomous_task_role=iam_stack.autonomous_task_role,
    bedrock_unified_task_role=iam_stack.bedrock_unified_task_role,
    results_bucket=storage_stack.results_bucket,
    efs_filesystem=network_stack.efs_filesystem,
    efs_access_point=network_stack.efs_access_point,
    ecs_security_group=network_stack.ecs_security_group,
    remediation_lambda_arn=lambda_stack.remediation_lambda.function_arn,
    env=env,
    description="ECS tasks for multiple autonomous AI security agents"
)
ecs_stack.add_dependency(network_stack)
ecs_stack.add_dependency(storage_stack)
ecs_stack.add_dependency(iam_stack)
ecs_stack.add_dependency(lambda_stack)

# Bedrock AI Security Stack
bedrock_stack = BedrockSecurityStack(
    app, f"{stack_prefix}-Bedrock",
    vpc=network_stack.vpc,
    ecs_cluster=ecs_stack.cluster,
    results_bucket=storage_stack.results_bucket,
    scan_table=storage_stack.scan_table,
    env=env,
    description="Bedrock AI-powered security scanning components"
)
bedrock_stack.add_dependency(network_stack)
bedrock_stack.add_dependency(ecs_stack)
bedrock_stack.add_dependency(storage_stack)

# Parameters Stack for configuration values
parameters_stack = ParametersStack(
    app, f"{stack_prefix}-Parameters",
    env=env,
    description="SSM parameters and secrets for security audit framework"
)

# Security Services Stack (GuardDuty, Security Hub, Config, etc.)
security_services_stack = SecurityServicesStack(
    app, f"{stack_prefix}-SecurityServices",
    results_bucket=storage_stack.results_bucket,
    env=env,
    description="AWS Security Services for enhanced protection and compliance"
)
security_services_stack.add_dependency(storage_stack)

# EventBridge Stack for automated triggers
eventbridge_stack = EventBridgeStack(
    app, f"{stack_prefix}-EventBridge",
    ecr_scanning_lambda=lambda_stack.ecr_scanning_lambda,
    cloudwatch_insights_lambda=lambda_stack.cloudwatch_insights_lambda,
    alert_topic=sns_stack.alert_topic,
    env=env,
    description="EventBridge rules for automated security scanning triggers"
)
eventbridge_stack.add_dependency(lambda_stack)
eventbridge_stack.add_dependency(sns_stack)

# QuickSight Stack for dashboards
quicksight_stack = QuickSightStack(
    app, f"{stack_prefix}-QuickSight",
    results_bucket=storage_stack.results_bucket,
    athena_results_bucket=storage_stack.athena_results_bucket,
    env=env,
    description="QuickSight configuration for security dashboards"
)
quicksight_stack.add_dependency(storage_stack)

# Athena Stack for data analytics
athena_stack = AthenaStack(
    app, f"{stack_prefix}-Athena",
    results_bucket=storage_stack.results_bucket,
    athena_results_bucket=storage_stack.athena_results_bucket,
    athena_setup_lambda=lambda_stack.athena_setup_lambda,
    env=env,
    description="Athena configuration for security scan analysis"
)
athena_stack.add_dependency(storage_stack)
athena_stack.add_dependency(lambda_stack)

# Step Functions for workflow orchestration
step_function_stack = StepFunctionStack(
    app, f"{stack_prefix}-StepFunctions",
    ceo_agent_lambda=lambda_stack.ceo_agent_lambda,
    ecs_cluster=ecs_stack.cluster,
    sns_topic=sns_stack.main_topic,
    aggregator_lambda=lambda_stack.aggregator_lambda,
    report_generator_lambda=lambda_stack.report_generator_lambda,
    remediation_lambda=lambda_stack.remediation_lambda,
    autonomous_task_definition=ecs_stack.autonomous_task_definition,
    bedrock_unified_task_definition=ecs_stack.bedrock_unified_task_definition,
    autonomous_code_analyzer_task_definition=ecs_stack.autonomous_code_analyzer_task_definition,
    autonomous_threat_intel_task_definition=ecs_stack.autonomous_threat_intel_task_definition,
    autonomous_infra_security_task_definition=ecs_stack.autonomous_infra_security_task_definition,
    autonomous_supply_chain_task_definition=ecs_stack.autonomous_supply_chain_task_definition,
    env=env,
    description="Step Functions for orchestrating multiple AI agents"
)
step_function_stack.add_dependency(ecs_stack)
step_function_stack.add_dependency(lambda_stack)
step_function_stack.add_dependency(network_stack)
step_function_stack.add_dependency(sns_stack)

# API Gateway for external access
api_stack = APIStack(
    app, f"{stack_prefix}-API",
    api_role=iam_stack.api_gateway_role,
    state_machine=step_function_stack.state_machine,
    scan_table=storage_stack.scan_table,
    ai_security_analyzer_lambda=lambda_stack.ai_security_analyzer_lambda,
    custom_authorizer_lambda=getattr(security_services_stack, 'custom_authorizer', None) if 'security_services_stack' in locals() else None,
    kms_key=storage_stack.kms_key,  # Pass KMS key for CloudWatch logs encryption
    env=env,
    description="API Gateway for AI Security Audit Framework"
)
api_stack.add_dependency(lambda_stack)
api_stack.add_dependency(iam_stack)
api_stack.add_dependency(step_function_stack)
if 'security_services_stack' in locals():
    api_stack.add_dependency(security_services_stack)

# Certificate management for HTTPS (optional - requires domain configuration)
# To enable: Set DOMAIN_NAME environment variable to your domain (e.g., example.com)
domain_name = os.getenv('DOMAIN_NAME')
if domain_name:
    certificate_stack = CertificateStack(
        app, f"{stack_prefix}-Certificate",
        domain_name=domain_name,
        api=api_stack.api,
        hosted_zone=None,  # Set to your Route53 hosted zone if available
        env=env,
        description="TLS/SSL certificate management for secure HTTPS endpoints"
    )
    certificate_stack.add_dependency(api_stack)
    
    # Output instructions for manual configuration
    cdk.CfnOutput(
        certificate_stack, "CertificateInstructions",
        value="Certificate created. If not using Route53, manually validate certificate in ACM console and configure DNS.",
        description="Certificate setup instructions"
    )
else:
    # Output instructions for enabling HTTPS
    cdk.CfnOutput(
        api_stack, "HTTPSInstructions",
        value="To enable HTTPS: Set DOMAIN_NAME environment variable and redeploy",
        description="Instructions for enabling HTTPS with custom domain"
    )

# Monitoring and observability
monitoring_stack = MonitoringStack(
    app, f"{stack_prefix}-Monitoring",
    alert_topic=sns_stack.alert_topic,
    lambdas={
        "ceo_agent": lambda_stack.ceo_agent_lambda,
        "aggregator": lambda_stack.aggregator_lambda,
        "report_generator": lambda_stack.report_generator_lambda,
        "remediation": lambda_stack.remediation_lambda,
        "quicksight_dashboard": lambda_stack.quicksight_dashboard_lambda,
        "athena_setup": lambda_stack.athena_setup_lambda,
        "data_transformer": lambda_stack.data_transformer_lambda,
        "ai_security_analyzer": lambda_stack.ai_security_analyzer_lambda,
        "sns_handler": lambda_stack.sns_handler_lambda,
        "ecr_scanning": lambda_stack.ecr_scanning_lambda
    },
    tables={
        "scan": storage_stack.scan_table,
        "remediation": storage_stack.remediation_table,
        "config": storage_stack.config_table,
        "ai_decisions": storage_stack.ai_decisions_table,
        "explanations": storage_stack.explanations_table,
        "business_context": storage_stack.business_context_table,
        "ai_scans": storage_stack.ai_scans_table,
        "ai_findings": storage_stack.ai_findings_table
    },
    buckets={
        "results": storage_stack.results_bucket,
        "reports": storage_stack.reports_bucket,
        "athena_results": storage_stack.athena_results_bucket
    },
    ecs_services=None,  # ECS services are task definitions, not services in this stack
    env=env,
    description="Monitoring for AI Security Audit Framework"
)
monitoring_stack.add_dependency(lambda_stack)
monitoring_stack.add_dependency(storage_stack)
monitoring_stack.add_dependency(sns_stack)

# Output important values
cdk.CfnOutput(
    app, "APIEndpoint",
    value=api_stack.api.url,
    description="API Gateway endpoint URL"
)

cdk.CfnOutput(
    app, "SNSTopic",
    value=sns_stack.main_topic.topic_arn,
    description="SNS topic for triggering scans"
)

cdk.CfnOutput(
    app, "StateMachineArn",
    value=step_function_stack.state_machine.state_machine_arn,
    description="Step Functions state machine ARN"
)

cdk.CfnOutput(
    app, "ECSCluster",
    value=ecs_stack.cluster.cluster_name,
    description="ECS cluster for AI agents"
)

cdk.CfnOutput(
    app, "ResultsBucket",
    value=storage_stack.results_bucket.bucket_name,
    description="S3 bucket for scan results"
)

# Security Hardening Stack for additional security measures
security_hardening_stack = SecurityHardeningStack(
    app, f"{stack_prefix}-SecurityHardening",
    alert_topic=sns_stack.alert_topic,
    lambdas={
        "ceo_agent": lambda_stack.ceo_agent_lambda,
        "aggregator": lambda_stack.aggregator_lambda,
        "report_generator": lambda_stack.report_generator_lambda,
        "remediation": lambda_stack.remediation_lambda,
        "ai_security_analyzer": lambda_stack.ai_security_analyzer_lambda
    },
    tables={
        "scan": storage_stack.scan_table,
        "remediation": storage_stack.remediation_table,
        "ai_findings": storage_stack.ai_findings_table,
        "ai_scans": storage_stack.ai_scans_table
    },
    buckets={
        "results": storage_stack.results_bucket,
        "reports": storage_stack.reports_bucket,
        "ai_policies": storage_stack.ai_policies_bucket
    },
    env=env,
    description="Additional security hardening measures"
)
security_hardening_stack.add_dependency(sns_stack)
security_hardening_stack.add_dependency(lambda_stack)
security_hardening_stack.add_dependency(storage_stack)

# Add tags to all stacks
for stack in [network_stack, storage_stack, iam_stack, lambda_stack,
              ecs_stack, step_function_stack, api_stack, sns_stack,
              monitoring_stack, bedrock_stack, security_services_stack,
              parameters_stack, security_hardening_stack, eventbridge_stack,
              quicksight_stack, athena_stack]:
    cdk.Tags.of(stack).add("Project", "AISecurityAudit")
    cdk.Tags.of(stack).add("Environment", os.getenv("ENVIRONMENT", "dev"))
    cdk.Tags.of(stack).add("ManagedBy", "CDK")
    cdk.Tags.of(stack).add("SecurityFramework", "Autonomous-AI-Agents")
    cdk.Tags.of(stack).add("AIModel", "Bedrock-Claude")
    # Add backup tag for resources that should be backed up
    cdk.Tags.of(stack).add("backup", "true")

app.synth()