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
    ceo_agent_role=iam_stack.lambda_role,
    aggregator_role=iam_stack.lambda_role,
    report_generator_role=iam_stack.lambda_role,
    quicksight_dashboard_role=iam_stack.lambda_role,
    remediation_lambda_role=iam_stack.lambda_role,
    ai_security_role=iam_stack.ai_security_role,
    results_bucket=storage_stack.results_bucket,
    scan_table=storage_stack.scan_table,
    remediation_table=storage_stack.remediation_table,
    alert_topic_arn="",  # Will be set later to avoid circular dependency
    efs_filesystem=network_stack.efs_filesystem,
    efs_access_point=network_stack.efs_access_point,
    lambda_security_group=network_stack.lambda_security_group,
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


# Step Functions for workflow orchestration
step_function_stack = StepFunctionStack(
    app, f"{stack_prefix}-StepFunctions",
    ceo_agent_lambda=lambda_stack.ceo_lambda,
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
    env=env,
    description="API Gateway for AI Security Audit Framework"
)
api_stack.add_dependency(lambda_stack)
api_stack.add_dependency(iam_stack)
api_stack.add_dependency(step_function_stack)

# Monitoring and observability
monitoring_stack = MonitoringStack(
    app, f"{stack_prefix}-Monitoring",
    lambdas=[
        lambda_stack.ceo_lambda,
        lambda_stack.aggregator_lambda,
        lambda_stack.report_generator_lambda,
        lambda_stack.remediation_lambda
    ],
    state_machine=step_function_stack.state_machine,
    api=api_stack.api,
    env=env,
    description="Monitoring for AI Security Audit Framework"
)
monitoring_stack.add_dependency(lambda_stack)
monitoring_stack.add_dependency(step_function_stack)
monitoring_stack.add_dependency(api_stack)

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

# Add tags to all stacks
for stack in [network_stack, storage_stack, iam_stack, lambda_stack, 
              ecs_stack, step_function_stack, api_stack, sns_stack, 
              monitoring_stack]:
    cdk.Tags.of(stack).add("Project", "AISecurityAudit")
    cdk.Tags.of(stack).add("Environment", os.getenv("ENVIRONMENT", "dev"))
    cdk.Tags.of(stack).add("ManagedBy", "CDK")
    cdk.Tags.of(stack).add("SecurityFramework", "Autonomous-AI-Agents")
    cdk.Tags.of(stack).add("AIModel", "Bedrock-Claude")

app.synth()