#!/usr/bin/env python3
"""
CDK Application for AI-Based Security Audit Framework with Multi-Region Support
"""
import os
import aws_cdk as cdk
import sys
from pathlib import Path

# Add the config directory to the path
sys.path.append(str(Path(__file__).parent / "config"))

from config.multi_region_config import MultiRegionConfig

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

# Get deployment context
environment = app.node.try_get_context("environment") or os.getenv("ENVIRONMENT", "dev")
deployment_region = app.node.try_get_context("region") or os.getenv("CDK_DEFAULT_REGION", "us-east-1")
is_primary_region = app.node.try_get_context("isPrimaryRegion") or (deployment_region == MultiRegionConfig.PRIMARY_REGION)

# Environment configuration
env = cdk.Environment(
    account=os.getenv('CDK_DEFAULT_ACCOUNT'),
    region=deployment_region
)

# Stack configurations
stack_prefix = app.node.try_get_context("stack_prefix") or "AISecurityAudit"
stack_suffix = f"-{environment}"

# Get region configuration
region_config = MultiRegionConfig.get_region_config(deployment_region)
vpc_cidr = MultiRegionConfig.get_vpc_cidr(deployment_region)

# Tags for all resources
tags = {
    "Project": "AISecurityAudit",
    "Environment": environment,
    "Region": deployment_region,
    "ManagedBy": "CDK",
    "CostCenter": "Security",
    "IsPrimaryRegion": str(is_primary_region).lower()
}

# Apply tags to all stacks
for key, value in tags.items():
    cdk.Tags.of(app).add(key, value)

# Network infrastructure (deployed in all regions)
network_stack = NetworkStack(
    app, f"{stack_prefix}NetworkStack{stack_suffix}",
    vpc_cidr=vpc_cidr,
    env=env,
    description=f"Network infrastructure for AI Security Audit Framework in {deployment_region}"
)

# Storage resources (with multi-region replication)
storage_stack = StorageStack(
    app, f"{stack_prefix}StorageStack{stack_suffix}",
    environment=environment,
    is_primary_region=is_primary_region,
    replication_regions=MultiRegionConfig.get_deployment_regions(environment) if is_primary_region else [],
    env=env,
    description=f"Storage resources for scan results and AI intelligence in {deployment_region}"
)

# IAM roles and policies (only in primary region)
if is_primary_region:
    iam_stack = IAMStack(
        app, f"{stack_prefix}IAMStack{stack_suffix}",
        results_bucket=storage_stack.results_bucket,
        scan_table=storage_stack.scan_table,
        env=env,
        description="IAM roles for AI-powered security agents (global)"
    )
else:
    # Reference IAM roles from primary region
    iam_stack = None

# Lambda functions for orchestration and processing
lambda_stack = LambdaStack(
    app, f"{stack_prefix}LambdaStack{stack_suffix}",
    vpc=network_stack.vpc,
    ceo_agent_role=iam_stack.ceo_agent_role if iam_stack else None,
    aggregator_role=iam_stack.aggregator_role if iam_stack else None,
    report_generator_role=iam_stack.report_generator_role if iam_stack else None,
    quicksight_dashboard_role=iam_stack.quicksight_dashboard_role if iam_stack else None,
    remediation_lambda_role=iam_stack.remediation_lambda_role if iam_stack else None,
    ai_security_role=iam_stack.ai_security_role if iam_stack else None,
    athena_setup_role=iam_stack.athena_setup_role if iam_stack else None,
    data_transformer_role=iam_stack.data_transformer_role if iam_stack else None,
    results_bucket=storage_stack.results_bucket,
    scan_table=storage_stack.scan_table,
    remediation_table=storage_stack.remediation_table,
    alert_topic_arn="",  # Will be set later to avoid circular dependency
    efs_filesystem=network_stack.efs_filesystem,
    efs_access_point=network_stack.efs_access_point,
    lambda_security_group=network_stack.lambda_security_group,
    kms_key=storage_stack.kms_key,
    region=deployment_region,
    env=env,
    description=f"Lambda functions for AI security orchestration in {deployment_region}"
)
lambda_stack.add_dependency(network_stack)
lambda_stack.add_dependency(storage_stack)
if iam_stack:
    lambda_stack.add_dependency(iam_stack)

# SNS topics for event-driven architecture
sns_stack = SnsStack(
    app, f"{stack_prefix}SNSStack{stack_suffix}",
    sns_handler_lambda=lambda_stack.sns_handler_lambda,
    env=env,
    description=f"SNS topics for AI security scan triggers in {deployment_region}"
)
sns_stack.add_dependency(lambda_stack)

# Update Lambda environment with the actual topic ARN
lambda_stack.remediation_lambda.add_environment(
    "ALERT_TOPIC_ARN", sns_stack.scan_request_topic.topic_arn
)

# ECS Stack for all Autonomous AI Agents
ecs_stack = EcsStack(
    app, f"{stack_prefix}ECSStack{stack_suffix}",
    vpc=network_stack.vpc,
    task_execution_role=iam_stack.task_execution_role if iam_stack else None,
    autonomous_task_role=iam_stack.autonomous_task_role if iam_stack else None,
    bedrock_unified_task_role=iam_stack.bedrock_unified_task_role if iam_stack else None,
    results_bucket=storage_stack.results_bucket,
    efs_filesystem=network_stack.efs_filesystem,
    efs_access_point=network_stack.efs_access_point,
    ecs_security_group=network_stack.ecs_security_group,
    remediation_lambda_arn=lambda_stack.remediation_lambda.function_arn,
    region=deployment_region,
    env=env,
    description=f"ECS tasks for multiple autonomous AI security agents in {deployment_region}"
)
ecs_stack.add_dependency(network_stack)
ecs_stack.add_dependency(storage_stack)
if iam_stack:
    ecs_stack.add_dependency(iam_stack)
ecs_stack.add_dependency(lambda_stack)

# Bedrock AI Security Stack
bedrock_stack = BedrockSecurityStack(
    app, f"{stack_prefix}BedrockStack{stack_suffix}",
    vpc=network_stack.vpc,
    ecs_cluster=ecs_stack.cluster,
    results_bucket=storage_stack.results_bucket,
    scan_table=storage_stack.scan_table,
    env=env,
    description=f"Bedrock AI-powered security scanning components in {deployment_region}"
)
bedrock_stack.add_dependency(network_stack)
bedrock_stack.add_dependency(ecs_stack)
bedrock_stack.add_dependency(storage_stack)

# Parameters Stack for configuration values (only in primary region)
if is_primary_region:
    parameters_stack = ParametersStack(
        app, f"{stack_prefix}ParametersStack{stack_suffix}",
        env=env,
        description="SSM parameters and secrets for security audit framework (global)"
    )

# Security Services Stack
if MultiRegionConfig.should_deploy_feature(deployment_region, "security_lake"):
    security_services_stack = SecurityServicesStack(
        app, f"{stack_prefix}SecurityServicesStack{stack_suffix}",
        results_bucket=storage_stack.results_bucket,
        env=env,
        description=f"AWS Security Services for enhanced protection in {deployment_region}"
    )
    security_services_stack.add_dependency(storage_stack)
else:
    security_services_stack = None

# EventBridge Stack for automated triggers
eventbridge_stack = EventBridgeStack(
    app, f"{stack_prefix}EventBridgeStack{stack_suffix}",
    ecr_scanning_lambda=lambda_stack.ecr_scanning_lambda,
    cloudwatch_insights_lambda=lambda_stack.cloudwatch_insights_lambda,
    alert_topic=sns_stack.alert_topic,
    env=env,
    description=f"EventBridge rules for automated security scanning triggers in {deployment_region}"
)
eventbridge_stack.add_dependency(lambda_stack)
eventbridge_stack.add_dependency(sns_stack)

# QuickSight Stack (only in primary region)
if MultiRegionConfig.should_deploy_feature(deployment_region, "quicksight"):
    quicksight_stack = QuickSightStack(
        app, f"{stack_prefix}QuickSightStack{stack_suffix}",
        results_bucket=storage_stack.results_bucket,
        athena_results_bucket=storage_stack.athena_results_bucket,
        env=env,
        description="QuickSight configuration for security dashboards (primary region only)"
    )
    quicksight_stack.add_dependency(storage_stack)

# Athena Stack for data analytics
athena_workgroup = MultiRegionConfig.get_region_config(deployment_region).get("features", {}).get("athena_workgroup", "primary")
athena_stack = AthenaStack(
    app, f"{stack_prefix}AthenaStack{stack_suffix}",
    results_bucket=storage_stack.results_bucket,
    athena_results_bucket=storage_stack.athena_results_bucket,
    athena_setup_lambda=lambda_stack.athena_setup_lambda,
    workgroup_name=f"security-audit-{athena_workgroup}",
    env=env,
    description=f"Athena configuration for security scan analysis in {deployment_region}"
)
athena_stack.add_dependency(storage_stack)
athena_stack.add_dependency(lambda_stack)

# Step Functions for workflow orchestration
step_function_stack = StepFunctionStack(
    app, f"{stack_prefix}StepFunctionsStack{stack_suffix}",
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
    description=f"Step Functions for orchestrating multiple AI agents in {deployment_region}"
)
step_function_stack.add_dependency(ecs_stack)
step_function_stack.add_dependency(lambda_stack)
step_function_stack.add_dependency(network_stack)
step_function_stack.add_dependency(sns_stack)

# API Gateway for external access
api_stack = APIStack(
    app, f"{stack_prefix}APIStack{stack_suffix}",
    api_role=iam_stack.api_gateway_role if iam_stack else None,
    state_machine=step_function_stack.state_machine,
    scan_table=storage_stack.scan_table,
    ai_security_analyzer_lambda=lambda_stack.ai_security_analyzer_lambda,
    custom_authorizer_lambda=getattr(security_services_stack, 'custom_authorizer', None) if security_services_stack else None,
    kms_key=storage_stack.kms_key,
    region=deployment_region,
    env=env,
    description=f"API Gateway for AI Security Audit Framework in {deployment_region}"
)
api_stack.add_dependency(lambda_stack)
if iam_stack:
    api_stack.add_dependency(iam_stack)
api_stack.add_dependency(step_function_stack)
if security_services_stack:
    api_stack.add_dependency(security_services_stack)

# Certificate management for HTTPS (optional)
domain_name = os.getenv('DOMAIN_NAME')
if domain_name and is_primary_region:
    certificate_stack = CertificateStack(
        app, f"{stack_prefix}CertificateStack{stack_suffix}",
        domain_name=domain_name,
        api=api_stack.api,
        hosted_zone=None,
        env=env,
        description="TLS/SSL certificate management for secure HTTPS endpoints"
    )
    certificate_stack.add_dependency(api_stack)

# Monitoring and observability
monitoring_stack = MonitoringStack(
    app, f"{stack_prefix}MonitoringStack{stack_suffix}",
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
    ecs_services=None,
    region=deployment_region,
    env=env,
    description=f"Monitoring for AI Security Audit Framework in {deployment_region}"
)
monitoring_stack.add_dependency(lambda_stack)
monitoring_stack.add_dependency(storage_stack)
monitoring_stack.add_dependency(sns_stack)

# Output important values
cdk.CfnOutput(
    api_stack, "APIEndpoint",
    value=api_stack.api.url,
    description=f"API Gateway endpoint URL for {deployment_region}",
    export_name=f"{stack_prefix}-API-Endpoint-{environment}-{deployment_region}"
)

cdk.CfnOutput(
    api_stack, "Region",
    value=deployment_region,
    description="Deployment region"
)

cdk.CfnOutput(
    api_stack, "IsPrimaryRegion",
    value=str(is_primary_region),
    description="Whether this is the primary region"
)

# Multi-region specific outputs
if environment == "prod" and is_primary_region:
    cdk.CfnOutput(
        api_stack, "DeploymentRegions",
        value=",".join(MultiRegionConfig.get_deployment_regions(environment)),
        description="All deployment regions for this environment"
    )
    
    cdk.CfnOutput(
        api_stack, "DisasterRecoveryRPO",
        value=f"{MultiRegionConfig.DISASTER_RECOVERY['rpo_minutes']} minutes",
        description="Recovery Point Objective"
    )
    
    cdk.CfnOutput(
        api_stack, "DisasterRecoveryRTO",
        value=f"{MultiRegionConfig.DISASTER_RECOVERY['rto_minutes']} minutes",
        description="Recovery Time Objective"
    )

app.synth()