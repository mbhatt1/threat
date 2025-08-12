"""
EventBridge Stack - Event rules and triggers for automated security scanning
"""
from aws_cdk import (
    Stack,
    Duration,
    CfnOutput,
    aws_events as events,
    aws_events_targets as targets,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_sns as sns
)
from constructs import Construct
from typing import Dict, Any


class EventBridgeStack(Stack):
    """EventBridge rules for automated security scanning triggers"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 ecr_scanning_lambda: lambda_.Function = None,
                 cloudwatch_insights_lambda: lambda_.Function = None,
                 alert_topic: sns.Topic = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # ECR Scanning Trigger Rule - triggers when new images are pushed
        if ecr_scanning_lambda:
            ecr_push_rule = events.Rule(
                self, "ECRImagePushRule",
                rule_name="security-audit-ecr-image-push",
                description="Trigger security scan when new ECR images are pushed",
                event_pattern=events.EventPattern(
                    source=["aws.ecr"],
                    detail_type=["ECR Image Action"],
                    detail={
                        "action-type": ["PUSH"],
                        "result": ["SUCCESS"]
                    }
                )
            )
            
            # Add Lambda target
            ecr_push_rule.add_target(
                targets.LambdaFunction(
                    ecr_scanning_lambda,
                    retry_attempts=2,
                    max_event_age=Duration.hours(1)
                )
            )
            
            # ECR Repository Creation Rule - enables scanning on new repositories
            ecr_repo_rule = events.Rule(
                self, "ECRRepositoryCreationRule",
                rule_name="security-audit-ecr-repo-creation",
                description="Enable scanning when new ECR repositories are created",
                event_pattern=events.EventPattern(
                    source=["aws.ecr"],
                    detail_type=["AWS API Call via CloudTrail"],
                    detail={
                        "eventSource": ["ecr.amazonaws.com"],
                        "eventName": ["CreateRepository"]
                    }
                )
            )
            
            ecr_repo_rule.add_target(
                targets.LambdaFunction(
                    ecr_scanning_lambda,
                    retry_attempts=2
                )
            )
        
        # CloudWatch Insights Scheduled Rules
        if cloudwatch_insights_lambda:
            # Daily security log analysis
            daily_insights_rule = events.Rule(
                self, "DailyInsightsRule",
                rule_name="security-audit-daily-insights",
                description="Daily CloudWatch Insights analysis for security patterns",
                schedule=events.Schedule.cron(
                    minute="0",
                    hour="2",  # 2 AM UTC
                    day="*",
                    month="*",
                    year="*"
                )
            )
            
            daily_insights_rule.add_target(
                targets.LambdaFunction(
                    cloudwatch_insights_lambda,
                    retry_attempts=2,
                    event=events.RuleTargetInput.from_object({
                        "analysisType": "daily",
                        "queries": [
                            "security_threats",
                            "failed_authentications",
                            "suspicious_api_calls",
                            "data_exfiltration_attempts"
                        ]
                    })
                )
            )
            
            # Hourly critical security events analysis
            hourly_insights_rule = events.Rule(
                self, "HourlyInsightsRule",
                rule_name="security-audit-hourly-insights",
                description="Hourly CloudWatch Insights for critical security events",
                schedule=events.Schedule.rate(Duration.hours(1))
            )
            
            hourly_insights_rule.add_target(
                targets.LambdaFunction(
                    cloudwatch_insights_lambda,
                    retry_attempts=1,
                    event=events.RuleTargetInput.from_object({
                        "analysisType": "hourly",
                        "queries": [
                            "root_account_usage",
                            "privilege_escalation",
                            "security_group_changes",
                            "iam_policy_changes"
                        ]
                    })
                )
            )
            
            # Weekly comprehensive analysis
            weekly_insights_rule = events.Rule(
                self, "WeeklyInsightsRule",
                rule_name="security-audit-weekly-insights",
                description="Weekly comprehensive security analysis",
                schedule=events.Schedule.cron(
                    minute="0",
                    hour="3",  # 3 AM UTC
                    day="1",   # Every Sunday
                    month="*",
                    year="*",
                    week_day="SUN"
                )
            )
            
            weekly_insights_rule.add_target(
                targets.LambdaFunction(
                    cloudwatch_insights_lambda,
                    retry_attempts=2,
                    event=events.RuleTargetInput.from_object({
                        "analysisType": "weekly",
                        "queries": [
                            "compliance_violations",
                            "resource_access_patterns",
                            "cost_anomalies",
                            "performance_degradation"
                        ]
                    })
                )
            )
        
        # Security Event Pattern Rules
        # Rule for detecting security group changes
        sg_change_rule = events.Rule(
            self, "SecurityGroupChangeRule",
            rule_name="security-audit-sg-changes",
            description="Detect security group modifications",
            event_pattern=events.EventPattern(
                source=["aws.ec2"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["ec2.amazonaws.com"],
                    "eventName": [
                        "AuthorizeSecurityGroupIngress",
                        "AuthorizeSecurityGroupEgress",
                        "RevokeSecurityGroupIngress",
                        "RevokeSecurityGroupEgress",
                        "CreateSecurityGroup",
                        "DeleteSecurityGroup"
                    ]
                }
            )
        )
        
        if alert_topic:
            sg_change_rule.add_target(
                targets.SnsTopic(
                    alert_topic,
                    message=events.RuleTargetInput.from_text(
                        "Security Group Change Detected: <aws.events.event.json>"
                    )
                )
            )
        
        # Rule for IAM policy changes
        iam_change_rule = events.Rule(
            self, "IAMPolicyChangeRule",
            rule_name="security-audit-iam-changes",
            description="Detect IAM policy and role modifications",
            event_pattern=events.EventPattern(
                source=["aws.iam"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["iam.amazonaws.com"],
                    "eventName": [
                        "AttachUserPolicy",
                        "DetachUserPolicy",
                        "AttachRolePolicy",
                        "DetachRolePolicy",
                        "CreatePolicy",
                        "DeletePolicy",
                        "CreateRole",
                        "DeleteRole",
                        "PutRolePolicy",
                        "DeleteRolePolicy"
                    ]
                }
            )
        )
        
        if alert_topic:
            iam_change_rule.add_target(
                targets.SnsTopic(
                    alert_topic,
                    message=events.RuleTargetInput.from_text(
                        "IAM Change Detected: <aws.events.event.json>"
                    )
                )
            )
        
        # Rule for failed authentication attempts
        failed_auth_rule = events.Rule(
            self, "FailedAuthRule",
            rule_name="security-audit-failed-auth",
            description="Detect failed authentication attempts",
            event_pattern=events.EventPattern(
                source=["aws.signin"],
                detail_type=["AWS Console Sign In via CloudTrail"],
                detail={
                    "eventName": ["ConsoleLogin"],
                    "responseElements": {
                        "ConsoleLogin": ["Failure"]
                    }
                }
            )
        )
        
        if alert_topic:
            failed_auth_rule.add_target(
                targets.SnsTopic(
                    alert_topic,
                    message=events.RuleTargetInput.from_text(
                        "Failed Authentication Attempt: <aws.events.event.json>"
                    )
                )
            )
        
        # Rule for root account usage
        root_usage_rule = events.Rule(
            self, "RootAccountUsageRule",
            rule_name="security-audit-root-usage",
            description="Detect root account usage",
            event_pattern=events.EventPattern(
                source=["aws.signin"],
                detail_type=["AWS Console Sign In via CloudTrail"],
                detail={
                    "userIdentity": {
                        "type": ["Root"]
                    }
                }
            )
        )
        
        if alert_topic:
            root_usage_rule.add_target(
                targets.SnsTopic(
                    alert_topic,
                    message=events.RuleTargetInput.from_text(
                        "ROOT ACCOUNT USAGE DETECTED: <aws.events.event.json>"
                    )
                )
            )
        
        # Rule for detecting GuardDuty findings
        guardduty_findings_rule = events.Rule(
            self, "GuardDutyFindingsRule",
            rule_name="security-audit-guardduty-findings",
            description="Process GuardDuty security findings",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"],
                detail={
                    "severity": [
                        {"numeric": [">=", 4]}  # Medium severity and above
                    ]
                }
            )
        )
        
        if alert_topic:
            guardduty_findings_rule.add_target(
                targets.SnsTopic(
                    alert_topic,
                    message=events.RuleTargetInput.from_text(
                        "GuardDuty Finding: <aws.events.event.json>"
                    )
                )
            )
        
        # Rule for AWS Config compliance changes
        config_compliance_rule = events.Rule(
            self, "ConfigComplianceRule",
            rule_name="security-audit-config-compliance",
            description="Detect AWS Config compliance changes",
            event_pattern=events.EventPattern(
                source=["aws.config"],
                detail_type=["Config Rules Compliance Change"],
                detail={
                    "configRuleInvokedTime": [{"exists": True}],
                    "newEvaluationResult": {
                        "complianceType": ["NON_COMPLIANT"]
                    }
                }
            )
        )
        
        if alert_topic:
            config_compliance_rule.add_target(
                targets.SnsTopic(
                    alert_topic,
                    message=events.RuleTargetInput.from_text(
                        "Config Compliance Violation: <aws.events.event.json>"
                    )
                )
            )
        
        # Output rule ARNs for reference
        CfnOutput(
            self, "ECRPushRuleArn",
            value=ecr_push_rule.rule_arn if ecr_scanning_lambda else "N/A",
            description="ARN of ECR image push event rule"
        )
        
        CfnOutput(
            self, "DailyInsightsRuleArn",
            value=daily_insights_rule.rule_arn if cloudwatch_insights_lambda else "N/A",
            description="ARN of daily CloudWatch Insights rule"
        )