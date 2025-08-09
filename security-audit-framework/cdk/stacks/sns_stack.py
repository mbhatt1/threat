"""
SNS Stack for Security Audit Framework
Provides SNS topics for triggering security scans
"""
from aws_cdk import (
    Stack,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subs,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_logs as logs,
    CfnOutput,
    RemovalPolicy
)
from constructs import Construct
from typing import Dict, Any

class SnsStack(Stack):
    """Create SNS topics and subscriptions for security scan triggers"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 sns_handler_lambda: lambda_.Function,
                 existing_alarm_topic: sns.Topic = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Main topic for scan requests
        self.scan_request_topic = sns.Topic(
            self, "ScanRequestTopic",
            display_name="Security Scan Request Topic",
            topic_name=f"security-scan-requests-{self.stack_name}"
        )
        
        # Subscribe SNS handler Lambda
        self.scan_request_topic.add_subscription(
            sns_subs.LambdaSubscription(
                sns_handler_lambda,
                filter_policy={
                    "scan_enabled": sns.SubscriptionFilter.string_filter(
                        allowlist=["true"]
                    )
                }
            )
        )
        
        # Dead letter queue for failed messages
        self.dlq_topic = sns.Topic(
            self, "ScanRequestDLQ",
            display_name="Security Scan Request DLQ",
            topic_name=f"security-scan-requests-dlq-{self.stack_name}"
        )
        
        # Subscribe alarm topic to DLQ for notifications
        if existing_alarm_topic:
            self.dlq_topic.add_subscription(
                sns_subs.SnsSubscription(existing_alarm_topic)
            )
        
        # GitHub webhook topic
        self.github_webhook_topic = sns.Topic(
            self, "GitHubWebhookTopic",
            display_name="GitHub Webhook Topic",
            topic_name=f"github-webhooks-{self.stack_name}"
        )
        
        # Forward GitHub webhooks to main scan topic
        self.github_webhook_topic.add_subscription(
            sns_subs.SnsSubscription(
                self.scan_request_topic,
                filter_policy={
                    "event_type": sns.SubscriptionFilter.string_filter(
                        allowlist=["push", "pull_request"]
                    )
                }
            )
        )
        
        # CodeCommit events topic
        self.codecommit_topic = sns.Topic(
            self, "CodeCommitEventsTopic",
            display_name="CodeCommit Events Topic",
            topic_name=f"codecommit-events-{self.stack_name}"
        )
        
        # Forward CodeCommit events to main scan topic
        self.codecommit_topic.add_subscription(
            sns_subs.SnsSubscription(
                self.scan_request_topic,
                raw_message_delivery=True
            )
        )
        
        # Security Hub findings topic
        self.security_hub_topic = sns.Topic(
            self, "SecurityHubFindingsTopic",
            display_name="Security Hub Findings Topic",
            topic_name=f"security-hub-findings-{self.stack_name}"
        )
        
        # Forward Security Hub findings to main scan topic
        self.security_hub_topic.add_subscription(
            sns_subs.SnsSubscription(
                self.scan_request_topic,
                filter_policy={
                    "finding_severity": sns.SubscriptionFilter.string_filter(
                        allowlist=["CRITICAL", "HIGH"]
                    )
                }
            )
        )
        
        # Scheduled scan topic
        self.scheduled_scan_topic = sns.Topic(
            self, "ScheduledScanTopic",
            display_name="Scheduled Scan Topic",
            topic_name=f"scheduled-scans-{self.stack_name}"
        )
        
        # Forward scheduled scans to main scan topic
        self.scheduled_scan_topic.add_subscription(
            sns_subs.SnsSubscription(self.scan_request_topic)
        )
        
        # Create IAM policy for publishing to topics
        self.publish_policy = iam.PolicyDocument(
            statements=[
                iam.PolicyStatement(
                    sid="AllowPublishToScanTopics",
                    effect=iam.Effect.ALLOW,
                    principals=[iam.ServicePrincipal("codecommit.amazonaws.com")],
                    actions=["sns:Publish"],
                    resources=[self.codecommit_topic.topic_arn]
                ),
                iam.PolicyStatement(
                    sid="AllowSecurityHubPublish",
                    effect=iam.Effect.ALLOW,
                    principals=[iam.ServicePrincipal("securityhub.amazonaws.com")],
                    actions=["sns:Publish"],
                    resources=[self.security_hub_topic.topic_arn]
                ),
                iam.PolicyStatement(
                    sid="AllowEventBridgePublish",
                    effect=iam.Effect.ALLOW,
                    principals=[iam.ServicePrincipal("events.amazonaws.com")],
                    actions=["sns:Publish"],
                    resources=[self.scheduled_scan_topic.topic_arn]
                )
            ]
        )
        
        # Apply policies to topics
        self.codecommit_topic.add_to_resource_policy(
            self.publish_policy.statements[0]
        )
        self.security_hub_topic.add_to_resource_policy(
            self.publish_policy.statements[1]
        )
        self.scheduled_scan_topic.add_to_resource_policy(
            self.publish_policy.statements[2]
        )
        
        # Grant Lambda permissions
        self.scan_request_topic.grant_publish(sns_handler_lambda)
        
        # Outputs
        CfnOutput(
            self, "ScanRequestTopicArn",
            value=self.scan_request_topic.topic_arn,
            description="ARN of the main scan request topic"
        )
        
        CfnOutput(
            self, "GitHubWebhookTopicArn",
            value=self.github_webhook_topic.topic_arn,
            description="ARN of the GitHub webhook topic"
        )
        
        CfnOutput(
            self, "CodeCommitTopicArn",
            value=self.codecommit_topic.topic_arn,
            description="ARN of the CodeCommit events topic"
        )
        
        CfnOutput(
            self, "SecurityHubTopicArn",
            value=self.security_hub_topic.topic_arn,
            description="ARN of the Security Hub findings topic"
        )
        
        CfnOutput(
            self, "ScheduledScanTopicArn",
            value=self.scheduled_scan_topic.topic_arn,
            description="ARN of the scheduled scan topic"
        )