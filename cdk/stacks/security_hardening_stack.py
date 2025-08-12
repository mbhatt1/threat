"""
Security Hardening Stack - Additional security measures for the framework
"""
from aws_cdk import (
    Stack,
    aws_config as config,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_lambda as lambda_,
    aws_iam as iam,
    Duration,
    CfnOutput,
    Tags
)
from constructs import Construct
import aws_cdk as cdk


class SecurityHardeningStack(Stack):
    """Additional security hardening measures"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 alert_topic: sns.Topic,
                 lambdas: dict,
                 tables: dict,
                 buckets: dict,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # AWS Config Rules for compliance
        self._create_config_rules()
        
        # Security-specific CloudWatch Alarms
        self._create_security_alarms(alert_topic, lambdas, tables)
        
        # API throttling alarms
        self._create_api_throttling_alarms(alert_topic)
        
        # Data classification tags
        self._apply_data_classification_tags(buckets, tables)
        
        # Security monitoring dashboard
        self._create_security_dashboard(lambdas, tables)
        
        # Automated remediation Lambda
        self._create_remediation_automation(alert_topic)
    
    def _create_config_rules(self):
        """Create AWS Config rules for security compliance"""
        
        # S3 bucket encryption rule
        config.ManagedRule(
            self, "S3BucketEncryptionRule",
            config_rule_name="s3-bucket-encryption-enabled",
            identifier="S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
            description="Checks that S3 buckets have encryption enabled"
        )
        
        # S3 bucket public read prohibited
        config.ManagedRule(
            self, "S3PublicReadProhibitedRule",
            config_rule_name="s3-bucket-public-read-prohibited",
            identifier="S3_BUCKET_PUBLIC_READ_PROHIBITED",
            description="Checks that S3 buckets do not allow public read access"
        )
        
        # Required tags rule
        config.ManagedRule(
            self, "RequiredTagsRule",
            config_rule_name="required-tags",
            identifier="REQUIRED_TAGS",
            input_parameters={
                "tag1Key": "Project",
                "tag2Key": "Environment",
                "tag3Key": "SecurityClassification"
            },
            description="Checks that resources have required tags"
        )
        
        # EBS encryption rule
        config.ManagedRule(
            self, "EBSEncryptionRule",
            config_rule_name="ebs-encryption-enabled",
            identifier="ENCRYPTED_VOLUMES",
            description="Checks that EBS volumes are encrypted"
        )
        
        # IAM password policy rule
        config.ManagedRule(
            self, "IAMPasswordPolicyRule",
            config_rule_name="iam-password-policy",
            identifier="IAM_PASSWORD_POLICY",
            input_parameters={
                "RequireUppercaseCharacters": "true",
                "RequireLowercaseCharacters": "true",
                "RequireNumbers": "true",
                "RequireSymbols": "true",
                "MinimumPasswordLength": "14"
            },
            description="Checks IAM password policy requirements"
        )
        
        # Multi-region CloudTrail enabled
        config.ManagedRule(
            self, "CloudTrailEnabledRule",
            config_rule_name="cloudtrail-enabled",
            identifier="CLOUD_TRAIL_ENABLED",
            description="Checks that CloudTrail is enabled"
        )
    
    def _create_security_alarms(self, alert_topic: sns.Topic, lambdas: dict, tables: dict):
        """Create security-specific CloudWatch alarms"""
        
        # Failed authentication attempts alarm
        for name, lambda_fn in lambdas.items():
            if name in ['api_authorizer', 'ceo_agent']:
                alarm = cloudwatch.Alarm(
                    self, f"{name}AuthFailureAlarm",
                    alarm_name=f"security-{name}-auth-failures",
                    alarm_description=f"Failed authentication attempts in {name}",
                    metric=lambda_fn.metric_errors(
                        statistic="Sum",
                        period=Duration.minutes(5)
                    ),
                    threshold=5,
                    evaluation_periods=1,
                    treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
                )
                alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Excessive API calls alarm (potential DDoS)
        api_calls_alarm = cloudwatch.Alarm(
            self, "ExcessiveAPICallsAlarm",
            alarm_name="security-excessive-api-calls",
            alarm_description="Excessive API calls detected",
            metric=cloudwatch.Metric(
                namespace="AWS/ApiGateway",
                metric_name="Count",
                statistic="Sum",
                period=Duration.minutes(1)
            ),
            threshold=1000,
            evaluation_periods=2,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        api_calls_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Suspicious Lambda execution patterns
        for name, lambda_fn in lambdas.items():
            # High error rate alarm
            error_rate_alarm = cloudwatch.Alarm(
                self, f"{name}HighErrorRateAlarm",
                alarm_name=f"security-{name}-high-error-rate",
                alarm_description=f"High error rate in {name} Lambda",
                metric=lambda_fn.metric_errors(
                    statistic="Average",
                    period=Duration.minutes(5)
                ),
                threshold=0.1,  # 10% error rate
                evaluation_periods=2,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            error_rate_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
            
            # Unusual invocation pattern
            invocation_alarm = cloudwatch.Alarm(
                self, f"{name}UnusualInvocationAlarm",
                alarm_name=f"security-{name}-unusual-invocations",
                alarm_description=f"Unusual invocation pattern in {name}",
                metric=lambda_fn.metric_invocations(
                    statistic="Sum",
                    period=Duration.minutes(5)
                ),
                threshold=100,  # Adjust based on normal patterns
                evaluation_periods=1,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            invocation_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # DynamoDB suspicious activity
        for name, table in tables.items():
            # High read/write alarm
            read_alarm = cloudwatch.Alarm(
                self, f"{name}HighReadsAlarm",
                alarm_name=f"security-{name}-high-reads",
                alarm_description=f"Unusually high reads on {name} table",
                metric=table.metric_consumed_read_capacity_units(
                    statistic="Sum",
                    period=Duration.minutes(5)
                ),
                threshold=10000,
                evaluation_periods=1,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            read_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
    
    def _create_api_throttling_alarms(self, alert_topic: sns.Topic):
        """Create API throttling and rate limit alarms"""
        
        # 4XX errors alarm (client errors, including rate limiting)
        throttle_alarm = cloudwatch.Alarm(
            self, "APIThrottlingAlarm",
            alarm_name="security-api-throttling",
            alarm_description="API throttling occurring",
            metric=cloudwatch.Metric(
                namespace="AWS/ApiGateway",
                metric_name="4XXError",
                statistic="Sum",
                period=Duration.minutes(5)
            ),
            threshold=50,
            evaluation_periods=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        throttle_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # WAF blocked requests alarm
        waf_blocked_alarm = cloudwatch.Alarm(
            self, "WAFBlockedRequestsAlarm",
            alarm_name="security-waf-blocked-requests",
            alarm_description="High number of WAF blocked requests",
            metric=cloudwatch.Metric(
                namespace="AWS/WAFV2",
                metric_name="BlockedRequests",
                statistic="Sum",
                period=Duration.minutes(5),
                dimensions_map={
                    "Rule": "ALL",
                    "WebACL": "SecurityAuditAPIWAF",
                    "Region": self.region
                }
            ),
            threshold=100,
            evaluation_periods=1,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        waf_blocked_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
    
    def _apply_data_classification_tags(self, buckets: dict, tables: dict):
        """Apply data classification tags to resources"""
        
        # S3 buckets
        for name, bucket in buckets.items():
            if 'results' in name or 'reports' in name:
                Tags.of(bucket).add("DataClassification", "Confidential")
                Tags.of(bucket).add("ComplianceScope", "PCI-DSS")
                Tags.of(bucket).add("RetentionPolicy", "7Years")
            else:
                Tags.of(bucket).add("DataClassification", "Internal")
                Tags.of(bucket).add("ComplianceScope", "SOC2")
                Tags.of(bucket).add("RetentionPolicy", "3Years")
        
        # DynamoDB tables
        for name, table in tables.items():
            if 'findings' in name or 'scan' in name:
                Tags.of(table).add("DataClassification", "Confidential")
                Tags.of(table).add("PIIData", "false")
                Tags.of(table).add("ComplianceScope", "SOC2")
            else:
                Tags.of(table).add("DataClassification", "Internal")
                Tags.of(table).add("PIIData", "false")
    
    def _create_security_dashboard(self, lambdas: dict, tables: dict):
        """Create CloudWatch dashboard for security monitoring"""
        
        dashboard = cloudwatch.Dashboard(
            self, "SecurityMonitoringDashboard",
            dashboard_name="security-audit-monitoring",
            period_override=cloudwatch.PeriodOverride.AUTO
        )
        
        # Lambda security metrics
        lambda_widgets = []
        for name, lambda_fn in lambdas.items():
            lambda_widgets.append(
                cloudwatch.GraphWidget(
                    title=f"{name} Security Metrics",
                    left=[
                        lambda_fn.metric_errors(statistic="Sum"),
                        lambda_fn.metric_throttles(statistic="Sum")
                    ],
                    right=[
                        lambda_fn.metric_duration(statistic="Average")
                    ],
                    width=12,
                    height=6
                )
            )
        
        # API Gateway security metrics
        api_security_widget = cloudwatch.GraphWidget(
            title="API Security Metrics",
            left=[
                cloudwatch.Metric(
                    namespace="AWS/ApiGateway",
                    metric_name="4XXError",
                    statistic="Sum"
                ),
                cloudwatch.Metric(
                    namespace="AWS/ApiGateway",
                    metric_name="5XXError",
                    statistic="Sum"
                )
            ],
            right=[
                cloudwatch.Metric(
                    namespace="AWS/ApiGateway",
                    metric_name="Count",
                    statistic="Sum"
                )
            ],
            width=24,
            height=6
        )
        
        # WAF metrics
        waf_widget = cloudwatch.GraphWidget(
            title="WAF Security Events",
            left=[
                cloudwatch.Metric(
                    namespace="AWS/WAFV2",
                    metric_name="BlockedRequests",
                    statistic="Sum",
                    dimensions_map={
                        "Rule": "ALL",
                        "WebACL": "SecurityAuditAPIWAF",
                        "Region": self.region
                    }
                ),
                cloudwatch.Metric(
                    namespace="AWS/WAFV2",
                    metric_name="AllowedRequests",
                    statistic="Sum",
                    dimensions_map={
                        "Rule": "ALL",
                        "WebACL": "SecurityAuditAPIWAF",
                        "Region": self.region
                    }
                )
            ],
            width=24,
            height=6
        )
        
        # Add widgets to dashboard
        dashboard.add_widgets(api_security_widget)
        dashboard.add_widgets(waf_widget)
        for widget in lambda_widgets:
            dashboard.add_widgets(widget)
    
    def _create_remediation_automation(self, alert_topic: sns.Topic):
        """Create automated remediation Lambda for security events"""
        
        # Create remediation Lambda role
        remediation_role = iam.Role(
            self, "AutoRemediationRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            description="Role for automated security remediation"
        )
        
        # Add specific remediation permissions
        remediation_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "iam:UpdateAccessKey",
                "iam:DeleteAccessKey",
                "iam:PutUserPolicy",
                "iam:AttachUserPolicy",
                "s3:PutBucketPolicy",
                "s3:PutBucketPublicAccessBlock",
                "ec2:ModifyInstanceAttribute",
                "ec2:StopInstances"
            ],
            resources=[
                f"arn:aws:iam::{self.account}:user/*",
                f"arn:aws:s3:::*",
                f"arn:aws:ec2:{self.region}:{self.account}:instance/*"
            ],
            conditions={
                "StringEquals": {
                    "aws:RequestedRegion": self.region,
                    "iam:ResourceTag/AutoRemediation": "enabled"
                }
            }
        ))
        
        # Create automated remediation Lambda
        remediation_lambda = lambda_.Function(
            self, "AutoRemediationFunction",
            function_name="security-auto-remediation",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
import json
import boto3
import os
from datetime import datetime

iam = boto3.client('iam')
s3 = boto3.client('s3')
sns = boto3.client('sns')

def handler(event, context):
    # Parse CloudWatch alarm
    message = json.loads(event['Records'][0]['Sns']['Message'])
    alarm_name = message['AlarmName']
    
    # Automated remediation based on alarm type
    if 'auth-failures' in alarm_name:
        # Lock account after multiple auth failures
        user = alarm_name.split('-')[2]  # Extract username from alarm
        try:
            # Disable access keys
            response = iam.list_access_keys(UserName=user)
            for key in response['AccessKeyMetadata']:
                iam.update_access_key(
                    UserName=user,
                    AccessKeyId=key['AccessKeyId'],
                    Status='Inactive'
                )
            
            # Notify
            sns.publish(
                TopicArn=os.environ['ALERT_TOPIC'],
                Subject='Security: Account Locked',
                Message=f'User {user} access keys disabled due to auth failures'
            )
        except Exception as e:
            print(f"Failed to lock account: {e}")
    
    elif 's3-public-access' in alarm_name:
        # Block public access on S3 bucket
        bucket = message['Trigger']['Dimensions'][0]['value']
        try:
            s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            sns.publish(
                TopicArn=os.environ['ALERT_TOPIC'],
                Subject='Security: S3 Public Access Blocked',
                Message=f'Public access blocked on bucket {bucket}'
            )
        except Exception as e:
            print(f"Failed to block public access: {e}")
    
    return {
        'statusCode': 200,
        'body': json.dumps('Remediation completed')
    }
"""),
            role=remediation_role,
            environment={
                "ALERT_TOPIC": alert_topic.topic_arn
            },
            timeout=Duration.minutes(5),
            memory_size=256,
            description="Automated security remediation for common issues"
        )
        
        # Subscribe to security alerts
        alert_topic.add_subscription(
            subscriptions.LambdaSubscription(remediation_lambda)
        )
        
        # Output
        CfnOutput(
            self, "RemediationLambdaArn",
            value=remediation_lambda.function_arn,
            description="ARN of automated remediation Lambda"
        )