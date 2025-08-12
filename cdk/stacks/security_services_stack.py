"""
Security Services Stack - AWS Security Services for Security Audit Framework
"""
from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    aws_cloudtrail as cloudtrail,
    aws_logs as logs,
    aws_s3 as s3,
    aws_kms as kms,
    aws_iam as iam,
    aws_guardduty as guardduty,
    aws_securityhub as securityhub,
    aws_config as config,
    aws_macie as macie,
    aws_backup as backup,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_lambda as lambda_,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cloudwatch_actions,
    aws_wafv2 as waf,
    aws_shield as shield,
    aws_sns as sns
)
from constructs import Construct
import json


class SecurityServicesStack(Stack):
    """Enable and configure AWS security services"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 results_bucket: s3.Bucket,
                 ecr_scanning_lambda: lambda_.Function = None,
                 cloudwatch_insights_lambda: lambda_.Function = None,
                 security_lake_lambda: lambda_.Function = None,
                 aggregator_lambda: lambda_.Function = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # KMS Keys for security services
        self.cloudtrail_key = kms.Key(
            self, "CloudTrailKey",
            description="KMS key for CloudTrail encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        self.config_key = kms.Key(
            self, "ConfigKey",
            description="KMS key for Config encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        self.backup_key = kms.Key(
            self, "BackupKey",
            description="KMS key for AWS Backup encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # CloudTrail
        # Create S3 bucket for CloudTrail logs
        trail_bucket = s3.Bucket(
            self, "CloudTrailBucket",
            bucket_name=f"security-audit-cloudtrail-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.cloudtrail_key,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="DeleteOldLogs",
                    expiration=Duration.days(90),
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(30)
                        )
                    ]
                )
            ],
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # CloudWatch Logs for CloudTrail
        log_group = logs.LogGroup(
            self, "CloudTrailLogGroup",
            log_group_name="/aws/cloudtrail/security-audit",
            retention=logs.RetentionDays.ONE_YEAR,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Create CloudTrail
        trail = cloudtrail.Trail(
            self, "SecurityAuditTrail",
            trail_name="security-audit-trail",
            bucket=trail_bucket,
            encryption_key=self.cloudtrail_key,
            include_global_service_events=True,
            is_multi_region_trail=True,
            enable_file_validation=True,
            send_to_cloud_watch_logs=True,
            cloud_watch_logs_log_group=log_group,
            event_selectors=[
                cloudtrail.EventSelector(
                    read_write_type=cloudtrail.ReadWriteType.ALL,
                    include_management_events=True,
                    data_resources=[
                        cloudtrail.DataResource(
                            data_resource_type=cloudtrail.DataResourceType.S3_OBJECT,
                            values=["arn:aws:s3:::*/*"]
                        )
                    ]
                )
            ]
        )
        
        # GuardDuty
        guardduty_detector = guardduty.CfnDetector(
            self, "GuardDutyDetector",
            enable=True,
            finding_publishing_frequency="FIFTEEN_MINUTES",
            data_sources=guardduty.CfnDetector.CFNDataSourceConfigurationsProperty(
                s3_logs=guardduty.CfnDetector.CFNS3LogsConfigurationProperty(
                    enable=True
                ),
                kubernetes=guardduty.CfnDetector.CFNKubernetesConfigurationProperty(
                    audit_logs=guardduty.CfnDetector.CFNKubernetesAuditLogsConfigurationProperty(
                        enable=True
                    )
                ),
                malware_protection=guardduty.CfnDetector.CFNMalwareProtectionConfigurationProperty(
                    scan_ec2_instance_with_findings=guardduty.CfnDetector.CFNScanEc2InstanceWithFindingsConfigurationProperty(
                        ebs_volumes=True
                    )
                )
            )
        )
        
        # Security Hub
        security_hub = securityhub.CfnHub(
            self, "SecurityHub",
            control_finding_generator="SECURITY_CONTROL",
            enable_default_standards=True,
            auto_enable_controls=True
        )
        
        # Enable security standards
        cis_standard = securityhub.CfnStandard(
            self, "CISStandard",
            standards_arn="arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"
        )
        cis_standard.add_dependency(security_hub)
        
        aws_foundational_standard = securityhub.CfnStandard(
            self, "AWSFoundationalStandard",
            standards_arn="arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
        )
        aws_foundational_standard.add_dependency(security_hub)
        
        # Config
        # Config bucket
        config_bucket = s3.Bucket(
            self, "ConfigBucket",
            bucket_name=f"security-audit-config-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.config_key,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="DeleteOldConfigs",
                    expiration=Duration.days(365),
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90)
                        )
                    ]
                )
            ],
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # Config service-linked role
        config_role = iam.Role(
            self, "ConfigRole",
            assumed_by=iam.ServicePrincipal("config.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/ConfigRole")
            ]
        )
        
        # Config recorder
        config_recorder = config.CfnConfigurationRecorder(
            self, "ConfigRecorder",
            name="security-audit-recorder",
            role_arn=config_role.role_arn,
            recording_group=config.CfnConfigurationRecorder.RecordingGroupProperty(
                all_supported=True,
                include_global_resource_types=True,
                resource_types=[]  # Empty means all resource types
            )
        )
        
        # Config delivery channel
        delivery_channel = config.CfnDeliveryChannel(
            self, "ConfigDeliveryChannel",
            name="security-audit-delivery",
            s3_bucket_name=config_bucket.bucket_name,
            config_snapshot_delivery_properties=config.CfnDeliveryChannel.ConfigSnapshotDeliveryPropertiesProperty(
                delivery_frequency="TwentyFour_Hours"
            )
        )
        
        # Start Config recording
        config.CfnConfigurationRecorder(
            self, "StartConfigRecording",
            name=config_recorder.name,
            role_arn=config_role.role_arn
        ).add_dependency(delivery_channel)
        
        # Config rules for compliance checking
        config_rules = [
            config.ManagedRule(
                self, "RequiredTags",
                identifier=config.ManagedRuleIdentifiers.REQUIRED_TAGS,
                input_parameters={
                    "tag1Key": "Environment",
                    "tag2Key": "Owner",
                    "tag3Key": "SecurityLevel"
                }
            ),
            config.ManagedRule(
                self, "S3BucketPublicReadProhibited",
                identifier=config.ManagedRuleIdentifiers.S3_BUCKET_PUBLIC_READ_PROHIBITED
            ),
            config.ManagedRule(
                self, "S3BucketSSLRequestsOnly",
                identifier=config.ManagedRuleIdentifiers.S3_BUCKET_SSL_REQUESTS_ONLY
            ),
            config.ManagedRule(
                self, "EC2InstancesInVPC",
                identifier=config.ManagedRuleIdentifiers.EC2_INSTANCES_IN_VPC
            )
        ]
        
        # Macie
        macie_session = macie.CfnSession(
            self, "MacieSession",
            status="ENABLED",
            finding_publishing_frequency="FIFTEEN_MINUTES"
        )
        
        # Custom data identifier for sensitive data
        pii_identifier = macie.CfnCustomDataIdentifier(
            self, "PIIIdentifier",
            name="security-audit-pii",
            description="Detect PII in security scan results",
            regex="\\b(?:ssn|social[-\\s]?security)[-\\s]?(?:number)?\\b",
            keywords=["ssn", "social security", "date of birth", "driver license", "passport"],
            ignore_words=["test", "demo", "sample"]
        )
        pii_identifier.add_dependency(macie_session)
        
        # Macie classification job for results bucket
        self.macie_job = macie.CfnClassificationJob(
            self, "MacieClassificationJob",
            job_type="SCHEDULED",
            name="security-audit-s3-scan",
            schedule_frequency=macie.CfnClassificationJob.ScheduleFrequencyProperty(
                weekly_schedule=macie.CfnClassificationJob.WeeklyScheduleProperty(
                    day_of_week="SUNDAY"
                )
            ),
            s3_job_definition=macie.CfnClassificationJob.S3JobDefinitionProperty(
                bucket_definitions=[
                    macie.CfnClassificationJob.S3BucketDefinitionForJobProperty(
                        account_id=self.account,
                        buckets=[
                            f"security-scan-results-{self.account}-{self.region}",
                            f"security-audit-policies-{self.account}-{self.region}"
                        ]
                    )
                ],
                scoping=macie.CfnClassificationJob.ScopingProperty(
                    includes=macie.CfnClassificationJob.JobScopingBlockProperty(
                        and_=[
                            macie.CfnClassificationJob.JobScopeTermProperty(
                                simple_scope_term=macie.CfnClassificationJob.SimpleScopeTermProperty(
                                    comparator="STARTS_WITH",
                                    key="OBJECT_KEY",
                                    values=["raw/", "processed/"]
                                )
                            )
                        ]
                    )
                )
            )
        )
        self.macie_job.add_dependency(macie_session)
        
        # AWS Backup Configuration
        # Create backup vault with KMS encryption
        backup_vault = backup.BackupVault(
            self, "SecurityAuditBackupVault",
            backup_vault_name="security-audit-backup-vault",
            encryption_key=self.backup_key,
            removal_policy=RemovalPolicy.RETAIN,
            access_policy=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        effect=iam.Effect.DENY,
                        principals=[iam.AnyPrincipal()],
                        actions=["backup:DeleteRecoveryPoint"],
                        resources=["*"],
                        conditions={
                            "StringNotEquals": {
                                "aws:PrincipalOrgID": Stack.of(self).account
                            }
                        }
                    )
                ]
            )
        )
        
        # Backup plan with multiple rules for different retention periods
        backup_plan = backup.BackupPlan(
            self, "SecurityAuditBackupPlan",
            backup_plan_name="security-audit-backup-plan",
            backup_plan_rules=[
                # Daily backups retained for 7 days
                backup.BackupPlanRule(
                    backup_vault=backup_vault,
                    rule_name="DailyBackups",
                    schedule_expression=events.Schedule.cron(
                        hour="3",
                        minute="0"
                    ),
                    delete_after=Duration.days(7),
                    move_to_cold_storage_after=Duration.days(3)
                ),
                # Weekly backups retained for 30 days
                backup.BackupPlanRule(
                    backup_vault=backup_vault,
                    rule_name="WeeklyBackups",
                    schedule_expression=events.Schedule.cron(
                        hour="4",
                        minute="0",
                        week_day="SUN"
                    ),
                    delete_after=Duration.days(30)
                ),
                # Monthly backups retained for 1 year
                backup.BackupPlanRule(
                    backup_vault=backup_vault,
                    rule_name="MonthlyBackups",
                    schedule_expression=events.Schedule.cron(
                        hour="5",
                        minute="0",
                        day="1"
                    ),
                    delete_after=Duration.days(365),
                    move_to_cold_storage_after=Duration.days(90)
                )
            ]
        )
        
        # Tag-based backup selection
        backup_plan.add_selection(
            "SecurityAuditBackupSelection",
            resources=[
                backup.BackupResource.from_tag(
                    key="backup",
                    value="true"
                ),
                backup.BackupResource.from_tag(
                    key="Environment",
                    value="production"
                )
            ],
            role=iam.Role(
                self, "BackupServiceRole",
                assumed_by=iam.ServicePrincipal("backup.amazonaws.com"),
                managed_policies=[
                    iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSBackupServiceRolePolicyForBackup"),
                    iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSBackupServiceRolePolicyForRestores")
                ]
            )
        )
        
        # AWS Shield Advanced Configuration
        # NOTE: Shield Advanced has a monthly cost of $3000 USD plus data transfer fees
        # Only enable if you need advanced DDoS protection
        
        # Create SNS topic for Shield alerts
        shield_alert_topic = sns.Topic(
            self, "ShieldAlertTopic",
            topic_name="security-audit-shield-alerts",
            display_name="AWS Shield Advanced Alerts"
        )
        
        # Shield DRT (DDoS Response Team) access role
        shield_drt_role = iam.Role(
            self, "ShieldDRTRole",
            role_name="AWSDRTAccessRole",
            assumed_by=iam.ServicePrincipal("drt.shield.amazonaws.com"),
            description="Role for AWS Shield DRT to access resources during DDoS incidents"
        )
        
        # Grant DRT necessary permissions
        shield_drt_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("DDoSResponseTeamPolicy")
        )
        
        # Shield Advanced subscription
        # IMPORTANT: This will enable Shield Advanced with its associated costs
        # Comment out if you don't want to enable Shield Advanced
        """
        shield_subscription = shield.CfnSubscription(
            self, "ShieldSubscription",
            # Subscription is automatically created when you enable Shield Advanced
            # This is a placeholder to document the subscription
        )
        
        # Protection Group for API Gateway and other resources
        shield_protection_group = shield.CfnProtectionGroup(
            self, "APIProtectionGroup",
            protection_group_id="security-audit-api-protection",
            aggregation="SUM",
            pattern="BY_RESOURCE_TYPE",
            resource_type="APPLICATION_LOAD_BALANCER",  # Change based on your resources
            members=[]  # Will be populated with protected resource ARNs
        )
        """
        
        # Shield Proactive Engagement
        # This enables AWS Shield Response Team to contact you during attacks
        """
        shield_proactive_engagement = shield.CfnProactiveEngagement(
            self, "ShieldProactiveEngagement",
            proactive_engagement_status="ENABLED",
            emergency_contact_list=[
                shield.CfnProactiveEngagement.EmergencyContactProperty(
                    email_address="security-team@example.com",
                    phone_number="+1234567890",
                    contact_notes="Primary security contact"
                ),
                shield.CfnProactiveEngagement.EmergencyContactProperty(
                    email_address="ops-team@example.com",
                    phone_number="+0987654321",
                    contact_notes="Secondary operations contact"
                )
            ]
        )
        """
        
        # CloudWatch Alarms for Shield
        shield_alarm = cloudwatch.Alarm(
            self, "ShieldDDoSAlarm",
            alarm_name="security-audit-potential-ddos",
            alarm_description="Potential DDoS attack detected",
            metric=cloudwatch.Metric(
                namespace="AWS/DDoSProtection",
                metric_name="DDoSDetected",
                dimensions_map={
                    "ResourceArn": f"arn:aws:apigateway:{self.region}::/restapis/*"
                }
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD
        )
        
        shield_alarm.add_alarm_action(
            cloudwatch_actions.SnsAction(shield_alert_topic)
        )
        
        # Output Shield configuration status
        CfnOutput(
            self, "ShieldAdvancedStatus",
            value="Shield Advanced is configured but NOT enabled by default due to cost. Uncomment Shield resources in code to enable.",
            description="AWS Shield Advanced subscription status"
        )
        
        CfnOutput(
            self, "ShieldAlertTopicArn",
            value=shield_alert_topic.topic_arn,
            description="SNS topic for Shield DDoS alerts"
        )
        
        # X-Ray Service Map
        xray_service_map = cloudwatch.CfnDashboard(
            self, "XRayServiceMap",
            dashboard_name="security-audit-xray-service-map",
            dashboard_body=json.dumps({
                "widgets": [
                    {
                        "type": "metric",
                        "properties": {
                            "metrics": [
                                ["AWS/X-Ray", "TracesProcessed"],
                                [".", "TracesReceived"]
                            ],
                            "period": 300,
                            "stat": "Sum",
                            "region": self.region,
                            "title": "X-Ray Traces"
                        }
                    },
                    {
                        "type": "metric",
                        "properties": {
                            "metrics": [
                                ["AWS/X-Ray", "LatencyHigh", {"stat": "Average"}],
                                [".", "LatencyOK", {"stat": "Average"}]
                            ],
                            "period": 300,
                            "stat": "Average",
                            "region": self.region,
                            "title": "Service Latency"
                        }
                    }
                ]
            })
        )
        
        # Create custom authorizer Lambda function
        self.custom_authorizer = lambda_.Function(
            self, "CustomAuthorizer",
            function_name="security-audit-api-authorizer",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
import json
import base64
import os

def handler(event, context):
    '''
    Custom authorizer for API Gateway
    Validates tokens and returns IAM policy
    '''
    token = event.get('authorizationToken', '')
    
    # Extract method ARN
    method_arn = event['methodArn']
    
    # Simple token validation (replace with your actual validation logic)
    # For example: JWT validation, API key validation, etc.
    if not token or not token.startswith('Bearer '):
        raise Exception('Unauthorized')
    
    # Extract actual token
    actual_token = token.replace('Bearer ', '')
    
    # Validate token (implement your validation logic here)
    # This is a simple example - replace with actual validation
    if actual_token == os.environ.get('VALID_TOKEN', 'test-token'):
        principal_id = 'user|valid-user'
        effect = 'Allow'
    else:
        raise Exception('Unauthorized')
    
    # Generate IAM policy
    auth_response = {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': method_arn
                }
            ]
        },
        'context': {
            'user': principal_id,
            'token': actual_token
        }
    }
    
    return auth_response
            """),
            environment={
                "VALID_TOKEN": "your-secret-token-here"  # Use Secrets Manager in production
            },
            timeout=Duration.seconds(30),
            memory_size=256,
            tracing=lambda_.Tracing.ACTIVE,
            log_retention=logs.RetentionDays.ONE_WEEK
        )
        
        # Grant permissions for custom authorizer
        self.custom_authorizer.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "secretsmanager:GetSecretValue",
                    "kms:Decrypt"
                ],
                resources=["*"]  # Restrict to specific secrets in production
            )
        )
        
        # ECR Scanning Configuration (for existing repositories)
        # Note: This would typically be done in the ECR repository creation
        # but we'll create a Lambda to enable scanning on existing repos
        ecr_scanning_enabler = lambda_.Function(
            self, "ECRScanningEnabler",
            function_name="security-audit-ecr-scanning-enabler",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
import boto3
import json

def handler(event, context):
    '''
    Enable ECR scanning on all repositories
    '''
    ecr = boto3.client('ecr')
    
    try:
        # Get all repositories
        repos = []
        paginator = ecr.get_paginator('describe_repositories')
        for page in paginator.paginate():
            repos.extend(page['repositories'])
        
        # Enable scanning for each repository
        results = []
        for repo in repos:
            try:
                response = ecr.put_image_scanning_configuration(
                    repositoryName=repo['repositoryName'],
                    imageScanningConfiguration={
                        'scanOnPush': True
                    }
                )
                results.append({
                    'repository': repo['repositoryName'],
                    'status': 'enabled'
                })
            except Exception as e:
                results.append({
                    'repository': repo['repositoryName'],
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'ECR scanning configuration updated',
                'results': results
            })
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
            """),
            timeout=Duration.minutes(5),
            memory_size=256,
            tracing=lambda_.Tracing.ACTIVE
        )
        
        # Grant ECR permissions
        ecr_scanning_enabler.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ecr:DescribeRepositories",
                    "ecr:PutImageScanningConfiguration",
                    "ecr:GetRepositoryPolicy"
                ],
                resources=["*"]
            )
        )
        
        # EventBridge Rules for Automated Triggers
        
        # Rule to trigger ECR scanning enabler weekly
        ecr_scan_rule = events.Rule(
            self, "ECRScanEnablerRule",
            rule_name="security-audit-ecr-scan-enabler",
            description="Weekly trigger for ECR scanning enabler",
            schedule=events.Schedule.cron(
                minute="0",
                hour="2",
                week_day="MON"
            )
        )
        if ecr_scanning_lambda:
            ecr_scan_rule.add_target(events_targets.LambdaFunction(ecr_scanning_lambda))
        
        # Rule to trigger CloudWatch Insights analysis daily
        insights_rule = events.Rule(
            self, "CloudWatchInsightsRule",
            rule_name="security-audit-insights-analysis",
            description="Daily CloudWatch Insights security analysis",
            schedule=events.Schedule.cron(
                minute="0",
                hour="3"
            )
        )
        if cloudwatch_insights_lambda:
            insights_rule.add_target(events_targets.LambdaFunction(cloudwatch_insights_lambda))
        
        # Rule for Security Lake data ingestion
        security_lake_rule = events.Rule(
            self, "SecurityLakeIngestionRule",
            rule_name="security-audit-lake-ingestion",
            description="Trigger Security Lake ingestion on scan completion",
            event_pattern={
                "source": ["security.audit.framework"],
                "detail-type": ["Scan Completed"]
            }
        )
        if security_lake_lambda:
            security_lake_rule.add_target(events_targets.LambdaFunction(security_lake_lambda))
        
        # Rule to trigger findings aggregation every 4 hours
        aggregation_rule = events.Rule(
            self, "FindingsAggregationRule",
            rule_name="security-audit-findings-aggregation",
            description="Trigger findings aggregation every 4 hours",
            schedule=events.Schedule.rate(Duration.hours(4))
        )
        if aggregator_lambda:
            aggregation_rule.add_target(events_targets.LambdaFunction(aggregator_lambda))
        
        # CloudWatch Dashboard for Security Services
        security_dashboard = cloudwatch.Dashboard(
            self, "SecurityServicesDashboard",
            dashboard_name="security-audit-security-services",
            widgets=[
                [
                    cloudwatch.TextWidget(
                        markdown="# Security Services Dashboard\n\nMonitoring AWS Security Services",
                        width=24,
                        height=2
                    )
                ],
                [
                    cloudwatch.GraphWidget(
                        title="GuardDuty Findings",
                        left=[
                            cloudwatch.Metric(
                                namespace="AWS/GuardDuty",
                                metric_name="FindingsCount",
                                dimensions_map={"Severity": "HIGH"},
                                statistic="Sum",
                                label="High Severity"
                            ),
                            cloudwatch.Metric(
                                namespace="AWS/GuardDuty",
                                metric_name="FindingsCount",
                                dimensions_map={"Severity": "MEDIUM"},
                                statistic="Sum",
                                label="Medium Severity"
                            ),
                            cloudwatch.Metric(
                                namespace="AWS/GuardDuty",
                                metric_name="FindingsCount",
                                dimensions_map={"Severity": "LOW"},
                                statistic="Sum",
                                label="Low Severity"
                            )
                        ],
                        width=12
                    ),
                    cloudwatch.GraphWidget(
                        title="Security Hub Compliance Score",
                        left=[
                            cloudwatch.Metric(
                                namespace="AWS/SecurityHub",
                                metric_name="ComplianceScore",
                                statistic="Average"
                            )
                        ],
                        width=12
                    )
                ],
                [
                    cloudwatch.GraphWidget(
                        title="WAF Blocked Requests",
                        left=[
                            cloudwatch.Metric(
                                namespace="AWS/WAFV2",
                                metric_name="BlockedRequests",
                                dimensions_map={"Rule": "ALL"},
                                statistic="Sum"
                            )
                        ],
                        width=12
                    ),
                    cloudwatch.GraphWidget(
                        title="Config Compliance",
                        left=[
                            cloudwatch.Metric(
                                namespace="AWS/Config",
                                metric_name="NumberOfNonCompliantResources",
                                statistic="Sum"
                            )
                        ],
                        width=12
                    )
                ]
            ]
        )
        
        # Outputs
        CfnOutput(
            self, "CloudTrailLogGroup",
            value=log_group.log_group_name,
            description="CloudTrail log group name"
        )
        
        CfnOutput(
            self, "GuardDutyDetectorId",
            value=guardduty_detector.attr_id,
            description="GuardDuty detector ID"
        )
        
        CfnOutput(
            self, "SecurityHubArn",
            value=security_hub.attr_arn,
            description="Security Hub ARN"
        )
        
        CfnOutput(
            self, "BackupVaultName",
            value=backup_vault.backup_vault_name,
            description="Backup vault name"
        )
        
        CfnOutput(
            self, "CustomAuthorizerFunctionArn",
            value=self.custom_authorizer.function_arn,
            description="Custom authorizer Lambda function ARN"
        )
        
        CfnOutput(
            self, "SecurityDashboardURL",
            value=f"https://console.aws.amazon.com/cloudwatch/home?region={self.region}#dashboards:name={security_dashboard.dashboard_name}",
            description="Security services dashboard URL"
        )