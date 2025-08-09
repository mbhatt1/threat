"""
Monitoring Stack - CloudWatch dashboards, alarms, and event rules
"""
from aws_cdk import (
    Stack,
    aws_cloudwatch as cw,
    aws_stepfunctions as sfn,
    aws_apigateway as apigw,
    aws_s3 as s3,
    aws_dynamodb as dynamodb,
    aws_sns as sns,
    aws_cloudwatch_actions as cw_actions,
    aws_events as events,
    aws_events_targets as targets,
    aws_lambda as lambda_,
    Duration,
    CfnOutput
)
from constructs import Construct
from typing import Optional


class MonitoringStack(Stack):
    """CloudWatch monitoring for Security Audit Framework"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 state_machine: sfn.StateMachine,
                 api: apigw.RestApi,
                 results_bucket: s3.Bucket,
                 scan_table: dynamodb.Table,
                 lifecycle_lambda: Optional[lambda_.Function] = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # SNS Topic for alarms
        alarm_topic = sns.Topic(
            self, "AlarmTopic",
            topic_name="security-audit-alarms",
            display_name="Security Audit Framework Alarms"
        )
        
        # CloudWatch Dashboard
        dashboard = cw.Dashboard(
            self, "SecurityAuditDashboard",
            dashboard_name="security-audit-overview",
            default_interval=Duration.hours(6)
        )
        
        # Step Functions Metrics
        sfn_executions_metric = cw.Metric(
            namespace="AWS/States",
            metric_name="ExecutionsStarted",
            dimensions_map={
                "StateMachineArn": state_machine.state_machine_arn
            },
            statistic="Sum",
            period=Duration.minutes(5)
        )
        
        sfn_success_metric = cw.Metric(
            namespace="AWS/States",
            metric_name="ExecutionsSucceeded",
            dimensions_map={
                "StateMachineArn": state_machine.state_machine_arn
            },
            statistic="Sum",
            period=Duration.minutes(5)
        )
        
        sfn_failed_metric = cw.Metric(
            namespace="AWS/States",
            metric_name="ExecutionsFailed",
            dimensions_map={
                "StateMachineArn": state_machine.state_machine_arn
            },
            statistic="Sum",
            period=Duration.minutes(5)
        )
        
        sfn_duration_metric = cw.Metric(
            namespace="AWS/States",
            metric_name="ExecutionTime",
            dimensions_map={
                "StateMachineArn": state_machine.state_machine_arn
            },
            statistic="Average",
            period=Duration.minutes(5)
        )
        
        # API Gateway Metrics
        api_requests_metric = cw.Metric(
            namespace="AWS/ApiGateway",
            metric_name="Count",
            dimensions_map={
                "ApiName": api.rest_api_name,
                "Stage": "v1"
            },
            statistic="Sum",
            period=Duration.minutes(5)
        )
        
        api_4xx_metric = cw.Metric(
            namespace="AWS/ApiGateway",
            metric_name="4XXError",
            dimensions_map={
                "ApiName": api.rest_api_name,
                "Stage": "v1"
            },
            statistic="Sum",
            period=Duration.minutes(5)
        )
        
        api_5xx_metric = cw.Metric(
            namespace="AWS/ApiGateway",
            metric_name="5XXError",
            dimensions_map={
                "ApiName": api.rest_api_name,
                "Stage": "v1"
            },
            statistic="Sum",
            period=Duration.minutes(5)
        )
        
        api_latency_metric = cw.Metric(
            namespace="AWS/ApiGateway",
            metric_name="Latency",
            dimensions_map={
                "ApiName": api.rest_api_name,
                "Stage": "v1"
            },
            statistic="Average",
            period=Duration.minutes(5)
        )
        
        # S3 Bucket Metrics
        s3_bucket_size_metric = cw.Metric(
            namespace="AWS/S3",
            metric_name="BucketSizeBytes",
            dimensions_map={
                "BucketName": results_bucket.bucket_name,
                "StorageType": "StandardStorage"
            },
            statistic="Average",
            period=Duration.days(1)
        )
        
        s3_request_metric = cw.Metric(
            namespace="AWS/S3",
            metric_name="AllRequests",
            dimensions_map={
                "BucketName": results_bucket.bucket_name
            },
            statistic="Sum",
            period=Duration.minutes(5)
        )
        
        # DynamoDB Metrics
        dynamodb_consumed_read_metric = scan_table.metric_consumed_read_capacity_units()
        dynamodb_consumed_write_metric = scan_table.metric_consumed_write_capacity_units()
        dynamodb_throttled_requests = scan_table.metric_user_errors()
        
        # Custom Metrics (these would be published by Lambda functions)
        findings_count_metric = cw.Metric(
            namespace="SecurityAudit",
            metric_name="TotalFindings",
            statistic="Average",
            period=Duration.minutes(5)
        )
        
        critical_findings_metric = cw.Metric(
            namespace="SecurityAudit",
            metric_name="CriticalFindings",
            statistic="Sum",
            period=Duration.minutes(5)
        )
        
        scan_cost_metric = cw.Metric(
            namespace="SecurityAudit",
            metric_name="ScanCost",
            statistic="Average",
            period=Duration.minutes(5),
            unit=cw.Unit.COUNT  # Represents cents
        )
        
        # Dashboard Widgets
        
        # Overview Section
        dashboard.add_widgets(
            cw.TextWidget(
                markdown="# Security Audit Framework Dashboard\n\n**Real-time monitoring of security scans**",
                width=24,
                height=2
            )
        )
        
        # Execution Metrics Row
        dashboard.add_widgets(
            cw.GraphWidget(
                title="Scan Executions",
                left=[sfn_executions_metric],
                width=8,
                height=6
            ),
            cw.GraphWidget(
                title="Success vs Failed Scans",
                left=[sfn_success_metric],
                right=[sfn_failed_metric],
                width=8,
                height=6
            ),
            cw.SingleValueWidget(
                title="Average Scan Duration",
                metrics=[sfn_duration_metric],
                width=8,
                height=6
            )
        )
        
        # API Metrics Row
        dashboard.add_widgets(
            cw.GraphWidget(
                title="API Requests",
                left=[api_requests_metric],
                right=[api_4xx_metric, api_5xx_metric],
                width=12,
                height=6
            ),
            cw.GraphWidget(
                title="API Latency",
                left=[api_latency_metric],
                width=12,
                height=6
            )
        )
        
        # Findings Metrics Row
        dashboard.add_widgets(
            cw.GraphWidget(
                title="Security Findings",
                left=[findings_count_metric],
                right=[critical_findings_metric],
                width=12,
                height=6
            ),
            cw.GraphWidget(
                title="Scan Costs ($)",
                left=[scan_cost_metric.with_(statistic="Sum")],
                width=12,
                height=6
            )
        )
        
        # Storage Metrics Row
        dashboard.add_widgets(
            cw.GraphWidget(
                title="S3 Bucket Size (GB)",
                left=[s3_bucket_size_metric.with_(
                    statistic="Average",
                    period=Duration.days(1)
                )],
                width=12,
                height=6
            ),
            cw.GraphWidget(
                title="DynamoDB Capacity",
                left=[dynamodb_consumed_read_metric],
                right=[dynamodb_consumed_write_metric],
                width=12,
                height=6
            )
        )
        
        # Alarms
        
        # Step Functions failure alarm
        sfn_failure_alarm = cw.Alarm(
            self, "StepFunctionFailureAlarm",
            metric=sfn_failed_metric,
            threshold=1,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            alarm_description="Security scan execution failed",
            alarm_name="security-audit-scan-failed",
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING
        )
        sfn_failure_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
        
        # High scan duration alarm
        high_duration_alarm = cw.Alarm(
            self, "HighScanDurationAlarm",
            metric=sfn_duration_metric,
            threshold=3600000,  # 1 hour in milliseconds
            evaluation_periods=2,
            datapoints_to_alarm=2,
            alarm_description="Scan taking longer than 1 hour",
            alarm_name="security-audit-high-duration",
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING
        )
        high_duration_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
        
        # API 5xx errors alarm
        api_error_alarm = cw.Alarm(
            self, "ApiErrorAlarm",
            metric=api_5xx_metric,
            threshold=5,
            evaluation_periods=2,
            datapoints_to_alarm=1,
            alarm_description="High API error rate",
            alarm_name="security-audit-api-errors",
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING
        )
        api_error_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
        
        # Critical findings alarm
        critical_findings_alarm = cw.Alarm(
            self, "CriticalFindingsAlarm",
            metric=critical_findings_metric,
            threshold=1,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            alarm_description="Critical security findings detected",
            alarm_name="security-audit-critical-findings",
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING
        )
        critical_findings_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
        
        # High cost alarm
        high_cost_alarm = cw.Alarm(
            self, "HighCostAlarm",
            metric=scan_cost_metric.with_(
                statistic="Sum",
                period=Duration.hours(24)
            ),
            threshold=1000,  # $10 per day (in cents)
            evaluation_periods=1,
            datapoints_to_alarm=1,
            alarm_description="Daily scan costs exceeding $10",
            alarm_name="security-audit-high-cost",
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING
        )
        high_cost_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
        
        # DynamoDB throttling alarm
        dynamodb_throttle_alarm = cw.Alarm(
            self, "DynamoDBThrottleAlarm",
            metric=dynamodb_throttled_requests,
            threshold=1,
            evaluation_periods=2,
            datapoints_to_alarm=2,
            alarm_description="DynamoDB requests being throttled",
            alarm_name="security-audit-dynamodb-throttle",
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING
        )
        dynamodb_throttle_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
        
        # S3 bucket size alarm (warn at 100GB)
        bucket_size_alarm = cw.Alarm(
            self, "BucketSizeAlarm",
            metric=s3_bucket_size_metric,
            threshold=100 * 1024 * 1024 * 1024,  # 100GB in bytes
            evaluation_periods=1,
            datapoints_to_alarm=1,
            alarm_description="S3 bucket size exceeding 100GB",
            alarm_name="security-audit-bucket-size",
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING
        )
        bucket_size_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
        
        # Create billing alarms for cost monitoring
        self._create_billing_alarms(alarm_topic)
        
        # Create lifecycle event rules if lifecycle lambda is provided
        if lifecycle_lambda:
            self._create_lifecycle_event_rules(lifecycle_lambda, results_bucket)
        
        # Store alarm topic for other stacks
        self.alarm_topic = alarm_topic
        
        # Outputs
        CfnOutput(
            self, "DashboardURL",
            value=f"https://console.aws.amazon.com/cloudwatch/home?region={self.region}#dashboards:name={dashboard.dashboard_name}",
            description="CloudWatch Dashboard URL"
        )
        
        CfnOutput(
            self, "AlarmTopicArn",
            value=alarm_topic.topic_arn,
            description="SNS topic for alarm notifications"
        )
    
    def _create_billing_alarms(self, alarm_topic: sns.Topic):
        """Create CloudWatch billing alarms for cost monitoring"""
        
        # Overall account billing alarm
        account_billing_alarm = cw.Alarm(
            self, "AccountBillingAlarm",
            metric=cw.Metric(
                namespace="AWS/Billing",
                metric_name="EstimatedCharges",
                dimensions_map={
                    "Currency": "USD"
                },
                statistic="Maximum",
                period=Duration.hours(6)
            ),
            threshold=1000,  # $1000 threshold
            evaluation_periods=1,
            comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Alert when AWS account charges exceed $1000",
            alarm_name="security-audit-account-billing",
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING
        )
        account_billing_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
        
        # Security scan specific billing alarm
        scan_cost_hourly_alarm = cw.Alarm(
            self, "ScanCostHourlyAlarm",
            metric=cw.Metric(
                namespace="SecurityAudit",
                metric_name="ScanCost",
                statistic="Sum",
                period=Duration.hours(1)
            ),
            threshold=5000,  # $50 per hour (in cents)
            evaluation_periods=2,
            comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Alert when security scan costs exceed $50/hour",
            alarm_name="security-audit-scan-cost-hourly",
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING
        )
        scan_cost_hourly_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
        
        # Panic threshold - immediate action required
        panic_billing_alarm = cw.Alarm(
            self, "PanicBillingAlarm",
            metric=cw.Metric(
                namespace="AWS/Billing",
                metric_name="EstimatedCharges",
                dimensions_map={
                    "Currency": "USD"
                },
                statistic="Maximum",
                period=Duration.hours(1)
            ),
            threshold=5000,  # $5000 panic threshold
            evaluation_periods=1,
            comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="PANIC: AWS charges exceed $5000 - immediate action required",
            alarm_name="security-audit-panic-billing",
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING
        )
        panic_billing_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
        
        # S3 storage cost alarm
        s3_storage_cost_alarm = cw.Alarm(
            self, "S3StorageCostAlarm",
            metric=cw.Metric(
                namespace="AWS/Billing",
                metric_name="EstimatedCharges",
                dimensions_map={
                    "Currency": "USD",
                    "ServiceName": "AmazonS3"
                },
                statistic="Maximum",
                period=Duration.days(1)
            ),
            threshold=100,  # $100 per day for S3
            evaluation_periods=1,
            comparison_operator=cw.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="S3 storage costs exceeding $100/day",
            alarm_name="security-audit-s3-cost",
            treat_missing_data=cw.TreatMissingData.NOT_BREACHING
        )
        s3_storage_cost_alarm.add_alarm_action(cw_actions.SnsAction(alarm_topic))
    
    def _create_lifecycle_event_rules(self, lifecycle_lambda: lambda_.Function, results_bucket: s3.Bucket):
        """Create CloudWatch Events rules for lifecycle management"""
        
        # Daily review of recent scans
        daily_review_rule = events.Rule(
            self, "DailyLifecycleReview",
            description="Daily review of S3 lifecycle tags",
            schedule=events.Schedule.cron(
                minute="0",
                hour="3",  # 3 AM UTC
                week_day="*",
                month="*",
                year="*"
            )
        )
        
        daily_review_rule.add_target(
            targets.LambdaFunction(
                lifecycle_lambda,
                event=events.RuleTargetInput.from_object({
                    "source": "aws.events",
                    "action": "scheduled_review",
                    "days": 7
                })
            )
        )
        
        # Weekly deep review
        weekly_review_rule = events.Rule(
            self, "WeeklyLifecycleReview",
            description="Weekly deep review of all S3 objects",
            schedule=events.Schedule.cron(
                minute="0",
                hour="4",  # 4 AM UTC
                week_day="SUN",  # Sunday
                month="*",
                year="*"
            )
        )
        
        weekly_review_rule.add_target(
            targets.LambdaFunction(
                lifecycle_lambda,
                event=events.RuleTargetInput.from_object({
                    "source": "aws.events",
                    "action": "scheduled_review",
                    "days": 30
                })
            )
        )
        
        # S3 event notifications for new objects
        results_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            targets.LambdaDestination(lifecycle_lambda),
            s3.NotificationKeyFilter(
                prefix="raw/",
                suffix=".json"
            )
        )