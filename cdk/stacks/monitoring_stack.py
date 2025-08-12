"""
Monitoring Stack - CloudWatch Alarms and Dashboards for Security Audit Framework
"""
from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_dynamodb as dynamodb,
    aws_s3 as s3,
    aws_ecs as ecs
)
from constructs import Construct
from typing import List, Dict, Any


class MonitoringStack(Stack):
    """CloudWatch alarms and monitoring for security audit framework"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 alert_topic: sns.Topic,
                 lambdas: Dict[str, lambda_.Function],
                 tables: Dict[str, dynamodb.Table],
                 buckets: Dict[str, s3.Bucket],
                 ecs_services: Dict[str, ecs.FargateService] = None,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Create composite alarms for critical failures
        critical_alarm = cloudwatch.CompositeAlarm(
            self, "CriticalSecurityAlarm",
            composite_alarm_name="security-audit-critical-failures",
            alarm_description="Critical security audit failures requiring immediate attention",
            alarm_rule=cloudwatch.AlarmRule.any_of(
                cloudwatch.AlarmRule.from_boolean(False)  # Placeholder, will add conditions
            ),
            actions_enabled=True
        )
        
        # Lambda Function Alarms
        lambda_alarms = []
        for name, function in lambdas.items():
            # Error rate alarm
            error_alarm = cloudwatch.Alarm(
                self, f"{name}ErrorAlarm",
                alarm_name=f"security-audit-{name}-errors",
                alarm_description=f"High error rate for {name} Lambda",
                metric=function.metric_errors(
                    period=Duration.minutes(5),
                    statistic="Sum"
                ),
                threshold=5,
                evaluation_periods=2,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            error_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
            lambda_alarms.append(error_alarm)
            
            # Throttles alarm
            throttle_alarm = cloudwatch.Alarm(
                self, f"{name}ThrottleAlarm",
                alarm_name=f"security-audit-{name}-throttles",
                alarm_description=f"Lambda throttling detected for {name}",
                metric=function.metric_throttles(
                    period=Duration.minutes(5),
                    statistic="Sum"
                ),
                threshold=1,
                evaluation_periods=1,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            throttle_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
            
            # Duration alarm (80% of timeout)
            if hasattr(function, 'timeout') and function.timeout:
                duration_threshold = function.timeout.to_seconds() * 0.8 * 1000  # Convert to milliseconds
                duration_alarm = cloudwatch.Alarm(
                    self, f"{name}DurationAlarm",
                    alarm_name=f"security-audit-{name}-duration",
                    alarm_description=f"Lambda approaching timeout for {name}",
                    metric=function.metric_duration(
                        period=Duration.minutes(5),
                        statistic="Maximum"
                    ),
                    threshold=duration_threshold,
                    evaluation_periods=2,
                    comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                    treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
                )
                duration_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
            
            # Concurrent executions alarm
            concurrent_alarm = cloudwatch.Alarm(
                self, f"{name}ConcurrentAlarm",
                alarm_name=f"security-audit-{name}-concurrent",
                alarm_description=f"High concurrent executions for {name}",
                metric=function.metric("ConcurrentExecutions",
                    period=Duration.minutes(5),
                    statistic="Maximum"
                ),
                threshold=900,  # 90% of default limit
                evaluation_periods=2,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            concurrent_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # DynamoDB Alarms
        for name, table in tables.items():
            # User errors alarm
            user_errors_alarm = cloudwatch.Alarm(
                self, f"{name}UserErrorsAlarm",
                alarm_name=f"security-audit-{name}-user-errors",
                alarm_description=f"High user error rate for {name} table",
                metric=table.metric_user_errors(
                    period=Duration.minutes(5),
                    statistic="Sum"
                ),
                threshold=10,
                evaluation_periods=2,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            user_errors_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
            
            # System errors alarm
            system_errors_alarm = cloudwatch.Alarm(
                self, f"{name}SystemErrorsAlarm",
                alarm_name=f"security-audit-{name}-system-errors",
                alarm_description=f"System errors detected for {name} table",
                metric=table.metric_system_errors(
                    period=Duration.minutes(5),
                    statistic="Sum"
                ),
                threshold=1,
                evaluation_periods=1,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            system_errors_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
            lambda_alarms.append(system_errors_alarm)
            
            # Throttled requests alarm
            throttled_alarm = cloudwatch.Alarm(
                self, f"{name}ThrottledAlarm",
                alarm_name=f"security-audit-{name}-throttled",
                alarm_description=f"Throttled requests for {name} table",
                metric=cloudwatch.Metric(
                    namespace="AWS/DynamoDB",
                    metric_name="UserErrors",
                    dimensions_map={
                        "TableName": table.table_name,
                        "ErrorType": "ResourceNotFoundException"
                    },
                    period=Duration.minutes(5),
                    statistic="Sum"
                ),
                threshold=5,
                evaluation_periods=2,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            throttled_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # S3 Bucket Alarms
        for name, bucket in buckets.items():
            # 4xx errors alarm
            errors_4xx_alarm = cloudwatch.Alarm(
                self, f"{name}4xxErrorsAlarm",
                alarm_name=f"security-audit-{name}-4xx-errors",
                alarm_description=f"High 4xx error rate for {name} bucket",
                metric=cloudwatch.Metric(
                    namespace="AWS/S3",
                    metric_name="4xxErrors",
                    dimensions_map={
                        "BucketName": bucket.bucket_name,
                        "FilterId": "AllMetrics"
                    },
                    period=Duration.minutes(5),
                    statistic="Sum"
                ),
                threshold=10,
                evaluation_periods=2,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            errors_4xx_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
            
            # 5xx errors alarm
            errors_5xx_alarm = cloudwatch.Alarm(
                self, f"{name}5xxErrorsAlarm",
                alarm_name=f"security-audit-{name}-5xx-errors",
                alarm_description=f"5xx errors detected for {name} bucket",
                metric=cloudwatch.Metric(
                    namespace="AWS/S3",
                    metric_name="5xxErrors",
                    dimensions_map={
                        "BucketName": bucket.bucket_name,
                        "FilterId": "AllMetrics"
                    },
                    period=Duration.minutes(5),
                    statistic="Sum"
                ),
                threshold=1,
                evaluation_periods=1,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            errors_5xx_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
            lambda_alarms.append(errors_5xx_alarm)
        
        # ECS Service Alarms (if provided)
        if ecs_services:
            for name, service in ecs_services.items():
                # CPU utilization alarm
                cpu_alarm = cloudwatch.Alarm(
                    self, f"{name}CpuAlarm",
                    alarm_name=f"security-audit-{name}-cpu",
                    alarm_description=f"High CPU utilization for {name} service",
                    metric=service.metric_cpu_utilization(
                        period=Duration.minutes(5),
                        statistic="Average"
                    ),
                    threshold=80,
                    evaluation_periods=3,
                    comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                    treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
                )
                cpu_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
                
                # Memory utilization alarm
                memory_alarm = cloudwatch.Alarm(
                    self, f"{name}MemoryAlarm",
                    alarm_name=f"security-audit-{name}-memory",
                    alarm_description=f"High memory utilization for {name} service",
                    metric=service.metric_memory_utilization(
                        period=Duration.minutes(5),
                        statistic="Average"
                    ),
                    threshold=80,
                    evaluation_periods=3,
                    comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                    treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
                )
                memory_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Security-specific alarms
        
        # Failed scan attempts alarm
        failed_scans_alarm = cloudwatch.Alarm(
            self, "FailedScansAlarm",
            alarm_name="security-audit-failed-scans",
            alarm_description="Multiple scan failures detected",
            metric=cloudwatch.Metric(
                namespace="SecurityAudit",
                metric_name="ScanFailures",
                period=Duration.minutes(15),
                statistic="Sum"
            ),
            threshold=3,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        failed_scans_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        lambda_alarms.append(failed_scans_alarm)
        
        # High vulnerability count alarm
        high_vuln_alarm = cloudwatch.Alarm(
            self, "HighVulnerabilityAlarm",
            alarm_name="security-audit-high-vulnerabilities",
            alarm_description="High number of critical vulnerabilities detected",
            metric=cloudwatch.Metric(
                namespace="SecurityAudit",
                metric_name="CriticalVulnerabilities",
                period=Duration.hours(1),
                statistic="Maximum"
            ),
            threshold=10,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        high_vuln_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        lambda_alarms.append(high_vuln_alarm)
        
        # Unauthorized access attempts alarm
        unauthorized_alarm = cloudwatch.Alarm(
            self, "UnauthorizedAccessAlarm",
            alarm_name="security-audit-unauthorized-access",
            alarm_description="Unauthorized access attempts detected",
            metric=cloudwatch.Metric(
                namespace="SecurityAudit",
                metric_name="UnauthorizedAccess",
                period=Duration.minutes(5),
                statistic="Sum"
            ),
            threshold=5,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        unauthorized_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        lambda_alarms.append(unauthorized_alarm)
        
        # Data exfiltration alarm
        data_exfil_alarm = cloudwatch.Alarm(
            self, "DataExfiltrationAlarm",
            alarm_name="security-audit-data-exfiltration",
            alarm_description="Potential data exfiltration detected",
            metric=cloudwatch.Metric(
                namespace="SecurityAudit",
                metric_name="LargeDataTransfer",
                period=Duration.minutes(10),
                statistic="Maximum"
            ),
            threshold=1073741824,  # 1GB
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        data_exfil_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        lambda_alarms.append(data_exfil_alarm)
        
        # Update composite alarm with all critical alarms
        if lambda_alarms:
            critical_alarm = cloudwatch.CompositeAlarm(
                self, "UpdatedCriticalSecurityAlarm",
                composite_alarm_name="security-audit-critical-composite",
                alarm_description="Composite alarm for all critical security failures",
                alarm_rule=cloudwatch.AlarmRule.any_of(*lambda_alarms),
                actions_enabled=True
            )
            critical_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Create monitoring dashboard
        dashboard = cloudwatch.Dashboard(
            self, "SecurityMonitoringDashboard",
            dashboard_name="security-audit-monitoring",
            widgets=[
                [
                    cloudwatch.TextWidget(
                        markdown="# Security Audit Framework Monitoring\n\nReal-time monitoring of security scanning and analysis operations",
                        width=24,
                        height=2
                    )
                ],
                [
                    cloudwatch.AlarmStatusWidget(
                        title="Critical Alarms Status",
                        alarms=lambda_alarms[:5],  # Show top 5 critical alarms
                        width=12,
                        height=6
                    ),
                    cloudwatch.GraphWidget(
                        title="Lambda Error Rates",
                        left=[function.metric_errors() for _, function in list(lambdas.items())[:3]],
                        width=12,
                        height=6
                    )
                ],
                [
                    cloudwatch.GraphWidget(
                        title="Scan Success/Failure Rate",
                        left=[
                            cloudwatch.Metric(
                                namespace="SecurityAudit",
                                metric_name="ScanSuccess",
                                statistic="Sum",
                                period=Duration.minutes(5)
                            ),
                            cloudwatch.Metric(
                                namespace="SecurityAudit",
                                metric_name="ScanFailures",
                                statistic="Sum",
                                period=Duration.minutes(5)
                            )
                        ],
                        width=12,
                        height=6
                    ),
                    cloudwatch.GraphWidget(
                        title="Vulnerability Trends",
                        left=[
                            cloudwatch.Metric(
                                namespace="SecurityAudit",
                                metric_name="CriticalVulnerabilities",
                                statistic="Sum",
                                period=Duration.hours(1)
                            ),
                            cloudwatch.Metric(
                                namespace="SecurityAudit",
                                metric_name="HighVulnerabilities",
                                statistic="Sum",
                                period=Duration.hours(1)
                            ),
                            cloudwatch.Metric(
                                namespace="SecurityAudit",
                                metric_name="MediumVulnerabilities",
                                statistic="Sum",
                                period=Duration.hours(1)
                            )
                        ],
                        width=12,
                        height=6
                    )
                ],
                [
                    cloudwatch.LogQueryWidget(
                        title="Recent Security Events",
                        log_group_names=[f"/aws/lambda/{name}" for name in lambdas.keys()],
                        query_string="""
                        fields @timestamp, @message
                        | filter @message like /ERROR|CRITICAL|SECURITY/
                        | sort @timestamp desc
                        | limit 20
                        """,
                        width=24,
                        height=6
                    )
                ]
            ]
        )
        
        # Output alarm ARNs for integration
        CfnOutput(
            self, "CriticalAlarmArn",
            value=critical_alarm.alarm_arn,
            export_name="security-audit-critical-alarm-arn"
        )
        
        CfnOutput(
            self, "DashboardUrl",
            value=f"https://console.aws.amazon.com/cloudwatch/home?region={self.region}#dashboards:name={dashboard.dashboard_name}",
            export_name="security-audit-dashboard-url"
        )