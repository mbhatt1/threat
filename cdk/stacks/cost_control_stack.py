"""
Cost Control Stack - AWS Budgets, Cost Anomaly Detection, and Tagging Strategy
"""
from aws_cdk import (
    Stack,
    aws_budgets as budgets,
    aws_ce as ce,
    aws_sns as sns,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_iam as iam,
    CfnTag,
    Tags,
    CfnOutput
)
from constructs import Construct
from typing import List, Dict, Any


class CostControlStack(Stack):
    """Manages cost controls, budgets, and tagging for the security audit framework"""
    
    def __init__(self, scope: Construct, construct_id: str,
                 alert_topic: sns.Topic,
                 environment: str = "dev",
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Define budget amounts based on environment
        budget_amounts = {
            "dev": 500.0,      # $500/month for dev
            "staging": 1000.0,  # $1000/month for staging
            "prod": 5000.0     # $5000/month for production
        }
        
        monthly_budget_amount = budget_amounts.get(environment, 500.0)
        
        # Create overall monthly budget
        overall_budget = budgets.CfnBudget(
            self, "MonthlyBudget",
            budget=budgets.CfnBudget.BudgetDataProperty(
                budget_name=f"ai-security-audit-{environment}-monthly",
                budget_type="COST",
                time_unit="MONTHLY",
                budget_limit=budgets.CfnBudget.SpendProperty(
                    amount=monthly_budget_amount,
                    unit="USD"
                ),
                cost_filters={
                    "TagKeyValue": [f"user:Project$AISecurityAudit"]
                }
            ),
            notifications_with_subscribers=[
                budgets.CfnBudget.NotificationWithSubscribersProperty(
                    notification=budgets.CfnBudget.NotificationProperty(
                        comparison_operator="GREATER_THAN",
                        notification_type="ACTUAL",
                        threshold=80,  # Alert at 80% of budget
                        threshold_type="PERCENTAGE"
                    ),
                    subscribers=[
                        budgets.CfnBudget.SubscriberProperty(
                            address=alert_topic.topic_arn,
                            subscription_type="SNS"
                        )
                    ]
                ),
                budgets.CfnBudget.NotificationWithSubscribersProperty(
                    notification=budgets.CfnBudget.NotificationProperty(
                        comparison_operator="GREATER_THAN",
                        notification_type="FORECASTED",
                        threshold=100,  # Alert if forecasted to exceed budget
                        threshold_type="PERCENTAGE"
                    ),
                    subscribers=[
                        budgets.CfnBudget.SubscriberProperty(
                            address=alert_topic.topic_arn,
                            subscription_type="SNS"
                        )
                    ]
                )
            ]
        )
        
        # Service-specific budgets
        service_budgets = {
            "Lambda": monthly_budget_amount * 0.20,      # 20% for Lambda
            "ECS": monthly_budget_amount * 0.30,         # 30% for ECS/Fargate
            "Bedrock": monthly_budget_amount * 0.25,     # 25% for AI/Bedrock
            "Storage": monthly_budget_amount * 0.15,     # 15% for S3/DynamoDB
            "Other": monthly_budget_amount * 0.10        # 10% for other services
        }
        
        for service, amount in service_budgets.items():
            service_budget = budgets.CfnBudget(
                self, f"{service}Budget",
                budget=budgets.CfnBudget.BudgetDataProperty(
                    budget_name=f"ai-security-audit-{environment}-{service.lower()}",
                    budget_type="COST",
                    time_unit="MONTHLY",
                    budget_limit=budgets.CfnBudget.SpendProperty(
                        amount=amount,
                        unit="USD"
                    ),
                    cost_filters=self._get_service_filters(service)
                ),
                notifications_with_subscribers=[
                    budgets.CfnBudget.NotificationWithSubscribersProperty(
                        notification=budgets.CfnBudget.NotificationProperty(
                            comparison_operator="GREATER_THAN",
                            notification_type="ACTUAL",
                            threshold=90,  # Alert at 90% for services
                            threshold_type="PERCENTAGE"
                        ),
                        subscribers=[
                            budgets.CfnBudget.SubscriberProperty(
                                address=alert_topic.topic_arn,
                                subscription_type="SNS"
                            )
                        ]
                    )
                ]
            )
        
        # Cost Anomaly Detector
        anomaly_monitor = ce.CfnAnomalyMonitor(
            self, "CostAnomalyMonitor",
            monitor_name=f"ai-security-audit-{environment}-anomaly-monitor",
            monitor_type="CUSTOM",
            monitor_specification=ce.CfnAnomalyMonitor.ResourceTagProperty(
                key="Project",
                values=["AISecurityAudit"]
            )
        )
        
        # Cost Anomaly Subscription
        anomaly_subscription = ce.CfnAnomalySubscription(
            self, "CostAnomalySubscription",
            subscription_name=f"ai-security-audit-{environment}-anomaly-alerts",
            monitor_arn=[anomaly_monitor.attr_monitor_arn],
            subscribers=[
                ce.CfnAnomalySubscription.SubscriberProperty(
                    address=alert_topic.topic_arn,
                    type="SNS"
                )
            ],
            threshold=100.0,  # Alert on anomalies > $100
            frequency="DAILY"
        )
        
        # CloudWatch Alarms for cost metrics
        self._create_cost_alarms(alert_topic, environment, monthly_budget_amount)
        
        # Tag Policy Document
        tag_policy = {
            "Version": "1.0",
            "TagPolicy": {
                "RequiredTags": {
                    "Project": {
                        "Values": ["AISecurityAudit"],
                        "Enforced": True
                    },
                    "Environment": {
                        "Values": ["dev", "staging", "prod"],
                        "Enforced": True
                    },
                    "CostCenter": {
                        "Values": ["Security"],
                        "Enforced": True
                    },
                    "Owner": {
                        "Values": ["SecurityTeam"],
                        "Enforced": False
                    }
                },
                "OptionalTags": {
                    "Purpose": {
                        "Values": ["Scanning", "Analysis", "Reporting", "Infrastructure"],
                        "Enforced": False
                    },
                    "DataClassification": {
                        "Values": ["Public", "Internal", "Confidential", "Restricted"],
                        "Enforced": False
                    }
                }
            }
        }
        
        # Output tag policy for reference
        CfnOutput(
            self, "TagPolicy",
            value=str(tag_policy),
            description="Tagging policy for cost allocation"
        )
        
        # Resource tagging enforcement
        self._apply_default_tags(environment)
        
    def _get_service_filters(self, service: str) -> Dict[str, List[str]]:
        """Get cost filters for specific AWS services"""
        service_mappings = {
            "Lambda": {
                "Service": ["AWS Lambda"]
            },
            "ECS": {
                "Service": ["Amazon Elastic Container Service", "AWS Fargate"]
            },
            "Bedrock": {
                "Service": ["Amazon Bedrock", "Amazon SageMaker"]
            },
            "Storage": {
                "Service": ["Amazon Simple Storage Service", "Amazon DynamoDB", "Amazon Elastic File System"]
            },
            "Other": {
                "Service": ["Amazon CloudWatch", "Amazon SNS", "AWS Key Management Service", "Amazon EventBridge"]
            }
        }
        
        base_filter = {
            "TagKeyValue": [f"user:Project$AISecurityAudit"]
        }
        
        if service in service_mappings:
            base_filter.update(service_mappings[service])
        
        return base_filter
    
    def _create_cost_alarms(self, alert_topic: sns.Topic, environment: str, monthly_budget: float):
        """Create CloudWatch alarms for cost monitoring"""
        
        # Daily spend alarm
        daily_budget = monthly_budget / 30
        daily_spend_alarm = cloudwatch.Alarm(
            self, "DailySpendAlarm",
            alarm_name=f"ai-security-audit-{environment}-daily-spend",
            alarm_description=f"Alert when daily spend exceeds ${daily_budget:.2f}",
            metric=cloudwatch.Metric(
                namespace="AWS/Billing",
                metric_name="EstimatedCharges",
                dimensions_map={
                    "Currency": "USD"
                },
                statistic="Maximum",
                period=cloudwatch.Duration.hours(24)
            ),
            threshold=daily_budget,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
        daily_spend_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
        # Weekly spend alarm
        weekly_budget = monthly_budget / 4
        weekly_spend_alarm = cloudwatch.Alarm(
            self, "WeeklySpendAlarm",
            alarm_name=f"ai-security-audit-{environment}-weekly-spend",
            alarm_description=f"Alert when weekly spend exceeds ${weekly_budget:.2f}",
            metric=cloudwatch.Metric(
                namespace="AWS/Billing",
                metric_name="EstimatedCharges",
                dimensions_map={
                    "Currency": "USD"
                },
                statistic="Maximum",
                period=cloudwatch.Duration.days(7)
            ),
            threshold=weekly_budget,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD
        )
        weekly_spend_alarm.add_alarm_action(cw_actions.SnsAction(alert_topic))
        
    def _apply_default_tags(self, environment: str):
        """Apply default tags to all resources in the stack"""
        Tags.of(self).add("Project", "AISecurityAudit")
        Tags.of(self).add("Environment", environment)
        Tags.of(self).add("CostCenter", "Security")
        Tags.of(self).add("ManagedBy", "CDK")
        Tags.of(self).add("Purpose", "CostControl")
        Tags.of(self).add("DataClassification", "Internal")
        
        # Add billing tags
        Tags.of(self).add("BillingGroup", f"SecurityAudit-{environment}")
        Tags.of(self).add("AutoShutdown", "false" if environment == "prod" else "true")