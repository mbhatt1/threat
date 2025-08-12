# Cost Explorer API Integration

## Overview

The Security Audit Framework includes advanced cost intelligence through deep integration with AWS Cost Explorer API. This enhancement provides real-time cost analysis, forecasting, anomaly detection, and optimization recommendations to ensure cost-effective security scanning operations.

## Architecture

### Components

1. **Enhanced CostOptimizer Class**
   - Real-time pricing queries
   - Cost forecasting
   - Anomaly detection
   - Optimization recommendations
   - Scan-specific cost analysis

2. **CEO Agent Integration**
   - Performs cost analysis before scan execution
   - Monitors budget usage
   - Provides cost insights in scan results
   - Stores historical cost data

3. **Cost Analysis Storage**
   - S3 storage for cost analysis results
   - DynamoDB integration for quick lookups
   - Tagged resources for cost allocation

## Features

### 1. Real-Time Cost Analysis

```python
# Get current month spend breakdown
cost_breakdown = cost_optimizer.get_resource_cost_breakdown()
{
    'period': {'start': '2024-01-01', 'end': '2024-01-31'},
    'service_breakdown': {
        'AmazonECS': 245.67,
        'AmazonS3': 12.45,
        'AWSLambda': 8.90
    },
    'framework_costs': {
        'SecurityAuditFramework_prod': 267.02
    },
    'total_cost': 267.02
}
```

### 2. Cost Forecasting

```python
# Get 30-day cost forecast
forecast = cost_optimizer.get_cost_forecast(days=30)
{
    'forecast_period_days': 30,
    'total_forecast': 812.45,
    'average_daily_cost': 27.08,
    'daily_forecast': [
        {
            'date': '2024-01-15',
            'amount': 28.50,
            'lower_bound': 25.20,
            'upper_bound': 31.80
        },
        ...
    ]
}
```

### 3. Anomaly Detection

```python
# Detect cost anomalies
anomalies = cost_optimizer.get_cost_anomalies()
[
    {
        'anomaly_id': 'anomaly-123',
        'start_date': '2024-01-10',
        'dimension': 'AmazonECS',
        'max_impact': 150.00,
        'total_impact': 450.00
    }
]
```

### 4. Cost Optimization Recommendations

```python
# Get optimization recommendations
recommendations = cost_optimizer.get_cost_recommendations()
[
    {
        'type': 'rightsizing',
        'resource_id': 'i-1234567890',
        'current_instance': 'm5.large',
        'recommended_instance': 'm5.medium',
        'estimated_monthly_savings': 45.00
    },
    {
        'type': 'reserved_instance',
        'service': 'EC2',
        'instance_family': 'm5',
        'estimated_monthly_savings': 120.00
    }
]
```

### 5. Scan-Specific Cost Trends

```python
# Analyze scan cost trends
trends = cost_optimizer.analyze_scan_cost_trends(days=30)
{
    'period_days': 30,
    'total_cost': 450.67,
    'average_daily_cost': 15.02,
    'trend_percentage': 12.5,  # Costs trending up
    'scan_costs': {
        'scan-123': 45.67,
        'scan-124': 48.90,
        ...
    },
    'most_expensive_scan': ('scan-127', 52.30),
    'total_scans': 28
}
```

## Integration with HASHIRU Framework

The Cost Explorer API integration enhances the HASHIRU framework's decision-making capabilities:

### 1. Budget-Aware Execution Planning
- Checks current budget usage before scan execution
- Warns if scan may exceed monthly budget
- Adjusts execution plan based on cost constraints

### 2. Spot Instance Optimization
- Uses historical interruption data for Spot decisions
- Balances cost savings with reliability requirements
- Adjusts based on task priority and deadlines

### 3. Resource Rightsizing
- Analyzes actual resource usage from past scans
- Recommends optimal resource allocations
- Continuously improves cost efficiency

## API Endpoints

### Get Scan Cost Analysis
```http
GET /api/v1/scans/{scan_id}/cost-analysis
```

Response:
```json
{
    "scan_id": "scan-123",
    "analysis_timestamp": "2024-01-15T10:30:00Z",
    "current_month_spend": 267.02,
    "forecast": {
        "30_days": 812.45,
        "average_daily": 27.08
    },
    "insights_summary": {
        "status": "healthy",
        "warnings": [],
        "recommendations": [
            {
                "type": "rightsizing",
                "savings": 45.00,
                "resource": "m5.large"
            }
        ]
    }
}
```

### Get Cost Trends
```http
GET /api/v1/cost/trends?days=30
```

Response:
```json
{
    "period_days": 30,
    "total_cost": 450.67,
    "trend_percentage": 12.5,
    "daily_average": 15.02,
    "by_service": {
        "ECS": 380.45,
        "Lambda": 45.22,
        "S3": 25.00
    }
}
```

## Configuration

### Environment Variables

```bash
# Budget monitoring
BUDGET_NAME=SecurityAuditBudget
MAX_BUDGET_PER_SCAN=10.0

# Cost optimization thresholds
SPOT_INTERRUPTION_TOLERANCE=0.05
BUDGET_WARNING_THRESHOLD=0.75
BUDGET_CRITICAL_THRESHOLD=0.90

# Cost analysis retention
COST_ANALYSIS_RETENTION_DAYS=90
```

### IAM Permissions

Required permissions for Cost Explorer API:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ce:GetCostAndUsage",
                "ce:GetCostForecast",
                "ce:GetAnomalies",
                "ce:GetAnomalyMonitors",
                "ce:CreateAnomalyMonitor",
                "ce:GetRightsizingRecommendation",
                "ce:GetReservationPurchaseRecommendation",
                "ce:GetCostCategories",
                "ce:GetTags",
                "pricing:GetProducts",
                "pricing:DescribeServices",
                "budgets:DescribeBudget",
                "budgets:DescribeBudgets"
            ],
            "Resource": "*"
        }
    ]
}
```

## Cost Allocation Tags

All resources are tagged for accurate cost tracking:

| Tag Key | Tag Value | Purpose |
|---------|-----------|---------|
| Project | SecurityAuditFramework | Overall project tracking |
| Environment | dev/staging/prod | Environment separation |
| ScanId | scan-xxxxx | Per-scan cost tracking |
| AgentType | SAST/DEPENDENCY/etc | Agent-specific costs |
| Priority | critical/high/normal/low | Priority-based analysis |

## Dashboard Integration

Cost insights are integrated into the QuickSight dashboard:

1. **Cost Overview Widget**
   - Current month spend
   - Forecast vs budget
   - Trend indicators

2. **Service Breakdown Chart**
   - Pie chart of costs by AWS service
   - Time series of daily costs

3. **Scan Cost Analysis**
   - Cost per scan histogram
   - Top expensive scans table
   - Cost efficiency metrics

4. **Recommendations Panel**
   - Active cost optimization opportunities
   - Potential monthly savings
   - Implementation priority

## Best Practices

### 1. Budget Management
- Set realistic budgets based on historical data
- Monitor budget alerts actively
- Review cost anomalies weekly

### 2. Cost Optimization
- Implement recommendations promptly
- Use Spot instances for non-critical scans
- Right-size resources based on actual usage

### 3. Cost Allocation
- Ensure all resources are properly tagged
- Use cost categories for detailed tracking
- Generate monthly cost reports by team/project

### 4. Forecasting
- Review forecasts before major scan campaigns
- Adjust budgets based on forecast accuracy
- Plan for seasonal variations

## Troubleshooting

### High Cost Alerts
1. Check for cost anomalies in Cost Explorer
2. Review recent scan execution plans
3. Verify Spot instance usage
4. Check for stuck or long-running tasks

### Inaccurate Forecasts
1. Ensure sufficient historical data (30+ days)
2. Check for one-time cost spikes
3. Verify cost allocation tags
4. Review anomaly detection settings

### Missing Cost Data
1. Verify IAM permissions
2. Check Cost Explorer data availability (24-48 hour delay)
3. Ensure resources are tagged correctly
4. Validate AWS account has Cost Explorer enabled

## Future Enhancements

1. **Machine Learning Cost Prediction**
   - ML models for scan cost prediction
   - Pattern recognition for cost anomalies
   - Automated cost optimization

2. **Multi-Account Cost Management**
   - Consolidated billing integration
   - Cross-account cost allocation
   - Organization-wide budgets

3. **Advanced Scheduling**
   - Cost-aware scan scheduling
   - Off-peak pricing optimization
   - Batch processing for cost efficiency