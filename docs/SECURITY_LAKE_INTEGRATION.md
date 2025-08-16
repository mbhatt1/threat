# AWS Security Lake Integration Guide

## Overview

AWS Security Lake is a purpose-built data lake that automatically centralizes security data from AWS services, third-party sources, and custom applications. The AI Security Audit Framework integrates seamlessly with Security Lake to provide unified security data management and advanced analytics.

## Architecture

```
┌─────────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   AI Security       │────▶│  OCSF Converter  │────▶│  Security Lake  │
│   Audit Framework   │     │    Lambda        │     │   S3 Bucket     │
└─────────────────────┘     └──────────────────┘     └─────────────────┘
                                     │                         │
                                     ▼                         ▼
                            ┌──────────────────┐     ┌─────────────────┐
                            │   Glue Crawler   │     │    Athena       │
                            │  & Data Catalog  │────▶│   Queries       │
                            └──────────────────┘     └─────────────────┘
```

## Prerequisites

1. AWS Security Lake enabled in your AWS account
2. Security Lake configured with appropriate sources
3. IAM permissions for Security Lake integration
4. S3 bucket for Security Lake data storage

## Configuration

### 1. Enable Security Lake

```bash
# Enable Security Lake in your AWS account
aws securitylake create-data-lake \
  --regions us-east-1 \
  --configuration '{
    "replicationConfiguration": {
      "regions": ["us-west-2"],
      "roleArn": "arn:aws:iam::123456789012:role/SecurityLakeReplicationRole"
    },
    "lifecycleConfiguration": {
      "transitions": [{
        "days": 30,
        "storageClass": "STANDARD_IA"
      }],
      "expiration": {
        "days": 365
      }
    }
  }'
```

### 2. Configure Framework Integration

Update your CDK stack to include Security Lake configuration:

```python
# threat/cdk/stacks/security_lake_stack.py
from aws_cdk import (
    Stack,
    aws_s3 as s3,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_events as events,
    aws_events_targets as targets,
)

class SecurityLakeStack(Stack):
    def __init__(self, scope, construct_id, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        
        # Security Lake S3 bucket (managed by AWS)
        security_lake_bucket = f"aws-security-data-lake-{self.region}-{self.account}"
        
        # OCSF converter Lambda
        ocsf_converter = lambda_.Function(
            self, "OCSFConverter",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("../src/lambdas/security_lake"),
            environment={
                "SECURITY_LAKE_BUCKET": security_lake_bucket,
                "OCSF_VERSION": "1.1.0"
            }
        )
        
        # Grant permissions to write to Security Lake
        ocsf_converter.add_to_role_policy(
            iam.PolicyStatement(
                actions=["s3:PutObject", "s3:PutObjectAcl"],
                resources=[f"arn:aws:s3:::{security_lake_bucket}/ai-security-audit/*"]
            )
        )
```

### 3. OCSF Data Format

The framework converts findings to Open Cybersecurity Schema Framework (OCSF) format:

```json
{
  "metadata": {
    "version": "1.1.0",
    "product": {
      "name": "AI Security Audit Framework",
      "vendor_name": "Your Organization",
      "version": "1.0.0"
    },
    "profiles": ["security_finding"],
    "log_type": "VULNERABILITY_FINDING"
  },
  "time": 1705320600,
  "severity": "High",
  "severity_id": 3,
  "activity_name": "Vulnerability Detected",
  "activity_id": 1,
  "type_name": "Vulnerability Finding",
  "type_uid": 200101,
  "category_name": "Findings",
  "category_uid": 2,
  "class_name": "Vulnerability Finding",
  "class_uid": 2001,
  "finding": {
    "uid": "finding-550e8400-e29b-41d4-a716-446655440000",
    "title": "SQL Injection Vulnerability",
    "desc": "Potential SQL injection in user input handling",
    "types": ["SQL Injection"],
    "src_url": "https://github.com/example/repo/blob/main/src/db/queries.py#L45",
    "remediation": {
      "desc": "Use parameterized queries to prevent SQL injection",
      "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
    }
  },
  "vulnerabilities": [{
    "cve": {
      "uid": "CVE-2024-12345",
      "cvss": {
        "base_score": 8.5,
        "severity": "High",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      }
    }
  }],
  "resources": [{
    "type": "Repository",
    "uid": "https://github.com/example/repo",
    "name": "example-repo",
    "owner": {
      "name": "example",
      "type": "Organization"
    }
  }],
  "enrichments": [{
    "type": "AI Analysis",
    "data": {
      "confidence": 0.95,
      "false_positive_probability": 0.05,
      "exploit_complexity": "Low",
      "business_impact": "High"
    },
    "provider": "Hephaestus AI"
  }]
}
```

## Data Ingestion

### 1. Real-time Ingestion

Configure EventBridge rules to stream findings to Security Lake:

```python
# EventBridge rule for real-time ingestion
security_finding_rule = events.Rule(
    self, "SecurityFindingRule",
    event_pattern={
        "source": ["ai.security.audit"],
        "detail-type": ["Security Finding Detected"]
    }
)

security_finding_rule.add_target(
    targets.LambdaFunction(ocsf_converter)
)
```

### 2. Batch Ingestion

For historical data or bulk imports:

```python
import boto3
import json
from datetime import datetime

def batch_ingest_to_security_lake(findings, bucket_name):
    """Batch ingest findings to Security Lake"""
    s3 = boto3.client('s3')
    
    # Convert findings to OCSF format
    ocsf_records = []
    for finding in findings:
        ocsf_record = convert_to_ocsf(finding)
        ocsf_records.append(json.dumps(ocsf_record))
    
    # Write to Security Lake partition
    partition = datetime.utcnow().strftime("year=%Y/month=%m/day=%d/hour=%H")
    key = f"ai-security-audit/{partition}/findings_{datetime.utcnow().timestamp()}.json"
    
    # Upload to S3
    s3.put_object(
        Bucket=bucket_name,
        Key=key,
        Body='\n'.join(ocsf_records),
        ContentType='application/x-ndjson'
    )
```

## Querying Data with Athena

### 1. Create Athena Table

```sql
CREATE EXTERNAL TABLE IF NOT EXISTS security_lake.ai_security_findings (
  metadata struct<
    version: string,
    product: struct<
      name: string,
      vendor_name: string,
      version: string
    >,
    profiles: array<string>,
    log_type: string
  >,
  time bigint,
  severity string,
  severity_id int,
  activity_name string,
  type_name string,
  finding struct<
    uid: string,
    title: string,
    desc: string,
    types: array<string>,
    src_url: string,
    remediation: struct<
      desc: string,
      references: array<string>
    >
  >,
  vulnerabilities array<struct<
    cve: struct<
      uid: string,
      cvss: struct<
        base_score: double,
        severity: string,
        vector_string: string
      >
    >
  >>,
  resources array<struct<
    type: string,
    uid: string,
    name: string
  >>,
  enrichments array<struct<
    type: string,
    data: map<string, string>,
    provider: string
  >>
)
STORED AS PARQUET
LOCATION 's3://aws-security-data-lake-{region}-{account}/ai-security-audit/'
PARTITIONED BY (
  year int,
  month int,
  day int,
  hour int
);
```

### 2. Sample Queries

**Find Critical Vulnerabilities**
```sql
SELECT 
  finding.title,
  finding.desc,
  resources[1].name as repository,
  time
FROM security_lake.ai_security_findings
WHERE severity = 'Critical'
  AND year = 2024
  AND month = 1
ORDER BY time DESC
LIMIT 10;
```

**Vulnerability Trends by Repository**
```sql
SELECT 
  resources[1].name as repository,
  severity,
  COUNT(*) as count,
  DATE(from_unixtime(time)) as date
FROM security_lake.ai_security_findings
WHERE year = 2024
GROUP BY 1, 2, 4
ORDER BY date DESC, count DESC;
```

**AI Confidence Analysis**
```sql
SELECT 
  finding.title,
  severity,
  CAST(enrichments[1].data['confidence'] AS DOUBLE) as ai_confidence,
  CAST(enrichments[1].data['false_positive_probability'] AS DOUBLE) as fp_probability
FROM security_lake.ai_security_findings
WHERE enrichments[1].provider = 'Hephaestus AI'
  AND CAST(enrichments[1].data['confidence'] AS DOUBLE) > 0.9
ORDER BY ai_confidence DESC;
```

## Automated Alerting

### 1. CloudWatch Insights Integration

Create alerts based on Security Lake data:

```python
# CloudWatch Insights query
insights_query = """
fields @timestamp, severity, finding.title, resources.0.name
| filter severity in ["Critical", "High"]
| stats count() by bin(5m)
"""

# Create metric filter
log_group = f"/aws/security-lake/{region}/ai-security-audit"
metric_filter = logs.MetricFilter(
    self, "CriticalFindingsMetric",
    log_group=log_group,
    metric_namespace="SecurityAudit",
    metric_name="CriticalFindings",
    filter_pattern=logs.FilterPattern.literal('[severity="Critical"]'),
    metric_value="1"
)
```

### 2. SNS Notifications

```python
# SNS topic for critical findings
critical_findings_topic = sns.Topic(
    self, "CriticalFindingsTopic",
    display_name="Critical Security Findings"
)

# Lambda to process and send notifications
notification_handler = lambda_.Function(
    self, "NotificationHandler",
    runtime=lambda_.Runtime.PYTHON_3_11,
    handler="handler.lambda_handler",
    code=lambda_.Code.from_asset("../src/lambdas/notifications"),
    environment={
        "SNS_TOPIC_ARN": critical_findings_topic.topic_arn
    }
)
```

## Best Practices

### 1. Data Retention

Configure lifecycle policies for cost optimization:

```json
{
  "Rules": [{
    "Id": "SecurityLakeRetention",
    "Status": "Enabled",
    "Transitions": [
      {
        "Days": 30,
        "StorageClass": "STANDARD_IA"
      },
      {
        "Days": 90,
        "StorageClass": "GLACIER"
      }
    ],
    "Expiration": {
      "Days": 365
    }
  }]
}
```

### 2. Access Control

Implement least-privilege access:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/SecurityAnalyst"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::aws-security-data-lake-*/*"
      ],
      "Condition": {
        "StringEquals": {
          "s3:prefix": "ai-security-audit/*"
        }
      }
    }
  ]
}
```

### 3. Data Quality

Implement validation before ingestion:

```python
def validate_ocsf_record(record):
    """Validate OCSF record before ingestion"""
    required_fields = ['time', 'severity', 'finding', 'class_uid']
    
    for field in required_fields:
        if field not in record:
            raise ValueError(f"Missing required field: {field}")
    
    # Validate severity
    valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Informational']
    if record['severity'] not in valid_severities:
        raise ValueError(f"Invalid severity: {record['severity']}")
    
    # Validate timestamp
    if not isinstance(record['time'], int) or record['time'] < 0:
        raise ValueError("Invalid timestamp")
    
    return True
```

## Monitoring and Troubleshooting

### 1. CloudWatch Metrics

Monitor ingestion metrics:
- Records ingested per minute
- Failed ingestion attempts
- Data lag time
- Query performance

### 2. Common Issues

**Issue: Data not appearing in Security Lake**
- Check IAM permissions
- Verify S3 bucket policies
- Review Lambda logs for errors
- Confirm OCSF format validation

**Issue: Athena queries timing out**
- Optimize partitioning strategy
- Use projection for better performance
- Consider data compaction

**Issue: High storage costs**
- Review lifecycle policies
- Implement data tiering
- Consider aggregation for older data

## Integration with SIEM

Export Security Lake data to external SIEM systems:

```python
def export_to_siem(query_results, siem_endpoint):
    """Export Security Lake query results to SIEM"""
    import requests
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {get_siem_token()}'
    }
    
    for batch in chunk_results(query_results, size=100):
        response = requests.post(
            siem_endpoint,
            json={'findings': batch},
            headers=headers
        )
        
        if response.status_code != 200:
            logger.error(f"SIEM export failed: {response.text}")
```

## Next Steps

1. Set up automated reporting dashboards
2. Implement machine learning models on Security Lake data
3. Create custom OCSF schemas for specialized findings
4. Integrate with AWS Security Hub for centralized visibility