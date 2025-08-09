# S3 Lifecycle Policies - Intelligent Data Tiering

## Overview

The Security Audit Framework implements sophisticated S3 lifecycle policies that automatically optimize storage costs based on data priority, findings severity, and access patterns. The system uses a combination of static lifecycle rules and dynamic tagging to ensure critical security data remains accessible while minimizing storage costs.

## Architecture

```
┌─────────────────────┐
│   S3 Objects        │
│ (Scan Results)      │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Lifecycle Manager   │
│     Lambda          │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Dynamic Tagging    │
│  - Priority         │
│  - Severity         │
│  - Age              │
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Storage Classes     │
│ - STANDARD          │
│ - INFREQUENT_ACCESS │
│ - INTELLIGENT_TIER  │
│ - GLACIER           │
│ - DEEP_ARCHIVE      │
└─────────────────────┘
```

## Lifecycle Rules

### 1. Critical Findings (High Priority)
- **Retention**: 2 years
- **Transitions**:
  - Day 0-7: STANDARD (immediate access)
  - Day 7-90: INTELLIGENT_TIERING
  - Day 90+: GLACIER_INSTANT_RETRIEVAL

### 2. High Priority Scans
- **Retention**: 1.5 years
- **Transitions**:
  - Day 0-14: STANDARD
  - Day 14-30: INFREQUENT_ACCESS
  - Day 30-180: INTELLIGENT_TIERING
  - Day 180+: GLACIER_INSTANT_RETRIEVAL

### 3. Normal Priority Scans
- **Retention**: 3 years
- **Transitions**:
  - Day 0-7: STANDARD
  - Day 7-30: INFREQUENT_ACCESS
  - Day 30-90: INTELLIGENT_TIERING
  - Day 90-365: GLACIER_INSTANT_RETRIEVAL
  - Day 365+: DEEP_ARCHIVE

### 4. Processed Reports
- **Retention**: 1 year
- **Transitions**:
  - Day 1: INFREQUENT_ACCESS
  - Day 7: INTELLIGENT_TIERING
  - Day 30+: GLACIER_INSTANT_RETRIEVAL

### 5. QuickSight Data
- **Retention**: 6 months
- **Transitions**:
  - Day 0-30: STANDARD
  - Day 30+: INTELLIGENT_TIERING

### 6. Error Logs
- **Retention**: 90 days
- **Transitions**:
  - Day 30+: GLACIER_INSTANT_RETRIEVAL

## Dynamic Tagging System

The Lifecycle Manager Lambda automatically tags S3 objects based on:

### Object Tags
- **ScanId**: Unique scan identifier
- **Priority**: critical | high | normal | low
- **FindingSeverity**: critical | high | medium | low
- **CreatedAt**: ISO timestamp
- **Repository**: Sanitized repository URL
- **Type**: sast | secrets | dependency | iac | error | other
- **ComplianceStatus**: compliant | non-compliant (if available)
- **EstimatedCost**: Scan cost in USD

### Tag-Based Actions
1. **Critical findings** are tagged immediately and kept in hot storage
2. **High-value scans** (high cost or many findings) get extended retention
3. **Error logs** are quickly archived after investigation period
4. **Compliance-critical** data gets special handling

## Lifecycle Manager Lambda

The Lambda function handles:

### Event Sources
1. **S3 Events**: New object created
2. **CloudWatch Events**: Daily and weekly reviews
3. **Direct Invocation**: Post-scan completion

### Functions
- **Tag Application**: Apply appropriate tags based on scan metadata
- **Tag Review**: Update tags based on changing priorities
- **Bulk Operations**: Process multiple scans efficiently
- **Cost Optimization**: Balance access patterns with storage costs

### Schedule
- **Daily Review**: 3 AM UTC - Review last 7 days of scans
- **Weekly Deep Review**: Sunday 4 AM UTC - Review last 30 days

## Cost Optimization

### Storage Class Costs (per GB/month)
- **STANDARD**: $0.023
- **INFREQUENT_ACCESS**: $0.0125
- **INTELLIGENT_TIERING**: $0.0125 + monitoring
- **GLACIER_INSTANT**: $0.004
- **DEEP_ARCHIVE**: $0.00099

### Example Savings
For 1TB of scan data after 1 year:
- Without lifecycle: $276/year (all STANDARD)
- With lifecycle: ~$48/year (mixed storage classes)
- **Savings**: ~83%

## Retrieval Patterns

### Instant Access (< 1 minute)
- STANDARD
- INFREQUENT_ACCESS
- INTELLIGENT_TIERING
- GLACIER_INSTANT_RETRIEVAL

### Delayed Access
- DEEP_ARCHIVE: 12-48 hours

## Monitoring

### CloudWatch Metrics
- Object count by storage class
- Storage costs by class
- Transition events
- Tag application success/failure

### Alarms
- Failed lifecycle transitions
- Unexpected storage growth
- High retrieval costs

## Best Practices

1. **Tag Early**: Apply tags immediately after scan completion
2. **Review Regularly**: Weekly reviews catch misclassified data
3. **Monitor Costs**: Track storage and retrieval costs
4. **Adjust Policies**: Update rules based on access patterns
5. **Document Changes**: Keep lifecycle policy changes documented

## Configuration

### Environment Variables
```bash
RESULTS_BUCKET=security-scan-results
SCAN_TABLE=SecurityScans
```

### IAM Permissions Required
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObjectTagging",
        "s3:PutObjectTagging",
        "s3:GetBucketTagging",
        "s3:PutBucketTagging",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::security-scan-results",
        "arn:aws:s3:::security-scan-results/*"
      ]
    }
  ]
}
```

## Integration with Other Components

### CEO Agent
- Stores scan priority in DynamoDB
- Priority influences initial storage class

### Report Generator
- Marks processed reports for quick archival
- Stores visualization data separately

### Aggregator
- Provides finding counts for severity tagging
- Influences retention period

### Sub-CEO Agent
- File group priorities affect object tagging
- Critical file groups get extended retention

## Future Enhancements

1. **Machine Learning**: Predict access patterns
2. **Custom Policies**: Per-repository lifecycle rules
3. **Cost Predictor**: Estimate storage costs before scan
4. **Automated Cleanup**: Remove redundant scan data
5. **Compliance Mode**: Special handling for regulatory data