# CloudWatch Insights Queries for AI Security Audit Framework

## Overview

This guide provides a comprehensive collection of CloudWatch Insights queries for monitoring, analyzing, and troubleshooting the AI Security Audit Framework. These queries help you gain insights into system performance, security findings, and operational metrics.

## Prerequisites

- CloudWatch Logs enabled for all Lambda functions
- Proper log group organization
- Structured logging implemented (JSON format recommended)

## Log Groups Structure

```
/aws/lambda/ai-security-analyzer
/aws/lambda/security-lake-processor
/aws/lambda/remediation-handler
/aws/lambda/webhook-processor
/aws/api-gateway/security-audit-api
/security-audit/application-logs
/security-audit/hephaestus-analysis
```

## Common Queries

### 1. Security Finding Analysis

#### Top 10 Critical Vulnerabilities (Last 24 Hours)
```
fields @timestamp, severity, finding.title, repository, finding.file
| filter severity = "CRITICAL"
| stats count(*) as occurrence by finding.title
| sort occurrence desc
| limit 10
```

#### Vulnerability Distribution by Severity
```
fields @timestamp, severity
| filter @message like /VULNERABILITY_FOUND/
| stats count(*) as count by severity
| sort count desc
```

#### Finding Trends Over Time
```
fields @timestamp, severity
| filter @message like /FINDING/
| stats count(*) as findings by bin(1h) as time_bucket, severity
| sort time_bucket desc
```

### 2. Scan Performance Metrics

#### Average Scan Duration by Type
```
fields @timestamp, scan_type, duration
| filter @message like /SCAN_COMPLETED/
| stats avg(duration) as avg_duration, 
        min(duration) as min_duration,
        max(duration) as max_duration,
        count(*) as total_scans
  by scan_type
```

#### Scan Success Rate
```
fields @timestamp, status, scan_id
| filter @message like /SCAN_/
| stats count(*) as total,
        sum(case when status = "SUCCESS" then 1 else 0 end) as successful,
        sum(case when status = "FAILED" then 1 else 0 end) as failed
| fields successful/total * 100 as success_rate, total, successful, failed
```

#### Repository Scan Frequency
```
fields @timestamp, repository_url
| filter @message like /SCAN_STARTED/
| stats count(*) as scan_count by repository_url
| sort scan_count desc
| limit 20
```

### 3. Hephaestus AI Analysis

#### Cognitive Phase Progression
```
fields @timestamp, phase, analysis_id, duration
| filter @logGroup = "/security-audit/hephaestus-analysis"
| stats avg(duration) as avg_phase_duration,
        count(*) as phase_executions
  by phase
| sort phase
```

#### AI Hypothesis Success Rate
```
fields @timestamp, hypothesis_id, validation_result
| filter @message like /HYPOTHESIS_VALIDATION/
| stats count(*) as total_hypotheses,
        sum(case when validation_result = "CONFIRMED" then 1 else 0 end) as confirmed,
        sum(case when validation_result = "REJECTED" then 1 else 0 end) as rejected
| fields confirmed/total_hypotheses * 100 as confirmation_rate
```

#### Evolution Patterns
```
fields @timestamp, pattern_type, confidence_score
| filter @message like /PATTERN_DISCOVERED/
| filter confidence_score > 0.8
| stats count(*) as high_confidence_patterns by pattern_type
| sort high_confidence_patterns desc
```

### 4. System Performance

#### Lambda Cold Start Analysis
```
fields @timestamp, @initDuration, @duration, @memorySize, @maxMemoryUsed
| filter @type = "REPORT"
| filter @initDuration > 0
| stats count() as cold_starts,
        avg(@initDuration) as avg_init_time,
        max(@initDuration) as max_init_time,
        avg(@duration) as avg_duration
  by bin(5m)
```

#### Memory Utilization Patterns
```
fields @timestamp, @memorySize, @maxMemoryUsed, @duration
| filter @type = "REPORT"
| fields @maxMemoryUsed / @memorySize * 100 as memory_utilization
| stats avg(memory_utilization) as avg_utilization,
        max(memory_utilization) as max_utilization,
        count(*) as invocations
  by bin(1h)
```

#### API Gateway Latency
```
fields @timestamp, latency, status, method, resource
| filter @logGroup like /api-gateway/
| stats avg(latency) as avg_latency,
        percentile(latency, 50) as p50,
        percentile(latency, 95) as p95,
        percentile(latency, 99) as p99,
        count(*) as requests
  by method, resource, status
```

### 5. Error Analysis

#### Top Error Messages
```
fields @timestamp, @message, error.message, error.type
| filter level = "ERROR"
| stats count(*) as error_count by error.message
| sort error_count desc
| limit 20
```

#### Error Rate by Lambda Function
```
fields @timestamp, @logGroup, level
| stats count(*) as total_logs,
        sum(case when level = "ERROR" then 1 else 0 end) as errors
  by @logGroup
| fields @logGroup, errors/total_logs * 100 as error_rate, total_logs, errors
| sort error_rate desc
```

#### Failed Remediation Attempts
```
fields @timestamp, remediation_id, error_reason, finding_id
| filter @message like /REMEDIATION_FAILED/
| stats count(*) as failure_count by error_reason
| sort failure_count desc
```

### 6. Security Operations

#### Unauthorized Access Attempts
```
fields @timestamp, source_ip, user_agent, status_code, path
| filter status_code = 403 or status_code = 401
| stats count(*) as unauthorized_attempts by source_ip
| sort unauthorized_attempts desc
| limit 50
```

#### Suspicious Scanning Patterns
```
fields @timestamp, repository_url, scan_frequency
| filter @message like /SCAN_REQUESTED/
| stats count(*) as scan_count by repository_url, bin(1h) as hour
| filter scan_count > 10
| sort scan_count desc
```

#### API Key Usage
```
fields @timestamp, api_key_id, action, source_ip
| filter @message like /API_KEY_USED/
| stats count(*) as usage_count,
        dc(source_ip) as unique_ips,
        dc(action) as unique_actions
  by api_key_id
| sort usage_count desc
```

### 7. Business Metrics

#### Cost Analysis by Scan Type
```
fields @timestamp, scan_type, @billedDuration, cost_multiplier
| filter @type = "REPORT"
| fields @billedDuration * 0.0000166667 * cost_multiplier as estimated_cost
| stats sum(estimated_cost) as total_cost,
        avg(estimated_cost) as avg_cost,
        count(*) as scan_count
  by scan_type
```

#### Repository Coverage
```
fields @timestamp, repository_url, last_scan_date
| filter @message like /REPOSITORY_SCANNED/
| stats max(@timestamp) as last_scan by repository_url
| fields repository_url, 
         (now() - last_scan) / 86400000 as days_since_scan
| filter days_since_scan > 30
```

#### Finding Resolution Time
```
fields finding_id, 
       created_timestamp,
       resolved_timestamp,
       (resolved_timestamp - created_timestamp) / 3600000 as resolution_hours
| filter @message like /FINDING_RESOLVED/
| stats avg(resolution_hours) as avg_resolution_time,
        min(resolution_hours) as min_resolution_time,
        max(resolution_hours) as max_resolution_time,
        count(*) as resolved_findings
  by severity
```

## Advanced Query Patterns

### 1. Correlation Queries

#### Correlate Scans with Findings
```
fields @timestamp, scan_id, finding_count, duration, repository_url
| filter @message like /SCAN_COMPLETED/
| join 
    (fields scan_id, count(*) as actual_findings 
     | filter @message like /FINDING_CREATED/
     | stats count(*) by scan_id)
  on scan_id
| fields scan_id, repository_url, finding_count, actual_findings, duration
```

#### Link Errors to Specific Deployments
```
fields @timestamp, deployment_id, version, error_count
| filter @message like /DEPLOYMENT_COMPLETED/
| join
    (fields deployment_id, count(*) as errors
     | filter level = "ERROR"
     | stats count(*) by deployment_id)
  on deployment_id
| sort error_count desc
```

### 2. Anomaly Detection

#### Detect Unusual Scan Volumes
```
fields @timestamp, bin(1h) as hour, count(*) as scan_count
| filter @message like /SCAN_STARTED/
| stats avg(scan_count) as avg_scans, 
        stddev(scan_count) as std_dev
| fields hour, scan_count, 
         abs(scan_count - avg_scans) / std_dev as z_score
| filter z_score > 2
| sort z_score desc
```

#### Identify Performance Degradation
```
fields @timestamp, @duration, function_name
| filter @type = "REPORT"
| stats avg(@duration) as current_avg by function_name, bin(5m)
| join
    (stats avg(@duration) as baseline_avg by function_name
     | filter @timestamp > ago(7d))
  on function_name
| fields function_name, 
         (current_avg - baseline_avg) / baseline_avg * 100 as perf_change
| filter perf_change > 50
```

## Query Optimization Tips

### 1. Use Time Filters
Always include time filters to limit data scanned:
```
| filter @timestamp > ago(1h)
```

### 2. Filter Early
Apply filters as early as possible in the query:
```
fields @timestamp, severity
| filter severity = "CRITICAL"  # Filter early
| stats count(*) by bin(1h)
```

### 3. Use Specific Log Groups
Target specific log groups when possible:
```
# Specify log group in the query interface or use:
| filter @logGroup = "/aws/lambda/ai-security-analyzer"
```

### 4. Limit Results
Use `limit` to prevent overwhelming results:
```
| sort error_count desc
| limit 100
```

### 5. Use Sampling for Large Datasets
For exploratory analysis on large datasets:
```
| filter @timestamp > ago(7d)
| filter rand() < 0.1  # 10% sample
```

## Saved Queries and Dashboards

### Creating Saved Queries

1. Run the query in CloudWatch Insights
2. Click "Actions" → "Save query"
3. Provide a meaningful name and description
4. Tag with categories: `security`, `performance`, `operations`

### Dashboard Configuration

Create CloudWatch dashboards with these key widgets:

1. **Security Overview**
   - Finding count by severity (line chart)
   - Top vulnerable repositories (table)
   - Remediation success rate (number)

2. **Performance Metrics**
   - Lambda duration percentiles (line chart)
   - Cold start frequency (bar chart)
   - API latency heatmap

3. **Operational Health**
   - Error rate trends (line chart)
   - System availability (number)
   - Active scans (gauge)

## Alerting Rules

### High Severity Findings Alert
```
fields severity
| filter severity = "CRITICAL" or severity = "HIGH"
| stats count(*) as critical_findings by bin(5m)
| filter critical_findings > 5
```

### Performance Degradation Alert
```
fields @duration, function_name
| filter @type = "REPORT"
| stats avg(@duration) as avg_duration by function_name
| filter avg_duration > 30000  # 30 seconds
```

### Error Spike Alert
```
fields level
| filter level = "ERROR"
| stats count(*) as error_count by bin(5m)
| filter error_count > 100
```

## Export and Integration

### Export to S3
```bash
aws logs start-query \
  --log-group-name "/aws/lambda/ai-security-analyzer" \
  --start-time $(date -u -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, severity, finding | filter severity = "CRITICAL"'

# Get query results and export
aws logs get-query-results --query-id <query-id> \
  | jq -r '.results[][] | @csv' > findings.csv
```

### Integration with Other Tools
- Use CloudWatch Logs Insights API for programmatic access
- Stream to Kinesis for real-time processing
- Export to Security Lake for long-term analysis