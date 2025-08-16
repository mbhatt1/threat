# Hephaestus AI System Integration

The Hephaestus AI Cognitive + Bedrock vulnerability discovery system is now fully integrated into the threat framework and can be triggered through multiple entry points.

## Entry Points

### 1. API Gateway Endpoint

Make HTTP POST requests to the AI Security Analyzer endpoint:

```bash
POST /dev/ai-security-analyzer
Content-Type: application/json

{
  "action": "hephaestus_cognitive",
  "payload": {
    "repository_s3_bucket": "your-code-bucket",
    "repository_s3_key": "repositories/myapp.zip",
    "max_iterations": 2,
    "severity_filter": "critical"
  }
}
```

**Response:**
```json
{
  "analysis_complete": true,
  "total_vulnerability_chains": 42,
  "iterations_completed": 2,
  "by_severity": {
    "critical": 8,
    "high": 15,
    "medium": 12,
    "low": 7
  },
  "critical_chains_count": 8,
  "chains": [...],
  "full_results_s3": "s3://results-bucket/hephaestus-results/request-id.json"
}
```

### 2. SNS Topic Trigger

Publish to the AI Security SNS topic:

```python
import boto3
import json

sns = boto3.client('sns')

message = {
    "action": "hephaestus_cognitive",
    "payload": {
        "repository_s3_bucket": "your-code-bucket",
        "repository_s3_key": "repositories/myapp.zip",
        "max_iterations": 3
    }
}

sns.publish(
    TopicArn='arn:aws:sns:region:account:threat-ai-security-topic',
    Message=json.dumps(message)
)
```

### 3. EventBridge Rule

Create an EventBridge rule to trigger Hephaestus analysis:

```json
{
  "Source": "threat.security",
  "DetailType": "Hephaestus Analysis Request",
  "Detail": {
    "action": "hephaestus_cognitive",
    "payload": {
      "repository_s3_bucket": "your-code-bucket",
      "repository_s3_key": "repositories/myapp.zip",
      "max_iterations": 2,
      "severity_filter": "high"
    }
  }
}
```

### 4. Direct Lambda Invocation

```python
import boto3
import json

lambda_client = boto3.client('lambda')

payload = {
    "action": "hephaestus_cognitive",
    "payload": {
        "repository_s3_bucket": "your-code-bucket",
        "repository_s3_key": "repositories/myapp.zip",
        "max_iterations": 2
    }
}

response = lambda_client.invoke(
    FunctionName='threat-ai-security-analyzer',
    InvocationType='RequestResponse',
    Payload=json.dumps(payload)
)
```

## Input Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `repository_s3_bucket` | string | Yes* | S3 bucket containing the repository |
| `repository_s3_key` | string | Yes* | S3 key to the repository (zip file) |
| `repository_path` | string | Yes* | Alternative: local path (for testing) |
| `max_iterations` | integer | No | Number of cognitive iterations (default: 2) |
| `severity_filter` | string | No | Filter results: "critical", "high", "medium", "low" |

*Either S3 location OR repository_path is required

## Integration with Step Functions

You can integrate Hephaestus into your security scanning workflow:

```json
{
  "Comment": "Security Scanning Workflow",
  "StartAt": "CloneRepository",
  "States": {
    "CloneRepository": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:repository-cloner",
      "Next": "RunHephaestusAnalysis"
    },
    "RunHephaestusAnalysis": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:ai-security-analyzer",
      "Parameters": {
        "action": "hephaestus_cognitive",
        "payload": {
          "repository_s3_bucket.$": "$.bucket",
          "repository_s3_key.$": "$.key",
          "max_iterations": 3
        }
      },
      "Next": "ProcessResults"
    },
    "ProcessResults": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:report-generator",
      "End": true
    }
  }
}
```

## Automated Triggers

### On Code Push (CI/CD Integration)

Configure your CI/CD pipeline to trigger Hephaestus:

```yaml
# GitHub Actions Example
- name: Trigger Hephaestus Analysis
  env:
    AWS_REGION: ${{ secrets.AWS_REGION }}
  run: |
    aws lambda invoke \
      --function-name threat-ai-security-analyzer \
      --payload '{"action":"hephaestus_cognitive","payload":{"repository_s3_bucket":"${{ env.BUCKET }}","repository_s3_key":"${{ env.KEY }}"}}' \
      response.json
```

### Scheduled Scans

Create an EventBridge rule for periodic scans:

```bash
aws events put-rule \
  --name hephaestus-weekly-scan \
  --schedule-expression "rate(7 days)"

aws events put-targets \
  --rule hephaestus-weekly-scan \
  --targets "Id"="1","Arn"="arn:aws:lambda:region:account:function:ai-security-analyzer","Input"="{\"action\":\"hephaestus_cognitive\",\"payload\":{\"repository_s3_bucket\":\"prod-code-bucket\",\"repository_s3_key\":\"current/app.zip\"}}"
```

## Output Handling

### Small Results (< 50 chains)
Results are returned directly in the Lambda response.

### Large Results
Full results including POCs are stored in S3:
- Location: `s3://results-bucket/hephaestus-results/{request-id}.json`
- The S3 location is returned in the response as `full_results_s3`

### Integration with Reporting

The results can be automatically processed by the report generator:

```python
# In your report generator Lambda
if event.get('hephaestus_results_s3'):
    s3 = boto3.client('s3')
    bucket, key = parse_s3_url(event['hephaestus_results_s3'])
    
    obj = s3.get_object(Bucket=bucket, Key=key)
    hephaestus_data = json.loads(obj['Body'].read())
    
    # Generate report from Hephaestus findings
    critical_chains = [c for c in hephaestus_data['chains'] 
                      if c['severity'] == 'critical']
```

## Monitoring and Alerts

### CloudWatch Metrics
Monitor Hephaestus performance:
- `HephaestusAnalysisTime`: Duration of analysis
- `HephaestusVulnerabilitiesFound`: Number of chains discovered
- `HephaestusCriticalFindings`: Critical severity count

### SNS Notifications
Configure SNS to alert on critical findings:

```python
if critical_chains_count > 0:
    sns.publish(
        TopicArn='arn:aws:sns:region:account:security-alerts',
        Subject='Critical Vulnerabilities Found by Hephaestus',
        Message=f'Found {critical_chains_count} critical vulnerability chains'
    )
```

## Cost Optimization

- Hephaestus uses AWS Bedrock which charges per token
- Monitor usage with CloudWatch metrics
- Use `max_iterations=1` for quick scans
- Filter by severity to reduce response size
- Consider scheduling intensive scans during off-peak hours

## Error Handling

The Lambda handles various error cases:
- Missing AWS credentials
- Bedrock access denied
- Invalid repository format
- Analysis timeouts

Errors are returned with appropriate status codes and messages.

## Example: Complete Integration Flow

```python
import boto3
import json

# 1. Upload code to S3
s3 = boto3.client('s3')
s3.upload_file('myapp.zip', 'code-bucket', 'repos/myapp.zip')

# 2. Trigger Hephaestus via EventBridge
events = boto3.client('events')
events.put_events(
    Entries=[{
        'Source': 'my.application',
        'DetailType': 'Code Analysis Request',
        'Detail': json.dumps({
            'action': 'hephaestus_cognitive',
            'payload': {
                'repository_s3_bucket': 'code-bucket',
                'repository_s3_key': 'repos/myapp.zip',
                'max_iterations': 2,
                'severity_filter': 'high'
            }
        })
    }]
)

# 3. Results will be:
# - Sent to SNS topic for notifications
# - Stored in S3 for detailed analysis
# - Available in CloudWatch Logs
# - Tracked in CloudWatch Metrics
```

## Best Practices

1. **Repository Preparation**: Zip your repository excluding unnecessary files (.git, node_modules, etc.)
2. **Iteration Count**: Start with 2 iterations, increase for deeper analysis
3. **Severity Filtering**: Use filters to focus on critical issues first
4. **Result Storage**: Always check `full_results_s3` for complete findings
5. **Cost Management**: Monitor Bedrock usage and adjust iterations accordingly
6. **Parallel Analysis**: For large codebases, split into components and analyze in parallel