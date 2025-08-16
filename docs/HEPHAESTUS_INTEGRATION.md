# Hephaestus AI Cognitive Vulnerability Discovery - Integration Guide

## Overview

Hephaestus AI has been successfully integrated into the threat security framework. It can now be triggered through multiple entry points:
- **API Gateway** - REST API endpoints
- **SNS Topics** - Message-based triggers
- **EventBridge** - Scheduled and event-driven triggers

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   API Gateway   │     │    SNS Topic    │     │   EventBridge   │
│  /ai/hephaestus │     │ Security Scans  │     │ Rules & Schedule│
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                         │
         └───────────────────────┴─────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ AI Security Analyzer   │
                    │       Lambda            │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Hephaestus AI Module  │
                    │  (Bedrock Integration) │
                    └─────────────────────────┘
```

## Triggering Hephaestus Analysis

### 1. Via API Gateway

**Endpoint**: `POST /v1/ai/hephaestus-cognitive`

**Request Body**:
```json
{
  "action": "hephaestus_cognitive",
  "payload": {
    "repository_url": "https://github.com/your-org/your-repo",
    "branch": "main",
    "scan_type": "full",
    "max_vulnerabilities": 10,
    "enable_evolution": true,
    "custom_patterns": []
  }
}
```

**Example cURL**:
```bash
curl -X POST https://your-api-gateway-url/v1/ai/hephaestus-cognitive \
  -H "Content-Type: application/json" \
  -H "Authorization: AWS4-HMAC-SHA256 ..." \
  -d '{
    "action": "hephaestus_cognitive",
    "payload": {
      "repository_url": "https://github.com/example/vulnerable-app",
      "branch": "main"
    }
  }'
```

### 2. Via SNS Topic

**Topic**: Security Scan Request Topic

**Message Format**:
```json
{
  "default": "Hephaestus Analysis Request",
  "message_type": "hephaestus_analysis",
  "repository_url": "https://github.com/your-org/your-repo",
  "branch": "main",
  "scan_type": "full",
  "max_vulnerabilities": 10,
  "enable_evolution": true
}
```

**AWS CLI Example**:
```bash
aws sns publish \
  --topic-arn arn:aws:sns:region:account:security-scan-requests-stackname \
  --message-attributes '{"scan_enabled":{"DataType":"String","StringValue":"true"}}' \
  --message '{
    "message_type": "hephaestus_analysis",
    "repository_url": "https://github.com/example/vulnerable-app",
    "branch": "main"
  }'
```

### 3. Via EventBridge

#### Scheduled Scans
Hephaestus runs automatically every week via the configured EventBridge rule.

#### Manual Trigger
**Event Pattern**:
```json
{
  "source": ["custom.security"],
  "detail-type": ["Hephaestus Analysis Request"],
  "detail": {
    "repository_url": "https://github.com/your-org/your-repo",
    "branch": "main",
    "scan_type": "full"
  }
}
```

**AWS CLI Example**:
```bash
aws events put-events \
  --entries '[{
    "Source": "custom.security",
    "DetailType": "Hephaestus Analysis Request",
    "Detail": "{\"repository_url\":\"https://github.com/example/vulnerable-app\",\"branch\":\"main\"}"
  }]'
```

## Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `repository_url` | string | required | Git repository URL to analyze |
| `branch` | string | "main" | Git branch to analyze |
| `scan_type` | string | "full" | Type of scan: "full" or "targeted" |
| `max_vulnerabilities` | integer | 10 | Maximum vulnerabilities to discover |
| `enable_evolution` | boolean | true | Enable evolutionary learning |
| `custom_patterns` | array | [] | Custom vulnerability patterns |
| `s3_bucket` | string | auto | S3 bucket for storing results |

## Hephaestus Cognitive Phases

1. **Exploration Phase**: Maps the application architecture
2. **Hypothesis Phase**: Generates vulnerability theories
3. **Experimentation Phase**: Tests vulnerability hypotheses
4. **Validation Phase**: Confirms exploitability
5. **Learning Phase**: Extracts patterns and insights
6. **Evolution Phase**: Adapts and improves detection

## Monitoring and Results

### CloudWatch Logs
- Log Group: `/aws/lambda/AISecurityAnalyzerLambda`
- Filter for Hephaestus: `[HEPHAESTUS]`

### S3 Results
Results are stored in the configured S3 bucket:
```
s3://your-results-bucket/hephaestus-results/
  ├── YYYY-MM-DD/
  │   ├── scan-id/
  │   │   ├── vulnerability-chains.json
  │   │   ├── analysis-report.json
  │   │   └── evolution-patterns.json
```

### DynamoDB Tracking
Scan status is tracked in the SecurityScans table:
- Partition Key: `scan_id`
- Scan Type: `hephaestus_cognitive`

## Example Vulnerability Chain Output

```json
{
  "vulnerability_chain": {
    "id": "vc-001",
    "severity": "critical",
    "cvss_score": 9.8,
    "chain_type": "multi_stage_exploit",
    "steps": [
      {
        "step": 1,
        "vulnerability": "SQL Injection",
        "location": "login.php:45",
        "exploit": "' OR '1'='1",
        "impact": "Authentication bypass"
      },
      {
        "step": 2,
        "vulnerability": "Privilege Escalation",
        "location": "admin.php:78",
        "exploit": "role=admin",
        "impact": "Admin access gained"
      },
      {
        "step": 3,
        "vulnerability": "Remote Code Execution",
        "location": "upload.php:123",
        "exploit": "shell.php upload",
        "impact": "System compromise"
      }
    ],
    "remediation": {
      "priority": "immediate",
      "fixes": [
        "Implement parameterized queries",
        "Add role-based access control",
        "Validate file uploads"
      ]
    }
  }
}
```

## Best Practices

1. **Repository Access**: Ensure the Lambda has access to private repositories via:
   - SSH keys stored in Secrets Manager
   - Personal Access Tokens
   - AWS CodeCommit credentials

2. **Performance**: For large codebases:
   - Use `scan_type: "targeted"` for specific areas
   - Adjust `max_vulnerabilities` based on needs
   - Monitor Lambda timeout (currently 15 minutes)

3. **Cost Optimization**:
   - Bedrock Claude 3 Sonnet is used by default
   - Monitor token usage in CloudWatch
   - Use EventBridge rules to control scan frequency

4. **Security**:
   - Results are encrypted at rest in S3
   - IAM roles follow least-privilege principle
   - API Gateway uses IAM authentication

## Troubleshooting

### Common Issues

1. **Timeout Errors**
   - Increase Lambda timeout
   - Reduce `max_vulnerabilities`
   - Use targeted scans

2. **Repository Access**
   - Check Secrets Manager configuration
   - Verify network connectivity
   - Ensure git credentials are valid

3. **Bedrock Limits**
   - Monitor token usage
   - Check service quotas
   - Implement retry logic

### Debug Commands

```bash
# Check Lambda logs
aws logs tail /aws/lambda/AISecurityAnalyzerLambda --follow

# Check scan status
aws dynamodb get-item \
  --table-name SecurityScans \
  --key '{"scan_id": {"S": "your-scan-id"}}'

# List recent Hephaestus results
aws s3 ls s3://your-results-bucket/hephaestus-results/ --recursive
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: Hephaestus Security Scan
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger Hephaestus Scan
        env:
          AWS_DEFAULT_REGION: us-east-1
        run: |
          aws sns publish \
            --topic-arn ${{ secrets.SNS_TOPIC_ARN }} \
            --message '{
              "message_type": "hephaestus_analysis",
              "repository_url": "${{ github.server_url }}/${{ github.repository }}",
              "branch": "${{ github.ref_name }}"
            }'
```

## Support and Feedback

For issues or feature requests related to Hephaestus integration:
1. Check CloudWatch logs for detailed error messages
2. Review the vulnerability chains in S3 for insights
3. Contact the security team for advanced configuration

## Future Enhancements

- [ ] Real-time vulnerability streaming
- [ ] Integration with SIEM systems
- [ ] Custom vulnerability pattern library
- [ ] Multi-language support expansion
- [ ] Automated remediation workflows