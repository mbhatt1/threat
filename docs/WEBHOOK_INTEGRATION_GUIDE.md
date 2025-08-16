# Webhook Integration Guide

## Overview

The AI Security Audit Framework supports webhooks to enable real-time notifications and integrations with external systems. This guide covers webhook configuration, event types, security, and integration patterns.

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Security Scan  │────▶│ EventBridge Rule │────▶│ Webhook Lambda  │
│     Events      │     │    (Filtering)   │     │   (Processing)  │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                           │
                                                           ▼
                                                  ┌─────────────────┐
                                                  │ External System │
                                                  │  (Your Webhook) │
                                                  └─────────────────┘
```

## Webhook Registration

### 1. Register via API

```bash
curl -X POST https://api.security-audit.region.amazonaws.com/v1/webhooks \
  -H "Content-Type: application/json" \
  -H "Authorization: AWS4-HMAC-SHA256 ..." \
  -d '{
    "url": "https://your-domain.com/security-webhook",
    "events": ["scan.completed", "finding.critical"],
    "secret": "your-webhook-secret-key",
    "description": "Production security notifications"
  }'
```

### 2. Register via CLI

```bash
ai-security webhook create \
  --url https://your-domain.com/security-webhook \
  --events scan.completed finding.critical \
  --secret your-webhook-secret-key
```

### 3. Register via CDK

```python
from aws_cdk import aws_dynamodb as dynamodb
import uuid

# In your CDK stack
webhook_table = dynamodb.Table(
    self, "WebhookRegistrations",
    table_name="security-webhooks",
    partition_key=dynamodb.Attribute(
        name="webhook_id",
        type=dynamodb.AttributeType.STRING
    )
)

# Add webhook registration
webhook_table.put_item(
    Item={
        'webhook_id': str(uuid.uuid4()),
        'url': 'https://your-domain.com/security-webhook',
        'events': ['scan.completed', 'finding.critical'],
        'secret': 'your-webhook-secret-key',
        'active': True,
        'created_at': datetime.utcnow().isoformat()
    }
)
```

## Event Types

### 1. Scan Events

#### scan.started
Triggered when a security scan begins.

```json
{
  "event_type": "scan.started",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "repository_url": "https://github.com/example/repo",
    "branch": "main",
    "scan_type": "comprehensive",
    "triggered_by": "scheduled"
  }
}
```

#### scan.completed
Triggered when a scan finishes successfully.

```json
{
  "event_type": "scan.completed",
  "timestamp": "2024-01-15T10:45:23Z",
  "data": {
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "repository_url": "https://github.com/example/repo",
    "duration_seconds": 923,
    "findings_summary": {
      "critical": 0,
      "high": 3,
      "medium": 7,
      "low": 15,
      "total": 25
    },
    "report_url": "https://security-reports.s3.amazonaws.com/scans/550e8400.pdf"
  }
}
```

#### scan.failed
Triggered when a scan encounters an error.

```json
{
  "event_type": "scan.failed",
  "timestamp": "2024-01-15T10:35:00Z",
  "data": {
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "error_code": "REPOSITORY_ACCESS_DENIED",
    "error_message": "Unable to clone repository: Authentication failed",
    "retry_attempt": 3,
    "will_retry": false
  }
}
```

### 2. Finding Events

#### finding.critical
Triggered for critical severity findings.

```json
{
  "event_type": "finding.critical",
  "timestamp": "2024-01-15T10:40:15Z",
  "data": {
    "finding_id": "finding-c001",
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "title": "Hardcoded AWS Credentials",
    "description": "AWS access keys found in source code",
    "severity": "critical",
    "category": "Secrets",
    "file": "src/config.js",
    "line": 15,
    "remediation": {
      "available": true,
      "auto_fixable": true,
      "description": "Remove credentials and use environment variables"
    }
  }
}
```

#### finding.high
Triggered for high severity findings.

```json
{
  "event_type": "finding.high",
  "timestamp": "2024-01-15T10:41:00Z",
  "data": {
    "finding_id": "finding-h001",
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "title": "SQL Injection Vulnerability",
    "severity": "high",
    "cvss_score": 8.5,
    "affected_component": "database query builder"
  }
}
```

### 3. Remediation Events

#### remediation.started
Triggered when automated remediation begins.

```json
{
  "event_type": "remediation.started",
  "timestamp": "2024-01-15T11:00:00Z",
  "data": {
    "remediation_id": "rem-001",
    "finding_id": "finding-c001",
    "remediation_type": "automated",
    "estimated_duration": 120
  }
}
```

#### remediation.completed
Triggered when remediation is successfully applied.

```json
{
  "event_type": "remediation.completed",
  "timestamp": "2024-01-15T11:02:30Z",
  "data": {
    "remediation_id": "rem-001",
    "finding_id": "finding-c001",
    "changes_applied": [
      {
        "file": "src/config.js",
        "action": "modified",
        "lines_changed": 3
      }
    ],
    "pr_created": true,
    "pr_url": "https://github.com/example/repo/pull/456"
  }
}
```

### 4. Hephaestus Events

#### hephaestus.phase_completed
Triggered when a Hephaestus cognitive phase completes.

```json
{
  "event_type": "hephaestus.phase_completed",
  "timestamp": "2024-01-15T12:00:00Z",
  "data": {
    "analysis_id": "hep-001",
    "phase": "hypothesis_generation",
    "phase_number": 2,
    "duration_seconds": 180,
    "hypotheses_generated": 15,
    "next_phase": "experimentation"
  }
}
```

## Webhook Security

### 1. Request Signing

All webhook requests include a signature header for verification:

```
X-Security-Signature: sha256=d2f5c1b3a4e5f6789abcdef1234567890abcdef1234567890abcdef12345678
```

#### Signature Verification (Python)
```python
import hmac
import hashlib

def verify_webhook_signature(payload, signature, secret):
    """Verify webhook signature"""
    expected_signature = 'sha256=' + hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, signature)

# In your webhook handler
@app.route('/security-webhook', methods=['POST'])
def handle_webhook():
    signature = request.headers.get('X-Security-Signature')
    if not verify_webhook_signature(request.data, signature, WEBHOOK_SECRET):
        return 'Invalid signature', 401
    
    # Process webhook...
```

#### Signature Verification (Node.js)
```javascript
const crypto = require('crypto');

function verifyWebhookSignature(payload, signature, secret) {
    const expectedSignature = 'sha256=' + crypto
        .createHmac('sha256', secret)
        .update(payload, 'utf8')
        .digest('hex');
    
    return signature === expectedSignature;
}

// In your Express handler
app.post('/security-webhook', (req, res) => {
    const signature = req.headers['x-security-signature'];
    
    if (!verifyWebhookSignature(JSON.stringify(req.body), signature, WEBHOOK_SECRET)) {
        return res.status(401).send('Invalid signature');
    }
    
    // Process webhook...
});
```

### 2. Request Headers

All webhook requests include these headers:

```
Content-Type: application/json
X-Security-Signature: sha256=...
X-Security-Event: scan.completed
X-Security-Delivery: 550e8400-e29b-41d4-a716-446655440000
X-Security-Timestamp: 1705318200
User-Agent: AI-Security-Audit/1.0
```

### 3. IP Whitelisting

Webhook requests originate from these IP ranges:
```
# Production (us-east-1)
52.94.247.0/24
52.119.224.0/20

# Production (us-west-2)
52.94.248.0/24
52.119.240.0/20
```

Configure your firewall to allow these IPs.

## Implementation Examples

### 1. Slack Integration

```python
import requests
import json

def send_to_slack(webhook_data):
    """Send security alerts to Slack"""
    event_type = webhook_data['event_type']
    data = webhook_data['data']
    
    # Format message based on event type
    if event_type == 'finding.critical':
        color = 'danger'
        title = f"🚨 Critical Security Finding: {data['title']}"
        text = data['description']
    elif event_type == 'scan.completed':
        findings = data['findings_summary']
        color = 'good' if findings['critical'] == 0 else 'danger'
        title = f"Security Scan Completed for {data['repository_url']}"
        text = f"Found {findings['total']} issues"
    
    slack_message = {
        'attachments': [{
            'color': color,
            'title': title,
            'text': text,
            'fields': [
                {'title': 'Severity', 'value': data.get('severity', 'N/A'), 'short': True},
                {'title': 'Category', 'value': data.get('category', 'N/A'), 'short': True}
            ],
            'footer': 'AI Security Audit',
            'ts': int(datetime.utcnow().timestamp())
        }]
    }
    
    requests.post(SLACK_WEBHOOK_URL, json=slack_message)
```

### 2. Jira Integration

```python
from jira import JIRA

def create_jira_issue(webhook_data):
    """Create Jira issues for security findings"""
    if webhook_data['event_type'] != 'finding.critical':
        return
    
    data = webhook_data['data']
    jira = JIRA(server=JIRA_SERVER, basic_auth=(JIRA_USER, JIRA_TOKEN))
    
    issue_dict = {
        'project': {'key': 'SEC'},
        'summary': f"[Security] {data['title']}",
        'description': f"""
h3. Security Finding Details

*Description:* {data['description']}
*Severity:* {data['severity']}
*File:* {data['file']}
*Line:* {data['line']}

h3. Remediation
{data['remediation']['description']}

h3. Additional Information
*Finding ID:* {data['finding_id']}
*Scan ID:* {data['scan_id']}
""",
        'issuetype': {'name': 'Security'},
        'priority': {'name': 'Critical'},
        'labels': ['security', 'automated', data['category'].lower()]
    }
    
    jira.create_issue(fields=issue_dict)
```

### 3. PagerDuty Integration

```python
import pdpyras

def trigger_pagerduty_alert(webhook_data):
    """Trigger PagerDuty for critical findings"""
    if webhook_data['event_type'] != 'finding.critical':
        return
    
    session = pdpyras.APISession(PAGERDUTY_API_KEY)
    data = webhook_data['data']
    
    session.trigger_incident(
        service_id=PAGERDUTY_SERVICE_ID,
        title=f"Critical Security Finding: {data['title']}",
        details={
            'finding': data,
            'repository': data.get('repository_url'),
            'immediate_action_required': True
        },
        incident_key=data['finding_id'],
        escalation_policy_id=SECURITY_ESCALATION_POLICY
    )
```

### 4. GitHub Issues

```python
from github import Github

def create_github_issue(webhook_data):
    """Create GitHub issues for findings"""
    if not webhook_data['event_type'].startswith('finding.'):
        return
    
    data = webhook_data['data']
    g = Github(GITHUB_TOKEN)
    
    # Parse repository from scan data
    repo_path = data['repository_url'].split('github.com/')[-1]
    repo = g.get_repo(repo_path)
    
    # Create issue
    issue = repo.create_issue(
        title=f"[Security] {data['title']}",
        body=f"""
## Security Finding

**Severity:** {data['severity']}
**Category:** {data['category']}
**File:** `{data['file']}`
**Line:** {data['line']}

### Description
{data['description']}

### Remediation
{data['remediation']['description']}

---
*This issue was automatically created by AI Security Audit Framework*
*Finding ID: {data['finding_id']}*
""",
        labels=['security', data['severity'], 'automated']
    )
```

## Webhook Management

### 1. List Webhooks

```bash
# CLI
ai-security webhook list

# API
curl -X GET https://api.security-audit.region.amazonaws.com/v1/webhooks \
  -H "Authorization: AWS4-HMAC-SHA256 ..."
```

### 2. Update Webhook

```bash
# CLI
ai-security webhook update \
  --id webhook-123 \
  --events scan.completed finding.critical finding.high

# API
curl -X PUT https://api.security-audit.region.amazonaws.com/v1/webhooks/webhook-123 \
  -H "Content-Type: application/json" \
  -H "Authorization: AWS4-HMAC-SHA256 ..." \
  -d '{
    "events": ["scan.completed", "finding.critical", "finding.high"]
  }'
```

### 3. Delete Webhook

```bash
# CLI
ai-security webhook delete --id webhook-123

# API
curl -X DELETE https://api.security-audit.region.amazonaws.com/v1/webhooks/webhook-123 \
  -H "Authorization: AWS4-HMAC-SHA256 ..."
```

### 4. Test Webhook

```bash
# Send test event
ai-security webhook test \
  --id webhook-123 \
  --event scan.completed
```

## Error Handling

### Retry Logic

Failed webhook deliveries are retried with exponential backoff:
- 1st retry: 1 minute
- 2nd retry: 5 minutes
- 3rd retry: 15 minutes
- 4th retry: 1 hour
- 5th retry: 6 hours

### Failure Notifications

After 5 failed attempts, webhooks are marked as failing and notifications are sent.

### Dead Letter Queue

Failed webhooks are stored in DLQ for manual review:

```python
# Query failed webhooks
dynamodb = boto3.resource('dynamodb')
dlq_table = dynamodb.Table('webhook-dlq')

response = dlq_table.query(
    KeyConditionExpression=Key('webhook_id').eq('webhook-123'),
    ScanIndexForward=False,
    Limit=10
)

for item in response['Items']:
    print(f"Failed delivery: {item['delivery_id']}")
    print(f"Error: {item['error_message']}")
    print(f"Response: {item['response_code']}")
```

## Monitoring

### CloudWatch Metrics

Monitor webhook performance with these metrics:
- `WebhookDeliverySuccess`: Successful deliveries
- `WebhookDeliveryFailure`: Failed deliveries
- `WebhookDeliveryLatency`: Delivery time
- `WebhookQueueDepth`: Pending deliveries

### Sample Dashboard Query

```
SELECT 
    webhook_id,
    COUNT(*) as total_deliveries,
    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
    AVG(delivery_time_ms) as avg_latency
FROM webhook_deliveries
WHERE timestamp > NOW() - INTERVAL 24 HOUR
GROUP BY webhook_id
```

## Best Practices

1. **Idempotency**: Design webhook handlers to be idempotent
2. **Timeouts**: Respond within 5 seconds to avoid timeouts
3. **Async Processing**: Process webhooks asynchronously
4. **Verification**: Always verify webhook signatures
5. **Monitoring**: Set up alerts for webhook failures
6. **Documentation**: Document expected webhook format for your team

## Troubleshooting

### Common Issues

1. **Signature Verification Failures**
   - Check secret key matches
   - Ensure no payload modification
   - Verify encoding (UTF-8)

2. **Timeout Errors**
   - Implement async processing
   - Return 200 immediately
   - Process in background

3. **Missing Events**
   - Check webhook registration
   - Verify event subscriptions
   - Review CloudWatch logs

4. **Duplicate Events**
   - Implement idempotency keys
   - Track processed events
   - Use delivery IDs