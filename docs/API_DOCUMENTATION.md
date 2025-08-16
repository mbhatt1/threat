# AI Security Audit Framework API Documentation

## Overview

The AI Security Audit Framework provides a comprehensive REST API for security scanning, vulnerability detection, and automated remediation. All API endpoints are secured with AWS IAM authentication and support both synchronous and asynchronous operations.

## Base URL

```
https://api.security-audit.{region}.amazonaws.com/v1
```

Replace `{region}` with your AWS region (e.g., `us-east-1`).

## Authentication

All API requests must be signed with AWS Signature Version 4. You can use AWS SDKs or tools like `awscurl` to automatically handle signing.

### Example with AWS CLI
```bash
aws apigatewayv2 invoke \
  --api-id {api-id} \
  --region {region} \
  --path-with-query-string "/scan" \
  --http-method POST \
  --body '{"repository_url": "https://github.com/example/repo"}'
```

## Endpoints

### 1. Create Security Scan

**POST** `/scan`

Initiates a new security scan for a repository.

#### Request Body
```json
{
  "repository_url": "https://github.com/example/repo",
  "branch": "main",
  "scan_type": "standard",
  "options": {
    "include_dependencies": true,
    "deep_analysis": false,
    "custom_rules": []
  }
}
```

#### Parameters
- `repository_url` (required): Git repository URL to scan
- `branch` (optional): Branch to scan (default: main/master)
- `scan_type` (optional): Type of scan - `quick`, `standard`, `comprehensive`, `hephaestus`
- `options` (optional): Additional scan configuration

#### Response
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "created_at": "2024-01-15T10:30:00Z",
  "estimated_completion": "2024-01-15T10:35:00Z",
  "webhook_url": "https://api.security-audit.us-east-1.amazonaws.com/v1/scan/550e8400-e29b-41d4-a716-446655440000/status"
}
```

### 2. Get Scan Status

**GET** `/scan/{scan_id}`

Retrieves the current status and results of a security scan.

#### Path Parameters
- `scan_id`: UUID of the scan

#### Response
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "repository_url": "https://github.com/example/repo",
  "branch": "main",
  "created_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:34:23Z",
  "findings": {
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 12,
    "total": 19
  },
  "detailed_findings": [
    {
      "id": "finding-001",
      "severity": "high",
      "category": "Security",
      "title": "SQL Injection Vulnerability",
      "description": "Potential SQL injection in user input handling",
      "file": "src/db/queries.py",
      "line": 45,
      "remediation": {
        "available": true,
        "auto_fixable": true,
        "remediation_id": "rem-001"
      }
    }
  ]
}
```

### 3. Hephaestus Cognitive Analysis

**POST** `/hephaestus/analyze`

Triggers advanced AI cognitive vulnerability discovery using the Hephaestus system.

#### Request Body
```json
{
  "repository_url": "https://github.com/example/repo",
  "deep_analysis": true,
  "evolution_enabled": true,
  "focus_areas": ["authentication", "data_validation"],
  "max_iterations": 10
}
```

#### Response
```json
{
  "analysis_id": "hep-550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "current_phase": "exploration",
  "phases_completed": [],
  "cognitive_insights": {
    "patterns_discovered": 0,
    "vulnerabilities_hypothesized": 0,
    "experiments_planned": 0
  }
}
```

### 4. Apply Remediation

**POST** `/remediate`

Applies automated remediation for identified security findings.

#### Request Body
```json
{
  "finding_id": "finding-001",
  "remediation_id": "rem-001",
  "dry_run": true,
  "create_pr": true,
  "pr_options": {
    "branch": "security-fix-001",
    "title": "Fix SQL injection vulnerability",
    "description": "Automated security fix"
  }
}
```

#### Response
```json
{
  "remediation_id": "rem-001",
  "status": "success",
  "changes_applied": [
    {
      "file": "src/db/queries.py",
      "action": "modified",
      "diff": "...",
      "lines_changed": 5
    }
  ],
  "pr_created": true,
  "pr_url": "https://github.com/example/repo/pull/123"
}
```

### 5. List Recent Scans

**GET** `/scans`

Lists recent security scans with filtering options.

#### Query Parameters
- `limit` (optional): Maximum results to return (default: 10, max: 100)
- `status` (optional): Filter by status - `pending`, `running`, `completed`, `failed`
- `severity` (optional): Filter by minimum severity - `critical`, `high`, `medium`, `low`
- `from_date` (optional): ISO 8601 date to filter scans after
- `to_date` (optional): ISO 8601 date to filter scans before

#### Response
```json
{
  "scans": [
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "repository_url": "https://github.com/example/repo",
      "status": "completed",
      "created_at": "2024-01-15T10:30:00Z",
      "findings_summary": {
        "critical": 0,
        "high": 2,
        "medium": 5,
        "low": 12
      }
    }
  ],
  "pagination": {
    "total": 45,
    "limit": 10,
    "offset": 0,
    "next_token": "eyJsYXN0S2V5IjogIjU1MGU4NDAwIn0="
  }
}
```

### 6. Webhook Management

**POST** `/webhooks`

Registers a webhook for scan notifications.

#### Request Body
```json
{
  "url": "https://example.com/webhook",
  "events": ["scan.completed", "scan.failed", "finding.critical"],
  "secret": "webhook-secret-key"
}
```

#### Response
```json
{
  "webhook_id": "wh-550e8400-e29b-41d4-a716-446655440000",
  "url": "https://example.com/webhook",
  "events": ["scan.completed", "scan.failed", "finding.critical"],
  "created_at": "2024-01-15T10:30:00Z",
  "status": "active"
}
```

## Error Responses

All errors follow a consistent format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid repository URL format",
    "details": {
      "field": "repository_url",
      "reason": "Must be a valid git URL"
    }
  },
  "request_id": "req-550e8400-e29b-41d4-a716-446655440000"
}
```

### Common Error Codes
- `VALIDATION_ERROR`: Invalid request parameters
- `NOT_FOUND`: Resource not found
- `UNAUTHORIZED`: Authentication failed
- `FORBIDDEN`: Insufficient permissions
- `RATE_LIMITED`: Too many requests
- `INTERNAL_ERROR`: Server error

## Rate Limiting

API requests are rate limited per AWS account:
- 100 requests per minute for scan creation
- 1000 requests per minute for status checks
- 10 requests per minute for Hephaestus analysis

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705318200
```

## Webhook Events

### Event Format
```json
{
  "event_type": "scan.completed",
  "timestamp": "2024-01-15T10:34:23Z",
  "data": {
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "repository_url": "https://github.com/example/repo",
    "findings_summary": {
      "critical": 0,
      "high": 2,
      "medium": 5,
      "low": 12
    }
  },
  "signature": "sha256=..."
}
```

### Available Events
- `scan.started`: Scan has begun processing
- `scan.completed`: Scan finished successfully
- `scan.failed`: Scan encountered an error
- `finding.critical`: Critical vulnerability discovered
- `finding.high`: High severity vulnerability discovered
- `remediation.completed`: Automated fix applied
- `hephaestus.phase_completed`: Hephaestus analysis phase finished

## SDK Examples

### Python
```python
import boto3
import json

client = boto3.client('apigatewaymanagementapi', 
                     endpoint_url='https://api.security-audit.us-east-1.amazonaws.com/v1')

# Create scan
response = client.post_to_connection(
    Data=json.dumps({
        'repository_url': 'https://github.com/example/repo',
        'scan_type': 'comprehensive'
    }),
    ConnectionId='scan'
)
```

### JavaScript/Node.js
```javascript
const AWS = require('aws-sdk');
const apiGateway = new AWS.ApiGatewayManagementApi({
  endpoint: 'https://api.security-audit.us-east-1.amazonaws.com/v1'
});

// Create scan
const params = {
  Data: JSON.stringify({
    repository_url: 'https://github.com/example/repo',
    scan_type: 'comprehensive'
  }),
  ConnectionId: 'scan'
};

apiGateway.postToConnection(params).promise()
  .then(data => console.log(data))
  .catch(err => console.error(err));
```

## Best Practices

1. **Use Webhooks**: For long-running scans, use webhooks instead of polling
2. **Batch Operations**: Group multiple operations when possible
3. **Error Handling**: Implement exponential backoff for retries
4. **Caching**: Cache scan results to avoid redundant API calls
5. **Security**: Never expose API credentials in client-side code

## Support

For API support and questions:
- Email: api-support@security-audit.com
- Documentation: https://docs.security-audit.com
- Status Page: https://status.security-audit.com