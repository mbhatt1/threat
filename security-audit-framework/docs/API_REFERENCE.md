# Security Audit Framework - API Reference

## Base URL

```
https://api.security-audit.example.com/v1
```

## Authentication

All API requests require authentication using AWS IAM Signature Version 4 or API Keys.

### IAM Authentication
```bash
# Using AWS CLI
aws apigateway test-invoke-method \
  --rest-api-id {api-id} \
  --resource-id {resource-id} \
  --http-method POST \
  --path-with-query-string '/v1/scans'
```

### API Key Authentication
```bash
curl -X POST https://api.security-audit.example.com/v1/scans \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/example/repo"}'
```

## Rate Limiting

- **Default**: 100 requests per minute per API key
- **Burst**: 200 requests
- **Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

## API Endpoints

### 1. Create Security Scan

Initiates a new security scan for a Git repository.

```http
POST /v1/scans
```

#### Request Body

```json
{
  "repository_url": "https://github.com/example/repo.git",
  "branch": "main",
  "scan_options": {
    "agents": ["SAST", "DEPENDENCY", "SECRETS", "IAC", "API", "CONTAINER"],
    "deep_scan": true,
    "priority": "high",
    "tags": {
      "environment": "production",
      "team": "backend"
    }
  },
  "notification_config": {
    "email": ["security@example.com"],
    "slack_webhook": "https://hooks.slack.com/services/xxx",
    "on_completion": true,
    "on_high_severity": true
  }
}
```

#### Response

```json
{
  "scan_id": "scan-123e4567-e89b-12d3-a456-426614174000",
  "status": "INITIATED",
  "created_at": "2024-01-15T10:30:00Z",
  "estimated_completion": "2024-01-15T10:45:00Z",
  "links": {
    "self": "/v1/scans/scan-123e4567-e89b-12d3-a456-426614174000",
    "status": "/v1/scans/scan-123e4567-e89b-12d3-a456-426614174000/status",
    "results": "/v1/scans/scan-123e4567-e89b-12d3-a456-426614174000/results"
  }
}
```

#### Status Codes

- `201 Created`: Scan successfully initiated
- `400 Bad Request`: Invalid request format
- `401 Unauthorized`: Authentication failed
- `429 Too Many Requests`: Rate limit exceeded

### 2. List Scans

Retrieves a list of security scans with pagination and filtering.

```http
GET /v1/scans
```

#### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `page` | integer | Page number | 1 |
| `page_size` | integer | Items per page (max 100) | 20 |
| `status` | string | Filter by status | all |
| `repository` | string | Filter by repository URL | - |
| `start_date` | ISO 8601 | Filter scans after date | - |
| `end_date` | ISO 8601 | Filter scans before date | - |
| `severity` | string | Filter by highest severity | - |

#### Response

```json
{
  "scans": [
    {
      "scan_id": "scan-123e4567-e89b-12d3-a456-426614174000",
      "repository_url": "https://github.com/example/repo.git",
      "branch": "main",
      "status": "COMPLETED",
      "created_at": "2024-01-15T10:30:00Z",
      "completed_at": "2024-01-15T10:42:00Z",
      "summary": {
        "total_findings": 42,
        "critical": 2,
        "high": 5,
        "medium": 15,
        "low": 20
      }
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_pages": 5,
    "total_items": 98
  },
  "links": {
    "self": "/v1/scans?page=1",
    "next": "/v1/scans?page=2",
    "last": "/v1/scans?page=5"
  }
}
```

### 3. Get Scan Details

Retrieves detailed information about a specific scan.

```http
GET /v1/scans/{scan_id}
```

#### Path Parameters

- `scan_id` (required): Unique scan identifier

#### Response

```json
{
  "scan_id": "scan-123e4567-e89b-12d3-a456-426614174000",
  "repository_url": "https://github.com/example/repo.git",
  "branch": "main",
  "commit_sha": "a1b2c3d4e5f6",
  "status": "COMPLETED",
  "created_at": "2024-01-15T10:30:00Z",
  "started_at": "2024-01-15T10:30:15Z",
  "completed_at": "2024-01-15T10:42:00Z",
  "scan_options": {
    "agents": ["SAST", "DEPENDENCY", "SECRETS"],
    "deep_scan": true,
    "priority": "high"
  },
  "execution_details": {
    "step_function_arn": "arn:aws:states:us-east-1:123456789012:execution:SecurityAudit:xxx",
    "cost_estimate": "$0.25",
    "duration_seconds": 720
  },
  "agent_status": {
    "SAST": {
      "status": "COMPLETED",
      "started_at": "2024-01-15T10:31:00Z",
      "completed_at": "2024-01-15T10:35:00Z",
      "findings_count": 15
    },
    "DEPENDENCY": {
      "status": "COMPLETED",
      "started_at": "2024-01-15T10:31:00Z",
      "completed_at": "2024-01-15T10:38:00Z",
      "findings_count": 22
    },
    "SECRETS": {
      "status": "COMPLETED",
      "started_at": "2024-01-15T10:31:00Z",
      "completed_at": "2024-01-15T10:33:00Z",
      "findings_count": 5
    }
  },
  "summary": {
    "total_findings": 42,
    "by_severity": {
      "critical": 2,
      "high": 5,
      "medium": 15,
      "low": 20
    },
    "by_agent": {
      "SAST": 15,
      "DEPENDENCY": 22,
      "SECRETS": 5
    }
  }
}
```

### 4. Get Scan Status

Retrieves the current status of a scan.

```http
GET /v1/scans/{scan_id}/status
```

#### Response

```json
{
  "scan_id": "scan-123e4567-e89b-12d3-a456-426614174000",
  "status": "IN_PROGRESS",
  "progress": {
    "percentage": 65,
    "current_phase": "SCANNING",
    "agents_completed": 2,
    "agents_total": 3
  },
  "estimated_completion": "2024-01-15T10:45:00Z"
}
```

### 5. Get Scan Results

Retrieves detailed findings from a completed scan.

```http
GET /v1/scans/{scan_id}/results
```

#### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `severity` | string | Filter by severity | all |
| `agent` | string | Filter by agent type | all |
| `file_path` | string | Filter by file path | - |
| `finding_type` | string | Filter by finding type | - |

#### Response

```json
{
  "scan_id": "scan-123e4567-e89b-12d3-a456-426614174000",
  "findings": [
    {
      "finding_id": "finding-987654321",
      "agent": "SAST",
      "type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "title": "SQL Injection vulnerability detected",
      "description": "User input is directly concatenated into SQL query without sanitization",
      "file_path": "src/api/users.py",
      "line_number": 42,
      "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021",
      "remediation": {
        "description": "Use parameterized queries or prepared statements",
        "example": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "effort": "LOW",
        "references": [
          "https://owasp.org/www-community/attacks/SQL_Injection"
        ]
      },
      "attack_vector": {
        "exploitability": "EASY",
        "impact": "HIGH",
        "mitre_attack": ["T1190", "T1055"]
      }
    }
  ],
  "attack_paths": [
    {
      "path_id": "path-123",
      "name": "Database Compromise via Web Application",
      "severity": "CRITICAL",
      "steps": [
        {
          "technique": "T1190",
          "name": "Exploit Public-Facing Application",
          "findings": ["finding-987654321"]
        },
        {
          "technique": "T1055",
          "name": "Process Injection",
          "findings": ["finding-123456789"]
        }
      ]
    }
  ],
  "statistics": {
    "total_findings": 42,
    "false_positive_rate": 0.15,
    "scan_coverage": 0.95
  }
}
```

### 6. Update Scan

Updates scan configuration or marks findings as false positives.

```http
PUT /v1/scans/{scan_id}
```

#### Request Body

```json
{
  "action": "mark_false_positive",
  "finding_ids": ["finding-987654321"],
  "reason": "Input is already sanitized by framework",
  "tags": {
    "reviewed_by": "security-team"
  }
}
```

#### Response

```json
{
  "scan_id": "scan-123e4567-e89b-12d3-a456-426614174000",
  "updated_findings": 1,
  "message": "Successfully marked 1 finding as false positive"
}
```

### 7. Cancel Scan

Cancels an in-progress scan.

```http
DELETE /v1/scans/{scan_id}
```

#### Response

```json
{
  "scan_id": "scan-123e4567-e89b-12d3-a456-426614174000",
  "status": "CANCELLED",
  "message": "Scan cancelled successfully"
}
```

### 8. Get Scan Report

Generates and retrieves a formatted report for a scan.

```http
GET /v1/scans/{scan_id}/report
```

#### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `format` | string | Report format (pdf, html, json) | json |
| `include_remediation` | boolean | Include remediation details | true |
| `include_code_snippets` | boolean | Include code snippets | true |

#### Response (JSON format)

```json
{
  "report": {
    "scan_id": "scan-123e4567-e89b-12d3-a456-426614174000",
    "generated_at": "2024-01-15T11:00:00Z",
    "executive_summary": {
      "risk_score": 85,
      "critical_findings": 2,
      "requires_immediate_action": true
    },
    "detailed_findings": [...],
    "recommendations": [
      {
        "priority": "HIGH",
        "action": "Update dependency 'requests' to version 2.31.0",
        "impact": "Resolves 3 critical vulnerabilities"
      }
    ]
  }
}
```

### 9. Trigger Remediation

Initiates automated remediation for specific findings.

```http
POST /v1/scans/{scan_id}/remediate
```

#### Request Body

```json
{
  "finding_ids": ["finding-987654321", "finding-123456789"],
  "remediation_type": "AUTO_FIX",
  "create_pull_request": true,
  "pr_options": {
    "branch_name": "security-fixes-2024-01-15",
    "title": "Security: Fix SQL injection vulnerabilities",
    "reviewers": ["security-team", "backend-team"]
  }
}
```

#### Response

```json
{
  "remediation_id": "rem-456789",
  "status": "IN_PROGRESS",
  "findings_to_remediate": 2,
  "pull_request_url": "https://github.com/example/repo/pull/123"
}
```

### 10. Get Repository Statistics

Retrieves historical statistics for a repository.

```http
GET /v1/repositories/statistics
```

#### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `repository_url` | string | Repository URL (required) | - |
| `start_date` | ISO 8601 | Start date for statistics | 30 days ago |
| `end_date` | ISO 8601 | End date for statistics | now |

#### Response

```json
{
  "repository_url": "https://github.com/example/repo.git",
  "period": {
    "start": "2023-12-15T00:00:00Z",
    "end": "2024-01-15T00:00:00Z"
  },
  "statistics": {
    "total_scans": 45,
    "findings_trend": [
      {
        "date": "2023-12-15",
        "critical": 5,
        "high": 10,
        "medium": 20,
        "low": 30
      }
    ],
    "top_vulnerabilities": [
      {
        "type": "DEPENDENCY_VULNERABILITY",
        "count": 156,
        "trend": "DECREASING"
      }
    ],
    "security_score_trend": [
      {
        "date": "2023-12-15",
        "score": 65
      },
      {
        "date": "2024-01-15",
        "score": 85
      }
    ],
    "mean_time_to_remediation": {
      "critical": "2.5 days",
      "high": "5.2 days",
      "medium": "15.3 days"
    }
  }
}
```

### 11. AI SQL Injection Analysis

Performs deep AI-powered SQL injection vulnerability analysis on code.

```http
POST /v1/ai-security/sql-injection
```

#### Request Body

```json
{
  "code": "def get_user(user_id):\n    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n    return db.execute(query)",
  "language": "python",
  "context": {
    "framework": "flask",
    "database": "postgresql"
  }
}
```

#### Response

```json
{
  "risk_score": 0.95,
  "vulnerabilities": [
    {
      "type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "confidence": 0.98,
      "description": "Direct string interpolation of user input into SQL query creates SQL injection vulnerability",
      "location": {
        "line": 2,
        "column": 13
      },
      "evidence": "The variable 'user_id' is directly interpolated into the SQL query without sanitization"
    }
  ],
  "recommendations": [
    {
      "priority": "CRITICAL",
      "fix": "Use parameterized queries: query = \"SELECT * FROM users WHERE id = %s\"; db.execute(query, (user_id,))",
      "explanation": "Parameterized queries prevent SQL injection by separating SQL logic from data"
    }
  ],
  "ai_analysis": {
    "model": "claude-3-sonnet",
    "reasoning": "The code uses f-string formatting to directly embed user input into a SQL query. This allows attackers to inject malicious SQL commands.",
    "attack_scenarios": [
      "Input: '1 OR 1=1' could return all users",
      "Input: '1; DROP TABLE users;--' could delete the users table"
    ]
  }
}
```

### 12. AI Threat Intelligence

Analyzes security threats and predicts potential attack vectors using AI.

```http
POST /v1/ai-security/threat-intelligence
```

#### Request Body

```json
{
  "scan_results": {
    "vulnerabilities": ["SQL_INJECTION", "XSS", "WEAK_CRYPTO"],
    "exposed_endpoints": ["/api/users", "/api/admin"],
    "technologies": ["python", "flask", "postgresql"]
  },
  "repository_url": "https://github.com/example/repo"
}
```

#### Response

```json
{
  "threat_assessment": {
    "overall_risk": "HIGH",
    "score": 8.5,
    "confidence": 0.92
  },
  "active_threats": [
    {
      "threat_type": "DATABASE_BREACH",
      "probability": 0.85,
      "impact": "CRITICAL",
      "ttc": "2-5 days",
      "description": "SQL injection combined with exposed admin endpoint creates high risk of database compromise"
    }
  ],
  "predicted_attacks": [
    {
      "attack_vector": "SQL_INJECTION_TO_PRIVILEGE_ESCALATION",
      "likelihood": 0.78,
      "sophistication": "MEDIUM",
      "potential_attackers": ["Script Kiddies", "Cybercriminals"],
      "mitre_techniques": ["T1190", "T1068"]
    }
  ],
  "recommendations": [
    {
      "action": "Implement WAF rules for SQL injection",
      "priority": "CRITICAL",
      "effort": "LOW"
    },
    {
      "action": "Enable database activity monitoring",
      "priority": "HIGH",
      "effort": "MEDIUM"
    }
  ],
  "historical_correlation": {
    "similar_breaches": 15,
    "average_impact": "$2.3M",
    "common_exploit_chain": ["SQL Injection", "Data Exfiltration", "Ransomware"]
  }
}
```

### 13. AI Root Cause Analysis

Performs deep root cause analysis on security incidents using AI.

```http
POST /v1/ai-security/root-cause
```

#### Request Body

```json
{
  "incident": {
    "type": "DATA_BREACH",
    "timestamp": "2024-01-15T03:45:00Z",
    "affected_systems": ["user-api", "database"],
    "indicators": [
      "Unusual database queries at 3:45 AM",
      "Large data transfer to unknown IP",
      "Admin account created without authorization"
    ]
  },
  "event_logs": [
    {
      "timestamp": "2024-01-15T03:30:00Z",
      "event": "Failed login attempts on admin panel",
      "source": "203.0.113.42"
    }
  ],
  "scan_history": {
    "last_scan": "2024-01-10T10:00:00Z",
    "critical_findings": 2,
    "unpatched_vulnerabilities": ["SQL_INJECTION", "WEAK_AUTH"]
  }
}
```

#### Response

```json
{
  "root_causes": [
    {
      "cause": "UNPATCHED_SQL_INJECTION",
      "confidence": 0.94,
      "evidence": [
        "SQL injection vulnerability detected 5 days before breach",
        "Attack pattern matches SQL injection exploitation",
        "Database queries show classic injection signatures"
      ],
      "contributing_factors": [
        "Delayed patching process",
        "Lack of WAF protection",
        "Missing database activity monitoring"
      ]
    }
  ],
  "attack_timeline": [
    {
      "time": "T-5 days",
      "event": "SQL injection vulnerability detected in scan",
      "severity": "CRITICAL"
    },
    {
      "time": "T-15 minutes",
      "event": "Initial reconnaissance via admin panel",
      "severity": "LOW"
    },
    {
      "time": "T-0",
      "event": "SQL injection exploit successful",
      "severity": "CRITICAL"
    },
    {
      "time": "T+5 minutes",
      "event": "Privilege escalation via injected admin account",
      "severity": "CRITICAL"
    },
    {
      "time": "T+15 minutes",
      "event": "Data exfiltration begins",
      "severity": "CRITICAL"
    }
  ],
  "remediation_gaps": [
    {
      "gap": "No automated patching for critical vulnerabilities",
      "impact": "5-day exposure window",
      "recommendation": "Implement automated patching with 24-hour SLA for critical issues"
    }
  ],
  "ai_insights": {
    "attack_sophistication": "MEDIUM",
    "attacker_profile": "Opportunistic cybercriminal exploiting known vulnerabilities",
    "prevention_effectiveness": "Would have been prevented by: WAF (95%), Timely patching (100%), DB monitoring (80%)"
  }
}
```

### 14. Pure AI Vulnerability Detection

Performs comprehensive vulnerability detection using pure AI analysis without traditional security tools.

```http
POST /v1/ai-security/pure-ai
```

#### Request Body

```json
{
  "code": "const express = require('express');\nconst app = express();\n\napp.get('/user/:id', (req, res) => {\n  const userId = req.params.id;\n  const query = `SELECT * FROM users WHERE id = ${userId}`;\n  db.query(query, (err, result) => {\n    if (err) res.status(500).send(err);\n    res.json(result);\n  });\n});",
  "language": "javascript",
  "analysis_depth": "comprehensive"
}
```

#### Response

```json
{
  "analysis_passes": {
    "general": {
      "vulnerabilities": 3,
      "code_quality_score": 0.4
    },
    "semantic": {
      "data_flow_issues": 2,
      "trust_boundary_violations": 1
    },
    "behavioral": {
      "suspicious_patterns": 2,
      "security_anti_patterns": 3
    },
    "cross_reference": {
      "confirmed_vulnerabilities": 5,
      "false_positives_removed": 1
    }
  },
  "findings": [
    {
      "vulnerability": "SQL_INJECTION",
      "severity": "CRITICAL",
      "confidence": 0.99,
      "cwe": "CWE-89",
      "description": "Direct template literal interpolation of user input into SQL query",
      "data_flow": [
        "User input from req.params.id",
        "Flows to userId variable",
        "Directly embedded in SQL query string",
        "Executed against database"
      ],
      "exploitation_difficulty": "TRIVIAL",
      "business_impact": "Complete database compromise possible"
    },
    {
      "vulnerability": "NO_INPUT_VALIDATION",
      "severity": "HIGH",
      "confidence": 0.95,
      "description": "User input accepted without any validation or sanitization"
    },
    {
      "vulnerability": "ERROR_INFO_DISCLOSURE",
      "severity": "MEDIUM",
      "confidence": 0.90,
      "description": "Raw error objects sent to client may leak sensitive information"
    }
  ],
  "ai_reasoning": {
    "analysis_strategy": "Multi-pass deep learning analysis focusing on data flow, semantic understanding, and behavioral patterns",
    "key_insights": [
      "Code shows classic SQL injection pattern with string interpolation",
      "No security middleware or input validation detected",
      "Error handling could expose stack traces to attackers"
    ],
    "comparison_confidence": "99% - pattern matches thousands of known SQL injection examples"
  },
  "recommended_fixes": {
    "immediate": [
      {
        "fix": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = ?', [userId], ...)",
        "effort": "5 minutes",
        "risk_reduction": "95%"
      }
    ],
    "comprehensive": [
      {
        "fix": "Implement input validation middleware",
        "effort": "1 hour",
        "risk_reduction": "80%"
      },
      {
        "fix": "Add security headers and rate limiting",
        "effort": "2 hours",
        "risk_reduction": "60%"
      }
    ]
  }
}
```

### 15. AI Security Sandbox

Tests code for vulnerabilities in an AI-simulated sandbox environment.

```http
POST /v1/ai-security/sandbox
```

#### Request Body

```json
{
  "code": "import pickle\nimport base64\n\ndef load_user_data(encoded_data):\n    decoded = base64.b64decode(encoded_data)\n    return pickle.loads(decoded)",
  "language": "python",
  "test_inputs": [
    "cG9zMQouCg==",
    "gASVFAAAAAAAAACMCF9fbWFpbl9flIwEdGVzdJSMAV2UhpQu"
  ],
  "simulation_options": {
    "detect_rce": true,
    "detect_data_leaks": true,
    "max_execution_time": 5000
  }
}
```

#### Response

```json
{
  "vulnerabilities_detected": [
    {
      "type": "INSECURE_DESERIALIZATION",
      "severity": "CRITICAL",
      "confidence": 0.99,
      "description": "Pickle deserialization of untrusted data can lead to remote code execution",
      "exploit_demonstration": {
        "payload": "cos\\nsystem\\n(S'echo pwned > /tmp/hacked'\\ntR.",
        "impact": "Arbitrary command execution on server",
        "success_rate": 1.0
      }
    }
  ],
  "simulated_attacks": [
    {
      "attack_type": "RCE_VIA_PICKLE",
      "stages": [
        {
          "stage": "Payload crafting",
          "description": "Attacker creates malicious pickle payload with os.system call"
        },
        {
          "stage": "Encoding",
          "description": "Payload base64 encoded to match expected format"
        },
        {
          "stage": "Execution",
          "description": "Server deserializes payload, executing arbitrary commands"
        }
      ],
      "potential_damage": {
        "data_theft": "HIGH",
        "system_compromise": "CRITICAL",
        "lateral_movement": "HIGH"
      }
    }
  ],
  "safe_alternatives": [
    {
      "recommendation": "Use JSON instead of pickle for data serialization",
      "example": "import json\\ndata = json.loads(decoded_data)",
      "security_improvement": "100% - JSON cannot execute arbitrary code"
    },
    {
      "recommendation": "If pickle is required, use hmac to sign data",
      "example": "import hmac\\nif not hmac.compare_digest(signature, expected): raise ValueError()",
      "security_improvement": "95% - Prevents untrusted deserialization"
    }
  ],
  "sandbox_execution": {
    "isolated": true,
    "resources_used": {
      "cpu_time": "120ms",
      "memory": "15MB"
    },
    "ai_confidence": 0.99,
    "analysis_method": "Static analysis + simulated execution paths"
  }
}
```

## Webhook Events

The API can send webhook notifications for scan events.

### Event Types

1. **scan.started**
   ```json
   {
     "event": "scan.started",
     "timestamp": "2024-01-15T10:30:00Z",
     "data": {
       "scan_id": "scan-123",
       "repository_url": "https://github.com/example/repo"
     }
   }
   ```

2. **scan.completed**
   ```json
   {
     "event": "scan.completed",
     "timestamp": "2024-01-15T10:42:00Z",
     "data": {
       "scan_id": "scan-123",
       "status": "COMPLETED",
       "summary": {
         "total_findings": 42,
         "critical": 2
       }
     }
   }
   ```

3. **finding.critical**
   ```json
   {
     "event": "finding.critical",
     "timestamp": "2024-01-15T10:35:00Z",
     "data": {
       "scan_id": "scan-123",
       "finding": {
         "type": "SQL_INJECTION",
         "severity": "CRITICAL",
         "file_path": "src/api/users.py"
       }
     }
   }
   ```

## Error Responses

All error responses follow a consistent format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid repository URL format",
    "details": {
      "field": "repository_url",
      "reason": "URL must be a valid Git repository"
    },
    "request_id": "req-789012",
    "documentation_url": "https://docs.security-audit.example.com/errors/VALIDATION_ERROR"
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `AUTHENTICATION_ERROR` | 401 | Authentication failed |
| `PERMISSION_DENIED` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Internal server error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

## SDK Examples

### Python SDK

```python
from security_audit import SecurityAuditClient

# Initialize client
client = SecurityAuditClient(
    api_key="YOUR_API_KEY",
    region="us-east-1"
)

# Create scan
scan = client.create_scan(
    repository_url="https://github.com/example/repo.git",
    branch="main",
    agents=["SAST", "DEPENDENCY", "SECRETS"],
    deep_scan=True
)

# Wait for completion
scan.wait_for_completion()

# Get results
results = scan.get_results()
for finding in results.findings:
    if finding.severity == "CRITICAL":
        print(f"Critical issue: {finding.title} in {finding.file_path}")
```

### JavaScript SDK

```javascript
const { SecurityAuditClient } = require('@security-audit/sdk');

// Initialize client
const client = new SecurityAuditClient({
  apiKey: 'YOUR_API_KEY',
  region: 'us-east-1'
});

// Create scan
const scan = await client.createScan({
  repositoryUrl: 'https://github.com/example/repo.git',
  branch: 'main',
  scanOptions: {
    agents: ['SAST', 'DEPENDENCY', 'SECRETS'],
    deepScan: true
  }
});

// Poll for results
const results = await scan.waitForCompletion();

// Process findings
results.findings
  .filter(f => f.severity === 'CRITICAL')
  .forEach(finding => {
    console.log(`Critical: ${finding.title} in ${finding.filePath}`);
  });
```

### Go SDK

```go
package main

import (
    "fmt"
    "github.com/security-audit/sdk-go"
)

func main() {
    // Initialize client
    client := securityaudit.NewClient(
        securityaudit.WithAPIKey("YOUR_API_KEY"),
        securityaudit.WithRegion("us-east-1"),
    )

    // Create scan
    scan, err := client.CreateScan(&securityaudit.CreateScanInput{
        RepositoryURL: "https://github.com/example/repo.git",
        Branch:        "main",
        ScanOptions: &securityaudit.ScanOptions{
            Agents:   []string{"SAST", "DEPENDENCY", "SECRETS"},
            DeepScan: true,
        },
    })
    if err != nil {
        panic(err)
    }

    // Wait for completion
    results, err := scan.WaitForCompletion()
    if err != nil {
        panic(err)
    }

    // Process results
    for _, finding := range results.Findings {
        if finding.Severity == "CRITICAL" {
            fmt.Printf("Critical: %s in %s\n", finding.Title, finding.FilePath)
        }
    }
}
```

## API Versioning

The API uses URL-based versioning. The current version is `v1`.

### Version Header

Clients can request a specific API version behavior using the header:
```
X-API-Version: 2024-01-15
```

### Deprecation Policy

- New versions are released quarterly
- Previous versions supported for 12 months
- Deprecation notices sent 6 months in advance
- Breaking changes only in major versions

## Rate Limiting Details

### Default Limits

| Tier | Requests/Minute | Burst | Monthly Scans |
|------|----------------|-------|---------------|
| Free | 10 | 20 | 100 |
| Standard | 100 | 200 | 1,000 |
| Professional | 500 | 1,000 | 10,000 |
| Enterprise | Custom | Custom | Unlimited |

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705319400
X-RateLimit-Retry-After: 60
```

## Best Practices

1. **Pagination**: Always paginate when listing resources
2. **Polling**: Use exponential backoff when polling for status
3. **Caching**: Cache scan results for at least 5 minutes
4. **Error Handling**: Implement retry logic for 5xx errors
5. **Webhooks**: Prefer webhooks over polling for real-time updates

## Support

- **Documentation**: https://docs.security-audit.example.com
- **API Status**: https://status.security-audit.example.com
- **Support Email**: api-support@security-audit.example.com
- **GitHub Issues**: https://github.com/security-audit/api/issues