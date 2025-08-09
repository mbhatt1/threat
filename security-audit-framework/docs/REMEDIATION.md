# Immediate Remediation System

## Overview

The Security Audit Framework includes an automated remediation system that can immediately respond to critical security findings. When enabled, the system can automatically take corrective actions for specific types of vulnerabilities, reducing the window of exposure and minimizing security risks.

## Architecture

### Components

1. **Remediation Lambda Function**
   - Centralized remediation logic
   - Handles multiple remediation types
   - Integrates with AWS services for automated fixes
   - Maintains audit trail in DynamoDB

2. **Agent Integration**
   - Secrets agent can trigger remediation for critical findings
   - Passes finding details to remediation Lambda
   - Configurable via environment variables

3. **Notification System**
   - SNS alerts for all remediation actions
   - Detailed notifications include finding and action taken
   - Audit logging for compliance

## Supported Remediation Types

### 1. AWS Access Key Rotation
- **Trigger**: Exposed AWS access keys in code
- **Action**: 
  - Deactivates compromised key
  - Creates new access key (if user has < 2 keys)
  - Stores new key in Secrets Manager
  - Notifies via SNS

### 2. Secrets Manager Rotation
- **Trigger**: Exposed secrets that exist in AWS Secrets Manager
- **Action**:
  - Triggers immediate rotation
  - Updates secret version
  - Maintains rotation history
  - Notifies of rotation completion

### 3. Database Password Rotation
- **Trigger**: Exposed RDS credentials
- **Action**:
  - Generates new password
  - Updates RDS instance
  - Stores in Secrets Manager
  - Updates connection strings

### 4. SSH Key Management
- **Trigger**: Exposed SSH private keys
- **Action**:
  - Marks key as compromised in tracking table
  - Removes from authorized_keys (if EC2)
  - Generates alert for manual review
  - Creates compliance report

## Configuration

### Environment Variables

```bash
# Enable/disable remediation
ENABLE_REMEDIATION=true

# Remediation Lambda ARN
REMEDIATION_LAMBDA_NAME=SecurityAudit-prod-Lambda-RemediationFunction

# Notification settings
ALERT_TOPIC_ARN=arn:aws:sns:region:account:SecurityAudit-Alerts
```

### IAM Permissions

The remediation system requires specific permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:DeleteAccessKey",
        "iam:CreateAccessKey",
        "iam:ListAccessKeys",
        "secretsmanager:RotateSecret",
        "secretsmanager:UpdateSecret",
        "rds:ModifyDBInstance",
        "ec2:DescribeKeyPairs",
        "ec2:DeleteKeyPair"
      ],
      "Resource": "*"
    }
  ]
}
```

## Workflow

### 1. Detection Phase
```mermaid
graph LR
    A[Security Agent] --> B{Critical Finding?}
    B -->|Yes| C[Check Remediation Enabled]
    B -->|No| D[Standard Reporting]
    C --> E[Invoke Remediation Lambda]
```

### 2. Remediation Phase
```mermaid
graph TD
    A[Remediation Lambda] --> B{Finding Type}
    B -->|AWS Key| C[Rotate Access Key]
    B -->|Secret| D[Rotate Secret]
    B -->|DB Password| E[Rotate DB Password]
    B -->|SSH Key| F[Manage SSH Key]
    C --> G[Update DynamoDB]
    D --> G
    E --> G
    F --> G
    G --> H[Send SNS Alert]
```

### 3. Audit Trail
All remediation actions are logged with:
- Timestamp
- Finding details
- Action taken
- Success/failure status
- Error messages (if any)

## Usage Examples

### Enable Remediation for Secrets Agent

```python
# In ECS task definition
environment = [
    {
        "name": "ENABLE_REMEDIATION",
        "value": "true"
    },
    {
        "name": "REMEDIATION_LAMBDA_NAME",
        "value": remediation_lambda.function_name
    }
]
```

### Manual Remediation Trigger

```python
import boto3
import json

lambda_client = boto3.client('lambda')

payload = {
    "finding_type": "aws_access_key",
    "details": {
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "user_name": "compromised-user",
        "file_path": "config/prod.env",
        "line_number": 42
    },
    "repository": "my-app",
    "scan_id": "scan-12345"
}

response = lambda_client.invoke(
    FunctionName='RemediationFunction',
    Payload=json.dumps(payload)
)
```

## Best Practices

### 1. Gradual Rollout
- Start with non-production environments
- Monitor remediation actions closely
- Gradually expand scope

### 2. Testing
- Test remediation in isolated environments
- Verify applications handle rotated credentials
- Maintain rollback procedures

### 3. Monitoring
- Set up CloudWatch alarms for remediation failures
- Monitor remediation frequency
- Track false positive rates

### 4. Compliance
- Maintain audit logs for all actions
- Document remediation policies
- Regular review of automated actions

## Limitations

1. **No Automatic Code Updates**: The system rotates credentials but doesn't update code
2. **Application Restarts**: Some applications may need restart after credential rotation
3. **Rate Limits**: AWS API rate limits apply to remediation actions
4. **Manual Review**: Some findings require human intervention

## Security Considerations

1. **Least Privilege**: Remediation Lambda has minimal required permissions
2. **Audit Trail**: All actions are logged and traceable
3. **Notification**: All stakeholders are notified of remediation actions
4. **Validation**: Findings are validated before remediation

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Check IAM roles for remediation Lambda
   - Verify agent has permission to invoke Lambda

2. **Remediation Failed**
   - Check CloudWatch logs for detailed errors
   - Verify target resource exists and is accessible

3. **No Remediation Triggered**
   - Verify ENABLE_REMEDIATION is set to "true"
   - Check finding severity threshold

### Debug Mode

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Future Enhancements

1. **Code Patching**: Automatic PR creation with updated credentials
2. **Custom Remediation**: Plugin system for custom remediation logic
3. **ML-Based Decisions**: Use ML to determine remediation actions
4. **Rollback Capability**: Automatic rollback on application failure