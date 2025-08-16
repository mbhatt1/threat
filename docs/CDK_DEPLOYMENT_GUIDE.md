# CDK Deployment Guide for Hephaestus Integration

## Overview

This guide ensures that the Hephaestus AI Cognitive module is properly deployed with the AWS CDK infrastructure.

## Pre-deployment Checklist

### 1. Verify Source Structure
```
threat/
├── cdk/                        # CDK infrastructure code
│   ├── app.py                 # Main CDK app (updated for AI Security Lambda)
│   └── stacks/
│       ├── lambda_stack.py    # Lambda configurations (custom bundling for Hephaestus)
│       ├── api_stack.py       # API Gateway endpoints
│       ├── eventbridge_stack.py # EventBridge rules
│       └── sns_stack.py       # SNS topics
├── src/                       # Source code
│   ├── ai_models/            # AI model implementations
│   │   ├── __init__.py
│   │   ├── hephaestus_ai_cognitive_bedrock.py  # Main Hephaestus module
│   │   └── ...
│   └── lambdas/
│       ├── ai_security_analyzer/
│       │   ├── handler.py     # Lambda handler with Hephaestus integration
│       │   └── requirements.txt # Dependencies including GitPython
│       └── sns_handler/
│           └── handler.py     # SNS handler with Hephaestus routing
```

### 2. Key CDK Updates Made

#### Lambda Stack (lambda_stack.py)
- **Custom Bundling**: The AI Security Analyzer Lambda now uses custom bundling to include the ai_models directory:
```python
ai_analyzer_code = lambda_.Code.from_asset(
    os.path.join("..", "src"),
    bundling=lambda_.BundlingOptions(
        image=lambda_.Runtime.PYTHON_3_11.bundling_image,
        command=[
            "bash", "-c",
            "pip install -r lambdas/ai_security_analyzer/requirements.txt -t /asset-output && " +
            "cp -r lambdas/ai_security_analyzer/handler.py /asset-output/ && " +
            "cp -r ai_models /asset-output/"
        ]
    )
)
```

#### Environment Variables
- `BEDROCK_MODEL_ID`: Set to Claude 3 Sonnet
- `HEPHAESTUS_MAX_FILES`: Limits files per batch
- `HEPHAESTUS_DEFAULT_ITERATIONS`: Cognitive iterations

## Deployment Steps

### 1. Install Dependencies
```bash
cd threat
pip install -r requirements.txt
```

### 2. Bootstrap CDK (if not already done)
```bash
cdk bootstrap aws://ACCOUNT-ID/REGION
```

### 3. Synthesize CDK Stack
```bash
cd cdk
cdk synth
```

### 4. Deploy the Stack
```bash
cdk deploy --all
```

### 5. Verify Deployment

#### Check Lambda Function
```bash
aws lambda get-function \
  --function-name AISecurityAudit-Lambda-AISecurityAnalyzerLambda
```

#### Check Lambda Code
```bash
# Download and inspect the deployment package
aws lambda get-function \
  --function-name AISecurityAudit-Lambda-AISecurityAnalyzerLambda \
  --query 'Code.Location' --output text | xargs wget -O lambda.zip

# Verify ai_models directory is included
unzip -l lambda.zip | grep ai_models
```

## Post-Deployment Verification

### 1. Test Lambda Directly
```bash
aws lambda invoke \
  --function-name AISecurityAudit-Lambda-AISecurityAnalyzerLambda \
  --payload '{
    "action": "hephaestus_cognitive",
    "payload": {
      "repository_url": "https://github.com/example/test-repo",
      "branch": "main"
    }
  }' \
  response.json
```

### 2. Check CloudWatch Logs
```bash
aws logs tail /aws/lambda/AISecurityAudit-Lambda-AISecurityAnalyzerLambda --follow
```

### 3. Verify API Gateway
```bash
# Get API ID
aws apigateway get-rest-apis \
  --query "items[?name=='security-audit-api'].id" \
  --output text

# Test endpoint (replace API_ID)
curl -X POST https://API_ID.execute-api.REGION.amazonaws.com/v1/ai/hephaestus-cognitive \
  -H "Content-Type: application/json" \
  -d '{
    "action": "hephaestus_cognitive",
    "payload": {
      "repository_url": "https://github.com/example/test-repo"
    }
  }'
```

## Troubleshooting

### Issue: ModuleNotFoundError for ai_models
**Solution**: The Lambda stack now uses custom bundling to ensure ai_models is included.

### Issue: GitPython not found
**Solution**: Added to Lambda requirements.txt

### Issue: Bedrock access denied
**Solution**: Ensure Lambda IAM role has bedrock:InvokeModel permission

### Issue: S3 access for repositories
**Solution**: Lambda role includes S3 read/write permissions

## CDK Best Practices for Hephaestus

1. **Memory Allocation**: Set to 3GB for complex analysis
2. **Timeout**: 15 minutes for full repository scans
3. **Ephemeral Storage**: 5GB for cloning repositories
4. **Environment Encryption**: KMS key for sensitive data

## Updating Hephaestus

When updating the Hephaestus module:

1. Modify `threat/src/ai_models/hephaestus_ai_cognitive_bedrock.py`
2. Run CDK diff to see changes: `cdk diff`
3. Deploy updates: `cdk deploy`
4. Monitor deployment in CloudFormation console

## Rollback Procedure

If issues occur:
```bash
# Rollback to previous version
cdk deploy --rollback

# Or manually via CloudFormation
aws cloudformation cancel-update-stack \
  --stack-name AISecurityAudit-Lambda
```

## Performance Optimization

1. **Cold Start Mitigation**:
   - Provisioned concurrency can be added if needed
   - Shared layer includes common dependencies

2. **Cost Optimization**:
   - Monitor Bedrock token usage
   - Use targeted scans for large repositories
   - Implement caching for repeated analyses

## Security Considerations

1. **Repository Access**:
   - Use Secrets Manager for git credentials
   - Rotate tokens regularly

2. **Result Storage**:
   - S3 bucket encryption enabled
   - Lifecycle policies for old results

3. **API Access**:
   - IAM authentication required
   - WAF rules protect against abuse