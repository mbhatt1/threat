# Security Audit Framework - Deployment Checklist

## Pre-Deployment Requirements

### AWS Account Setup
- [ ] AWS Account with appropriate permissions
- [ ] AWS CLI v2 installed and configured
- [ ] IAM user/role with deployment permissions
- [ ] Service quotas reviewed and increased if needed

### Development Environment
- [ ] Python 3.11+ installed
- [ ] Node.js 18+ and npm installed
- [ ] Docker installed and running
- [ ] AWS CDK v2 installed (`npm install -g aws-cdk`)
- [ ] Git configured with repository access

### AWS Service Limits Check
- [ ] Lambda concurrent executions: minimum 1000
- [ ] ECS Fargate tasks: minimum 100
- [ ] S3 buckets: sufficient quota
- [ ] DynamoDB tables: sufficient quota
- [ ] SNS topics: minimum 10

## Deployment Steps

### 1. Environment Configuration

```bash
# Set AWS profile
export AWS_PROFILE=security-audit

# Set deployment region
export AWS_REGION=us-east-1

# Set environment variables
export ENVIRONMENT=production
export PROJECT_NAME=security-audit-framework
```

### 2. Initial Setup

- [ ] Clone repository
  ```bash
  git clone <repository-url>
  cd security-audit-framework
  ```

- [ ] Install dependencies
  ```bash
  # Python dependencies
  python -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  
  # CDK dependencies
  cd cdk
  npm install
  cd ..
  ```

- [ ] Configure secrets
  ```bash
  # Create secrets in AWS Secrets Manager
  aws secretsmanager create-secret \
    --name security-audit/github-token \
    --secret-string '{"token":"your-github-token"}'
  
  aws secretsmanager create-secret \
    --name security-audit/email-config \
    --secret-string '{"sender":"security@example.com","recipients":["team@example.com"]}'
  ```

### 3. Infrastructure Deployment

- [ ] Bootstrap CDK (first time only)
  ```bash
  cdk bootstrap aws://${AWS_ACCOUNT_ID}/${AWS_REGION}
  ```

- [ ] Deploy core infrastructure
  ```bash
  cd cdk
  
  # Deploy in order
  cdk deploy CoreStack --require-approval never
  cdk deploy NetworkingStack --require-approval never
  cdk deploy StorageStack --require-approval never
  cdk deploy DatabaseStack --require-approval never
  ```

- [ ] Deploy compute resources
  ```bash
  cdk deploy ECSStack --require-approval never
  cdk deploy LambdaStack --require-approval never
  cdk deploy StepFunctionsStack --require-approval never
  ```

- [ ] Deploy integrations
  ```bash
  cdk deploy SNSStack --require-approval never
  cdk deploy APIStack --require-approval never
  cdk deploy MonitoringStack --require-approval never
  ```

### 4. Post-Deployment Configuration

- [ ] Configure SNS subscriptions
  ```bash
  # GitHub webhook
  aws sns subscribe \
    --topic-arn arn:aws:sns:${AWS_REGION}:${AWS_ACCOUNT_ID}:security-audit-github \
    --protocol https \
    --notification-endpoint https://api.yourdomain.com/webhooks/github
  ```

- [ ] Set up Security Hub
  ```bash
  # Enable Security Hub
  aws securityhub enable-security-hub
  
  # Enable standards
  aws securityhub batch-enable-standards \
    --standards-subscription-requests \
    StandardsArn=arn:aws:securityhub:${AWS_REGION}::standards/aws-foundational-security-best-practices/v/1.0.0
  ```

- [ ] Configure QuickSight
  ```bash
  # Create data source
  aws quicksight create-data-source \
    --aws-account-id ${AWS_ACCOUNT_ID} \
    --data-source-id security-audit-athena \
    --name "Security Audit Data" \
    --type ATHENA
  ```

### 5. Validation

- [ ] Test SNS message processing
  ```bash
  ./scripts/test-sns.sh
  ```

- [ ] Test API endpoints
  ```bash
  ./scripts/test-api.sh
  ```

- [ ] Trigger test scan
  ```bash
  ./scripts/test-scan.sh https://github.com/example/test-repo
  ```

- [ ] Verify CloudWatch logs
  ```bash
  aws logs tail /aws/lambda/security-audit-ceo-agent --follow
  ```

- [ ] Check ECS task status
  ```bash
  aws ecs list-tasks --cluster security-audit-cluster
  ```

## Production Configuration

### Security Hardening

- [ ] Enable WAF on API Gateway
  ```bash
  aws wafv2 create-web-acl \
    --name security-audit-waf \
    --scope REGIONAL \
    --default-action Allow={} \
    --rules file://waf-rules.json
  ```

- [ ] Configure VPC endpoints
  ```bash
  # S3 endpoint
  aws ec2 create-vpc-endpoint \
    --vpc-id ${VPC_ID} \
    --service-name com.amazonaws.${AWS_REGION}.s3
  
  # DynamoDB endpoint
  aws ec2 create-vpc-endpoint \
    --vpc-id ${VPC_ID} \
    --service-name com.amazonaws.${AWS_REGION}.dynamodb
  ```

- [ ] Enable GuardDuty
  ```bash
  aws guardduty create-detector --enable
  ```

### Monitoring Setup

- [ ] Create CloudWatch dashboards
  ```bash
  aws cloudwatch put-dashboard \
    --dashboard-name SecurityAuditOverview \
    --dashboard-body file://dashboards/overview.json
  ```

- [ ] Set up alarms
  ```bash
  # High error rate alarm
  aws cloudwatch put-metric-alarm \
    --alarm-name security-audit-errors \
    --alarm-description "High error rate in security audit" \
    --metric-name Errors \
    --namespace AWS/Lambda \
    --statistic Sum \
    --period 300 \
    --threshold 10 \
    --comparison-operator GreaterThanThreshold
  ```

- [ ] Configure X-Ray
  ```bash
  # Enable X-Ray tracing
  aws lambda update-function-configuration \
    --function-name security-audit-ceo-agent \
    --tracing-config Mode=Active
  ```

### Cost Optimization

- [ ] Set up cost alerts
  ```bash
  aws ce put-anomaly-monitor \
    --anomaly-monitor '{
      "MonitorName": "SecurityAuditCostMonitor",
      "MonitorType": "DIMENSIONAL",
      "MonitorDimension": "SERVICE"
    }'
  ```

- [ ] Configure S3 lifecycle policies
  ```bash
  aws s3api put-bucket-lifecycle-configuration \
    --bucket security-audit-results \
    --lifecycle-configuration file://s3-lifecycle.json
  ```

- [ ] Enable Compute Savings Plans
  ```bash
  # Review recommendations
  aws ce get-savings-plans-purchase-recommendation \
    --savings-plans-type COMPUTE_SP \
    --term-in-years ONE_YEAR \
    --payment-option NO_UPFRONT
  ```

## Operational Procedures

### Daily Checks
- [ ] Monitor CloudWatch dashboard
- [ ] Review Security Hub findings
- [ ] Check failed SNS messages in DLQ
- [ ] Verify ECS task health

### Weekly Tasks
- [ ] Analyze QuickSight reports
- [ ] Review cost optimization recommendations
- [ ] Update agent container images
- [ ] Check for security patches

### Monthly Tasks
- [ ] Perform disaster recovery drill
- [ ] Review and update IAM policies
- [ ] Analyze performance metrics
- [ ] Update documentation

## Troubleshooting Guide

### Common Issues

1. **SNS Messages Not Processing**
   ```bash
   # Check DLQ
   aws sqs receive-message --queue-url ${DLQ_URL}
   
   # View Lambda logs
   aws logs tail /aws/lambda/security-audit-sns-handler
   ```

2. **ECS Tasks Failing**
   ```bash
   # Describe task
   aws ecs describe-tasks --cluster security-audit-cluster --tasks ${TASK_ARN}
   
   # Check task logs
   aws logs get-log-events --log-group-name /ecs/security-audit
   ```

3. **High Costs**
   ```bash
   # Review cost explorer
   aws ce get-cost-and-usage \
     --time-period Start=2024-01-01,End=2024-01-31 \
     --granularity DAILY \
     --metrics UnblendedCost
   ```

### Support Contacts

- **AWS Support**: [Create support case](https://console.aws.amazon.com/support)
- **Internal Team**: security-audit-team@company.com
- **On-Call**: See PagerDuty rotation

## Rollback Procedures

### Infrastructure Rollback
```bash
# List stack events
aws cloudformation describe-stack-events --stack-name SecurityAuditStack

# Rollback to previous version
cdk deploy --rollback
```

### Application Rollback
```bash
# Revert Lambda function
aws lambda update-function-code \
  --function-name security-audit-ceo-agent \
  --s3-bucket deployment-artifacts \
  --s3-key previous-version.zip

# Revert ECS task definition
aws ecs update-service \
  --cluster security-audit-cluster \
  --service security-audit-agents \
  --task-definition security-audit-agents:previous
```

## Sign-off Checklist

### Technical Sign-off
- [ ] All infrastructure deployed successfully
- [ ] All tests passing
- [ ] Monitoring configured and working
- [ ] Security controls in place
- [ ] Documentation complete

### Business Sign-off
- [ ] Cost estimates reviewed and approved
- [ ] SLAs defined and agreed
- [ ] Runbook procedures documented
- [ ] Training completed
- [ ] Go-live approval received

---

**Deployment Status**: ⬜ Not Started / 🟡 In Progress / ✅ Complete

**Date**: _________________

**Deployed By**: _________________

**Approved By**: _________________