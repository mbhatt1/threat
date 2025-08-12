# Security Audit Framework - Operations Guide

## Table of Contents
1. [Deployment Guide](#deployment-guide)
2. [Configuration Management](#configuration-management)
3. [Monitoring & Alerting](#monitoring--alerting)
4. [Performance Tuning](#performance-tuning)
5. [Disaster Recovery](#disaster-recovery)
6. [Maintenance Procedures](#maintenance-procedures)
7. [Security Operations](#security-operations)
8. [Cost Management](#cost-management)
9. [Troubleshooting Runbook](#troubleshooting-runbook)
10. [Scaling Guide](#scaling-guide)

## Deployment Guide

### Prerequisites Checklist

```mermaid
graph TD
    subgraph "Prerequisites"
        AWS[AWS Account Setup]
        IAM[IAM Permissions]
        Tools[Development Tools]
        Secrets[Secrets Configuration]
    end
    
    subgraph "AWS Requirements"
        AWS --> Region[Select Region]
        AWS --> Limits[Check Service Limits]
        AWS --> Budget[Set Budget Alerts]
    end
    
    subgraph "IAM Setup"
        IAM --> Admin[Admin Access for Deploy]
        IAM --> Service[Service Accounts]
        IAM --> Roles[Cross-Account Roles]
    end
    
    subgraph "Tools Required"
        Tools --> CDK[AWS CDK 2.x]
        Tools --> Docker[Docker Engine]
        Tools --> Python[Python 3.11+]
        Tools --> Node[Node.js 18+]
    end
    
    subgraph "Secrets Setup"
        Secrets --> GitHub[GitHub Token]
        Secrets --> Email[SES Email]
        Secrets --> Keys[API Keys]
    end
```

### Deployment Process

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant CDK as AWS CDK
    participant CF as CloudFormation
    participant AWS as AWS Services
    participant Test as Testing
    
    Dev->>CDK: cdk bootstrap
    CDK->>CF: Create CDK Toolkit Stack
    
    Dev->>CDK: cdk synth
    CDK->>CDK: Generate Templates
    CDK->>Dev: Validate Templates
    
    Dev->>CDK: cdk deploy --all
    CDK->>CF: Create Stacks
    
    loop For Each Stack
        CF->>AWS: Create Resources
        AWS->>CF: Resource Created
        CF->>CDK: Stack Progress
    end
    
    CDK->>Dev: Deployment Complete
    Dev->>Test: Run Integration Tests
    Test->>AWS: Validate Services
    Test->>Dev: Test Results
```

### Step-by-Step Deployment

1. **Environment Setup**
   ```bash
   # Clone repository
   git clone <repository-url>
   cd security-audit-framework
   
   # Install dependencies
   npm install -g aws-cdk
   pip install -r requirements.txt
   ```

2. **Configure AWS Credentials**
   ```bash
   # Configure AWS CLI
   aws configure
   
   # Set environment variables
   export AWS_REGION=us-east-1
   export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
   export CDK_DEFAULT_REGION=$AWS_REGION
   ```

3. **Bootstrap CDK**
   ```bash
   # Bootstrap CDK in target region
   cdk bootstrap aws://$CDK_DEFAULT_ACCOUNT/$CDK_DEFAULT_REGION
   ```

4. **Deploy Infrastructure**
   ```bash
   # Deploy all stacks
   cd scripts
   ./deploy.sh
   
   # Or deploy individual stacks
   cdk deploy SecurityAudit-prod-Network
   cdk deploy SecurityAudit-prod-Storage
   # ... continue with other stacks
   ```

### Post-Deployment Verification

```mermaid
graph LR
    subgraph "Verification Steps"
        API[Test API Endpoints]
        SNS[Verify SNS Topics]
        Lambda[Check Lambda Functions]
        ECS[Validate ECS Tasks]
        Storage[Confirm S3/DynamoDB]
    end
    
    subgraph "Health Checks"
        API --> Health[/health endpoint]
        Lambda --> Logs[CloudWatch Logs]
        ECS --> Running[Task Status]
        Storage --> Access[Read/Write Test]
    end
    
    subgraph "Integration Tests"
        SNS --> Publish[Test Message]
        Publish --> Process[Verify Processing]
        Process --> Results[Check Results]
    end
```

## Configuration Management

### Environment Variables

```mermaid
graph TD
    subgraph "Lambda Environment Variables"
        CEO[CEO Agent]
        Agg[Aggregator]
        Report[Report Generator]
        SNS[SNS Handler]
    end
    
    subgraph "Required Variables"
        BUCKET[RESULTS_BUCKET]
        TABLE[SCAN_TABLE]
        TOPIC[SNS_TOPIC_ARN]
        STATE[STATE_MACHINE_ARN]
        EFS[EFS_MOUNT_PATH]
    end
    
    subgraph "Optional Variables"
        LIMIT[COST_LIMIT]
        EMAIL[SES_SENDER_EMAIL]
        DEBUG[DEBUG_LEVEL]
        REGION[AWS_REGION]
    end
    
    CEO --> BUCKET
    CEO --> TABLE
    CEO --> EFS
    
    Agg --> BUCKET
    Agg --> TABLE
    
    Report --> BUCKET
    Report --> EMAIL
    
    SNS --> TABLE
    SNS --> STATE
```

### Secrets Management

```mermaid
sequenceDiagram
    participant App as Application
    participant SM as Secrets Manager
    participant Cache as Local Cache
    participant Rotation as Rotation Lambda
    
    App->>Cache: Check for Secret
    
    alt Secret in Cache
        Cache->>App: Return Cached Secret
    else Secret Not Cached
        App->>SM: GetSecretValue
        SM->>App: Return Secret
        App->>Cache: Store with TTL
    end
    
    Note over SM,Rotation: Automatic Rotation
    SM->>Rotation: Trigger Rotation
    Rotation->>SM: Update Secret
    Rotation->>App: Invalidate Cache
```

### Configuration Files

1. **CDK Configuration** (`cdk.json`)
   ```json
   {
     "app": "python3 app.py",
     "context": {
       "@aws-cdk/core:stackRelativeExports": true,
       "env": "prod",
       "cost_limit": 1000,
       "enable_spot": true,
       "retention_days": 90
     }
   }
   ```

2. **Agent Configuration** (`agent-config.json`)
   ```json
   {
     "agents": {
       "SAST": {
         "enabled": true,
         "memory": 2048,
         "timeout": 900,
         "rules": ["security", "owasp-top-10"]
       },
       "SECRETS": {
         "enabled": true,
         "memory": 1024,
         "timeout": 600,
         "entropy_threshold": 4.5
       }
     }
   }
   ```

## Monitoring & Alerting

### Dashboard Architecture

```mermaid
graph TB
    subgraph "CloudWatch Dashboards"
        Ops[Operations Dashboard]
        Sec[Security Dashboard]
        Cost[Cost Dashboard]
        Perf[Performance Dashboard]
    end
    
    subgraph "Metrics"
        Lambda[Lambda Metrics]
        ECS[ECS Metrics]
        API[API Gateway Metrics]
        Custom[Custom Metrics]
    end
    
    subgraph "Alarms"
        Error[Error Rate > 5%]
        Latency[Latency > 3s]
        Cost[Daily Cost > $100]
        DLQ[DLQ Messages > 0]
    end
    
    subgraph "Notifications"
        SNS[SNS Topic]
        Email[Email Alerts]
        Slack[Slack Webhook]
        PagerDuty[PagerDuty Integration]
    end
    
    Lambda --> Ops
    ECS --> Ops
    API --> Ops
    Custom --> Sec
    
    Ops --> Error
    Perf --> Latency
    Cost --> Cost
    Ops --> DLQ
    
    Error --> SNS
    Latency --> SNS
    Cost --> SNS
    DLQ --> SNS
    
    SNS --> Email
    SNS --> Slack
    SNS --> PagerDuty
```

### Key Metrics to Monitor

```mermaid
graph LR
    subgraph "Business Metrics"
        ScanRate[Scans/Hour]
        SuccessRate[Success %]
        FindingCount[Findings/Scan]
        MTTR[Time to Remediate]
    end
    
    subgraph "Technical Metrics"
        LambdaDuration[Lambda Duration]
        LambdaErrors[Lambda Errors]
        ECSUtil[ECS CPU/Memory]
        APILatency[API Latency]
    end
    
    subgraph "Cost Metrics"
        HourlyCost[Hourly Cost]
        CostPerScan[Cost/Scan]
        SpotSavings[Spot Savings]
        Forecast[Monthly Forecast]
    end
    
    subgraph "Security Metrics"
        Critical[Critical Findings]
        Remediated[Auto-Remediated]
        FalsePositive[False Positive Rate]
        Coverage[Repo Coverage]
    end
```

### CloudWatch Insights Queries

```sql
-- Top errors by Lambda function
fields @timestamp, @message
| filter @type = "REPORT"
| stats count(*) by functionName
| sort count desc

-- Average scan duration by repository
fields repository_url, duration
| filter @message like /Scan completed/
| stats avg(duration) by repository_url
| sort avg desc

-- Cost analysis by agent
fields agent_type, cost
| filter @message like /Agent execution cost/
| stats sum(cost) by agent_type
| sort sum desc

-- Failed scans root cause
fields @timestamp, error_message, repository_url
| filter status = "FAILED"
| stats count(*) by error_message
| sort count desc
```

## Performance Tuning

### Lambda Optimization

```mermaid
graph TD
    subgraph "Memory Optimization"
        Profile[Profile Functions]
        Analyze[Analyze Usage]
        Adjust[Adjust Memory]
        Test[Performance Test]
    end
    
    subgraph "Cold Start Reduction"
        Provisioned[Provisioned Concurrency]
        SnapStart[Lambda SnapStart]
        Layers[Optimize Layers]
        Size[Reduce Package Size]
    end
    
    subgraph "Concurrency Management"
        Reserved[Reserved Concurrency]
        Throttle[Throttling Limits]
        Queue[SQS Buffer]
        Backoff[Exponential Backoff]
    end
    
    Profile --> Analyze
    Analyze --> Adjust
    Adjust --> Test
    Test --> Profile
    
    Provisioned --> Reserved
    SnapStart --> Size
    Layers --> Size
```

### ECS Task Optimization

```yaml
# Optimized task definition
taskDefinition:
  family: security-agent
  cpu: 1024  # 1 vCPU
  memory: 2048  # 2 GB
  
  containerDefinitions:
    - name: agent
      image: security-agent:latest
      
      # Resource limits
      cpu: 896  # Leave headroom for sidecar
      memory: 1792
      memoryReservation: 1024
      
      # Health check
      healthCheck:
        command: ["CMD-SHELL", "health-check.sh"]
        interval: 30
        timeout: 5
        retries: 3
        
      # Logging
      logConfiguration:
        logDriver: awslogs
        options:
          awslogs-group: /ecs/security-agent
          awslogs-stream-prefix: agent
          awslogs-multiline-pattern: "^\\d{4}-\\d{2}-\\d{2}"
```

## Disaster Recovery

### Backup Strategy

```mermaid
graph TD
    subgraph "Data Sources"
        S3Data[S3 Scan Results]
        DDBData[DynamoDB Tables]
        EFSData[EFS Repositories]
        Secrets[Secrets Manager]
    end
    
    subgraph "Backup Methods"
        S3Rep[S3 Cross-Region Replication]
        DDBBackup[DynamoDB Backups]
        EFSBackup[AWS Backup]
        SecretRep[Secret Replication]
    end
    
    subgraph "Recovery Targets"
        RPO[RPO: 1 hour]
        RTO[RTO: 4 hours]
        Retention[Retention: 90 days]
    end
    
    S3Data --> S3Rep
    DDBData --> DDBBackup
    EFSData --> EFSBackup
    Secrets --> SecretRep
    
    S3Rep --> RPO
    DDBBackup --> RPO
    EFSBackup --> RPO
    SecretRep --> RPO
```

### Disaster Recovery Procedures

```mermaid
sequenceDiagram
    participant Ops as Operations Team
    participant AWS as AWS Services
    participant DR as DR Region
    participant Monitor as Monitoring
    
    Monitor->>Ops: Alert: Primary Region Down
    Ops->>AWS: Verify Region Status
    
    Ops->>Ops: Initiate DR Procedure
    
    Ops->>DR: Deploy DR Stack
    DR->>DR: Create Resources
    
    Ops->>AWS: Update Route53
    AWS->>DR: Route Traffic to DR
    
    Ops->>DR: Restore Data
    DR->>DR: Restore from Backups
    
    Ops->>Monitor: Verify DR Active
    Monitor->>Ops: DR Region Healthy
```

### Recovery Steps

1. **Detect Failure**
   ```bash
   # Check region health
   aws health describe-events --region us-east-1
   
   # Verify service status
   ./scripts/health-check.sh
   ```

2. **Activate DR Region**
   ```bash
   # Deploy to DR region
   export AWS_REGION=us-west-2
   cdk deploy --all --context env=dr
   ```

3. **Restore Data**
   ```bash
   # Restore DynamoDB
   aws dynamodb restore-table-from-backup \
     --target-table-name security-scans \
     --backup-arn $BACKUP_ARN
   
   # Verify S3 replication
   aws s3 sync s3://prod-results s3://dr-results --dryrun
   ```

4. **Update DNS**
   ```bash
   # Update Route53 records
   aws route53 change-resource-record-sets \
     --hosted-zone-id $ZONE_ID \
     --change-batch file://dr-dns-update.json
   ```

## Maintenance Procedures

### Regular Maintenance Tasks

```mermaid
gantt
    title Maintenance Schedule
    dateFormat  YYYY-MM-DD
    section Daily
    Log Rotation          :daily1, 2024-01-01, 1d
    Backup Verification   :daily2, after daily1, 1d
    Health Checks        :daily3, after daily2, 1d
    
    section Weekly
    Security Patches     :weekly1, 2024-01-07, 7d
    Cost Review         :weekly2, after weekly1, 2d
    Performance Review  :weekly3, after weekly2, 2d
    
    section Monthly
    Dependency Updates  :monthly1, 2024-01-30, 3d
    Security Audit      :monthly2, after monthly1, 2d
    Capacity Planning   :monthly3, after monthly2, 2d
    
    section Quarterly
    DR Testing         :quarterly1, 2024-03-30, 5d
    Architecture Review :quarterly2, after quarterly1, 3d
```

### Update Procedures

1. **Lambda Function Updates**
   ```bash
   # Update function code
   cd src/lambdas/ceo_agent
   zip -r function.zip .
   
   aws lambda update-function-code \
     --function-name SecurityAudit-CEO-Agent \
     --zip-file fileb://function.zip
   
   # Update function configuration
   aws lambda update-function-configuration \
     --function-name SecurityAudit-CEO-Agent \
     --memory-size 1024 \
     --timeout 300
   ```

2. **Container Updates**
   ```bash
   # Build and push new image
   docker build -t security-agent:latest .
   docker tag security-agent:latest $ECR_URI:latest
   docker push $ECR_URI:latest
   
   # Update ECS service
   aws ecs update-service \
     --cluster security-audit \
     --service sast-agent \
     --force-new-deployment
   ```

## Security Operations

### Security Monitoring

```mermaid
graph TD
    subgraph "Threat Detection"
        GuardDuty[AWS GuardDuty]
        SecurityHub[Security Hub]
        CloudTrail[CloudTrail Logs]
        WAF[WAF Logs]
    end
    
    subgraph "Analysis"
        SIEM[SIEM Integration]
        Athena[Athena Queries]
        Detective[Amazon Detective]
    end
    
    subgraph "Response"
        Auto[Automated Response]
        Manual[Manual Investigation]
        Remediation[Remediation Actions]
    end
    
    GuardDuty --> SIEM
    SecurityHub --> SIEM
    CloudTrail --> Athena
    WAF --> Athena
    
    SIEM --> Auto
    Athena --> Manual
    Detective --> Manual
    
    Auto --> Remediation
    Manual --> Remediation
```

### Incident Response Playbook

```mermaid
stateDiagram-v2
    [*] --> Detection
    Detection --> Triage
    
    Triage --> Low: Low Severity
    Triage --> Medium: Medium Severity
    Triage --> High: High Severity
    Triage --> Critical: Critical Severity
    
    Low --> Document
    Medium --> Investigate
    High --> Contain
    Critical --> IsolateImmediate
    
    Document --> [*]
    Investigate --> Remediate
    Contain --> Remediate
    IsolateImmediate --> Remediate
    
    Remediate --> Verify
    Verify --> Document
    Document --> [*]
```

## Cost Management

### Cost Optimization Workflow

```mermaid
graph LR
    subgraph "Monitor"
        Daily[Daily Spend]
        Forecast[Monthly Forecast]
        Anomaly[Anomaly Detection]
    end
    
    subgraph "Analyze"
        ByService[Cost by Service]
        ByAgent[Cost by Agent]
        ByRepo[Cost by Repository]
    end
    
    subgraph "Optimize"
        Spot[Increase Spot Usage]
        RightSize[Right-size Resources]
        Schedule[Schedule Scans]
        Cache[Improve Caching]
    end
    
    subgraph "Implement"
        Update[Update Configuration]
        Deploy[Deploy Changes]
        Measure[Measure Impact]
    end
    
    Daily --> ByService
    Forecast --> ByAgent
    Anomaly --> ByRepo
    
    ByService --> Spot
    ByAgent --> RightSize
    ByRepo --> Schedule
    
    Spot --> Update
    RightSize --> Update
    Schedule --> Update
    Cache --> Update
    
    Update --> Deploy
    Deploy --> Measure
    Measure --> Daily
```

### Cost Reduction Strategies

1. **Spot Instance Optimization**
   ```yaml
   # ECS capacity provider
   capacityProvider:
     name: spot-capacity
     targetCapacity: 80  # 80% spot
     minimumScalingStepSize: 1
     maximumScalingStepSize: 10
   ```

2. **S3 Lifecycle Optimization**
   ```json
   {
     "Rules": [{
       "Id": "ArchiveOldScans",
       "Status": "Enabled",
       "Transitions": [
         {
           "Days": 30,
           "StorageClass": "STANDARD_IA"
         },
         {
           "Days": 90,
           "StorageClass": "GLACIER"
         }
       ]
     }]
   }
   ```

## Troubleshooting Runbook

### Common Issues and Solutions

```mermaid
graph TD
    subgraph "Scan Failures"
        Timeout[Scan Timeout]
        Memory[Out of Memory]
        Access[Access Denied]
        Network[Network Error]
    end
    
    subgraph "Solutions"
        IncTimeout[Increase Timeout]
        IncMemory[Increase Memory]
        CheckIAM[Check IAM Roles]
        CheckVPC[Check VPC Config]
    end
    
    subgraph "Verification"
        Logs[Check CloudWatch Logs]
        Metrics[Review Metrics]
        Test[Run Test Scan]
    end
    
    Timeout --> IncTimeout
    Memory --> IncMemory
    Access --> CheckIAM
    Network --> CheckVPC
    
    IncTimeout --> Test
    IncMemory --> Test
    CheckIAM --> Test
    CheckVPC --> Test
    
    Test --> Logs
    Test --> Metrics
```

### Debug Commands

```bash
# Check Lambda logs
aws logs tail /aws/lambda/SecurityAudit-CEO-Agent --follow

# Check ECS task status
aws ecs describe-tasks \
  --cluster security-audit \
  --tasks $TASK_ARN

# Check Step Functions execution
aws stepfunctions describe-execution \
  --execution-arn $EXECUTION_ARN

# Check DynamoDB scan status
aws dynamodb get-item \
  --table-name security-scans \
  --key '{"scan_id": {"S": "scan-123"}}'

# Check S3 results
aws s3 ls s3://security-scan-results/scans/scan-123/ --recursive
```

## Scaling Guide

### Horizontal Scaling

```mermaid
graph TD
    subgraph "Current Load"
        Load[Measure Load]
        Bottleneck[Identify Bottleneck]
    end
    
    subgraph "Scaling Options"
        Lambda[Lambda Concurrency]
        ECS[ECS Tasks]
        DDB[DynamoDB Capacity]
        S3[S3 Request Rate]
    end
    
    subgraph "Implementation"
        AutoScale[Auto Scaling]
        Manual[Manual Scaling]
        Scheduled[Scheduled Scaling]
    end
    
    Load --> Bottleneck
    
    Bottleneck --> Lambda
    Bottleneck --> ECS
    Bottleneck --> DDB
    Bottleneck --> S3
    
    Lambda --> AutoScale
    ECS --> AutoScale
    DDB --> AutoScale
    S3 --> Manual
```

### Scaling Configuration

1. **Lambda Auto Scaling**
   ```json
   {
     "FunctionName": "SecurityAudit-CEO-Agent",
     "ProvisionedConcurrencyConfig": {
       "AllocatedConcurrentExecutions": 100
     },
     "ScalingConfig": {
       "MinimumConcurrency": 10,
       "MaximumConcurrency": 1000,
       "TargetValue": 0.7,
       "ScaleInCooldown": 60,
       "ScaleOutCooldown": 30
     }
   }
   ```

2. **ECS Service Auto Scaling**
   ```yaml
   autoScaling:
     minCapacity: 2
     maxCapacity: 50
     targetCPU: 70
     targetMemory: 80
     scaleInCooldown: 300
     scaleOutCooldown: 60
   ```

### Performance Benchmarks

| Component | Baseline | Optimized | Max Scale |
|-----------|----------|-----------|-----------|
| Scans/Hour | 100 | 500 | 2000 |
| Lambda Concurrent | 50 | 200 | 1000 |
| ECS Tasks | 10 | 50 | 200 |
| S3 Requests/Sec | 100 | 500 | 3500 |
| DynamoDB RCU | 100 | 500 | 40000 |
| DynamoDB WCU | 100 | 500 | 40000 |

## Conclusion

This operations guide provides comprehensive procedures for deploying, monitoring, maintaining, and scaling the Security Audit Framework. Follow these practices to ensure reliable, secure, and cost-effective operations.

Regular review and updates of these procedures ensure the system remains aligned with best practices and organizational requirements.