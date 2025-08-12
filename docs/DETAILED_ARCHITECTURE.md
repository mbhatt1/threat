# Security Audit Framework - Detailed Architecture Documentation

## Table of Contents
1. [System Overview](#system-overview)
2. [Core Architecture](#core-architecture)
3. [SNS Event Flow](#sns-event-flow)
4. [Security Agent Architecture](#security-agent-architecture)
5. [Data Flow & Storage](#data-flow--storage)
6. [HASHIRU Intelligence System](#hashiru-intelligence-system)
7. [Strands Communication Protocol](#strands-communication-protocol)
8. [Cost Optimization](#cost-optimization)
9. [Security & Compliance](#security--compliance)
10. [Monitoring & Observability](#monitoring--observability)

## System Overview

The Security Audit Framework is a comprehensive, event-driven security scanning system built on AWS. It employs a multi-agent architecture with intelligent orchestration, cost optimization, and extensive integration capabilities.

### High-Level Architecture

```mermaid
graph TB
    subgraph "Event Sources"
        GH[GitHub Webhooks]
        CC[CodeCommit]
        SH[Security Hub]
        EB[EventBridge]
        API[API Gateway]
        Manual[Manual Triggers]
    end
    
    subgraph "SNS Topics"
        MainTopic[Main Scan Topic]
        GHTopic[GitHub Topic]
        CCTopic[CodeCommit Topic]
        SHTopic[Security Hub Topic]
        ScheduledTopic[Scheduled Topic]
    end
    
    subgraph "Processing Layer"
        SNSHandler[SNS Handler Lambda]
        StepFunc[Step Functions]
        CEO[CEO Agent Lambda]
    end
    
    subgraph "Security Agents"
        SAST[SAST Agent]
        Deps[Dependency Agent]
        Secrets[Secrets Agent]
        IaC[IaC Agent]
        APISec[API Security Agent]
        Container[Container Agent]
        BizLogic[Business Logic Agent]
        Auto[Autonomous Agent]
    end
    
    subgraph "Analytics & Reporting"
        Agg[Aggregator Lambda]
        Report[Report Generator]
        QS[QuickSight]
        Athena[Athena]
    end
    
    subgraph "Storage"
        S3[S3 Results]
        DDB[DynamoDB]
        EFS[EFS Repository]
    end
    
    GH --> GHTopic
    CC --> CCTopic
    SH --> SHTopic
    EB --> ScheduledTopic
    Manual --> MainTopic
    API --> StepFunc
    
    GHTopic --> MainTopic
    CCTopic --> MainTopic
    SHTopic --> MainTopic
    ScheduledTopic --> MainTopic
    
    MainTopic --> SNSHandler
    SNSHandler --> StepFunc
    StepFunc --> CEO
    
    CEO --> SAST
    CEO --> Deps
    CEO --> Secrets
    CEO --> IaC
    CEO --> APISec
    CEO --> Container
    CEO --> BizLogic
    CEO --> Auto
    
    SAST --> S3
    Deps --> S3
    Secrets --> S3
    IaC --> S3
    APISec --> S3
    Container --> S3
    BizLogic --> S3
    Auto --> S3
    
    S3 --> Agg
    Agg --> Report
    Report --> QS
    S3 --> Athena
    
    SNSHandler --> DDB
    CEO --> DDB
    Agg --> DDB
    
    CEO --> EFS
    SAST --> EFS
    Deps --> EFS
    Secrets --> EFS
```

## Core Architecture

### Component Breakdown

```mermaid
graph LR
    subgraph "Infrastructure Layer"
        VPC[VPC with Subnets]
        SG[Security Groups]
        IAM[IAM Roles]
        KMS[KMS Keys]
    end
    
    subgraph "Compute Layer"
        Lambda[Lambda Functions]
        ECS[ECS Fargate]
        StepFunctions[Step Functions]
    end
    
    subgraph "Storage Layer"
        S3Storage[S3 Buckets]
        DynamoDB[DynamoDB Tables]
        EFSStorage[EFS File System]
        SecretsManager[Secrets Manager]
    end
    
    subgraph "Integration Layer"
        SNS[SNS Topics]
        SQS[SQS Queues]
        EventBridge[EventBridge]
        APIGateway[API Gateway]
    end
    
    subgraph "Analytics Layer"
        Athena[Athena]
        QuickSight[QuickSight]
        CloudWatch[CloudWatch]
        SecurityHub[Security Hub]
    end
    
    VPC --> Lambda
    VPC --> ECS
    IAM --> Lambda
    IAM --> ECS
    
    Lambda --> S3Storage
    Lambda --> DynamoDB
    ECS --> EFSStorage
    ECS --> S3Storage
    
    SNS --> Lambda
    EventBridge --> SNS
    APIGateway --> StepFunctions
    
    S3Storage --> Athena
    Athena --> QuickSight
    Lambda --> CloudWatch
    S3Storage --> SecurityHub
```

## SNS Event Flow

### Detailed SNS Message Processing

```mermaid
sequenceDiagram
    participant Source as Event Source
    participant SNS as SNS Topic
    participant Filter as SNS Filter
    participant Handler as SNS Handler Lambda
    participant DDB as DynamoDB
    participant SF as Step Functions
    participant CEO as CEO Agent
    
    Source->>SNS: Publish Message
    SNS->>Filter: Apply Message Filters
    Filter->>Handler: Deliver if scan_enabled=true
    Handler->>Handler: Parse Message Type
    Handler->>Handler: Extract Scan Options
    Handler->>DDB: Create Scan Record
    Handler->>SF: Start Execution
    SF->>CEO: Invoke CEO Agent
    CEO->>DDB: Update Scan Status
    
    Note over Handler: Supports Multiple Message Types
    Note over Handler: 1. GitHub Webhooks
    Note over Handler: 2. CodeCommit Events
    Note over Handler: 3. Security Hub Findings
    Note over Handler: 4. Scheduled Scans
    Note over Handler: 5. Manual Requests
    Note over Handler: 6. Custom Integrations
```

### SNS Topic Hierarchy

```mermaid
graph TD
    subgraph "Topic Structure"
        Main[security-scan-requests<br/>Main Processing Topic]
        
        GitHub[github-webhooks<br/>GitHub Events]
        CodeCommit[codecommit-events<br/>CodeCommit Triggers]
        SecHub[security-hub-findings<br/>Security Hub Alerts]
        Scheduled[scheduled-scans<br/>Periodic Scans]
        
        DLQ[security-scan-requests-dlq<br/>Dead Letter Queue]
    end
    
    subgraph "Message Flow"
        GitHub --> Main
        CodeCommit --> Main
        SecHub --> Main
        Scheduled --> Main
        Main --> DLQ
    end
    
    subgraph "Filters"
        GitHubFilter[event_type: push/pull_request]
        SecHubFilter[severity: CRITICAL/HIGH]
        MainFilter[scan_enabled: true]
    end
    
    GitHub -.-> GitHubFilter
    SecHub -.-> SecHubFilter
    Main -.-> MainFilter
```

## Security Agent Architecture

### Agent Execution Flow

```mermaid
stateDiagram-v2
    [*] --> CEO_Analysis
    CEO_Analysis --> HASHIRU_Planning
    HASHIRU_Planning --> Agent_Selection
    
    Agent_Selection --> Parallel_Execution
    
    state Parallel_Execution {
        [*] --> SAST
        [*] --> Dependency
        [*] --> Secrets
        [*] --> IaC
        [*] --> API_Security
        [*] --> Container
        [*] --> Business_Logic
        [*] --> Autonomous
        
        SAST --> Upload_Results
        Dependency --> Upload_Results
        Secrets --> Upload_Results
        IaC --> Upload_Results
        API_Security --> Upload_Results
        Container --> Upload_Results
        Business_Logic --> Upload_Results
        Autonomous --> Upload_Results
    }
    
    Parallel_Execution --> Aggregation
    Aggregation --> Conditional_Triggers
    
    state Conditional_Triggers {
        [*] --> Check_Findings
        Check_Findings --> Trigger_Additional: High Risk Found
        Check_Findings --> Skip: Low Risk
        Trigger_Additional --> Deep_Scan
        Deep_Scan --> [*]
        Skip --> [*]
    }
    
    Conditional_Triggers --> Report_Generation
    Report_Generation --> Attack_Path_Analysis
    Attack_Path_Analysis --> Learning_Engine
    Learning_Engine --> [*]
```

### Individual Agent Architecture

```mermaid
graph TB
    subgraph "SAST Agent (Semgrep)"
        S1[Pull Repository]
        S2[Load Rule Sets]
        S3[Run Semgrep Scan]
        S4[Parse Results]
        S5[Apply Severity Mapping]
        S6[Generate Findings]
    end
    
    subgraph "Dependency Agent (OWASP)"
        D1[Analyze Package Files]
        D2[Check CVE Database]
        D3[Identify Vulnerabilities]
        D4[Calculate Risk Score]
        D5[Generate Findings]
    end
    
    subgraph "Secrets Agent (TruffleHog)"
        SE1[Scan Repository]
        SE2[Pattern Matching]
        SE3[Entropy Analysis]
        SE4[Verify Live Secrets]
        SE5[Trigger Remediation]
    end
    
    subgraph "Container Agent"
        C1[Parse Dockerfiles]
        C2[Analyze K8s Manifests]
        C3[Check Security Policies]
        C4[Trivy Integration]
        C5[Generate Findings]
    end
    
    S1 --> S2 --> S3 --> S4 --> S5 --> S6
    D1 --> D2 --> D3 --> D4 --> D5
    SE1 --> SE2 --> SE3 --> SE4 --> SE5
    C1 --> C2 --> C3 --> C4 --> C5
```

## Data Flow & Storage

### Data Pipeline

```mermaid
graph LR
    subgraph "Input Data"
        Repo[Git Repository]
        Meta[Scan Metadata]
        Config[Scan Configuration]
    end
    
    subgraph "Processing"
        EFS[EFS Mount]
        Agent[Security Agent]
        Transform[Data Transform]
    end
    
    subgraph "Storage Layers"
        S3Raw[S3 Raw Results]
        S3Processed[S3 Processed]
        S3Archive[S3 Archive]
        DDBMeta[DynamoDB Metadata]
        DDBStatus[DynamoDB Status]
    end
    
    subgraph "Analytics"
        Athena[Athena Queries]
        QuickSight[QuickSight Dashboards]
        Learning[Learning Engine]
    end
    
    Repo --> EFS
    Meta --> DDBMeta
    Config --> Agent
    
    EFS --> Agent
    Agent --> Transform
    Transform --> S3Raw
    Transform --> DDBStatus
    
    S3Raw --> S3Processed
    S3Processed --> S3Archive
    
    S3Processed --> Athena
    Athena --> QuickSight
    S3Processed --> Learning
    
    Learning --> DDBMeta
```

### Storage Lifecycle

```mermaid
graph TD
    subgraph "S3 Lifecycle Management"
        Fresh[Fresh Results<br/>Standard Storage<br/>0-7 days]
        Recent[Recent Results<br/>Standard-IA<br/>8-30 days]
        Historical[Historical Data<br/>Glacier Flexible<br/>31-90 days]
        Archive[Long-term Archive<br/>Glacier Deep Archive<br/>91+ days]
        Delete[Deletion<br/>After 365 days]
    end
    
    Fresh --> Recent
    Recent --> Historical
    Historical --> Archive
    Archive --> Delete
    
    Fresh -.-> QuickAccess[Immediate Access]
    Recent -.-> MinuteAccess[1-5 Minute Access]
    Historical -.-> HourAccess[1-12 Hour Access]
    Archive -.-> DayAccess[12-48 Hour Access]
```

## HASHIRU Intelligence System

### Decision Flow

```mermaid
graph TD
    subgraph "HASHIRU Core"
        Analyze[Repository Analysis]
        Profile[Build Repository Profile]
        Cost[Cost Estimation]
        Plan[Execution Planning]
        Optimize[Optimization Engine]
    end
    
    subgraph "Analysis Factors"
        Lang[Language Detection]
        Size[Repository Size]
        Complex[Complexity Score]
        History[Historical Data]
        Risk[Risk Assessment]
    end
    
    subgraph "Cost Factors"
        Compute[Compute Costs]
        Storage[Storage Costs]
        Network[Network Costs]
        Time[Time Estimates]
    end
    
    subgraph "Optimization"
        Spot[Spot Instance Usage]
        Parallel[Parallelization]
        Cache[Result Caching]
        Skip[Skip Redundant]
    end
    
    Analyze --> Lang
    Analyze --> Size
    Analyze --> Complex
    Analyze --> History
    Analyze --> Risk
    
    Profile --> Cost
    
    Cost --> Compute
    Cost --> Storage
    Cost --> Network
    Cost --> Time
    
    Plan --> Optimize
    
    Optimize --> Spot
    Optimize --> Parallel
    Optimize --> Cache
    Optimize --> Skip
```

### Cost Optimization Engine

```mermaid
sequenceDiagram
    participant CEO as CEO Agent
    participant HASHIRU as HASHIRU
    participant CostAPI as Cost Explorer API
    participant Pricing as Pricing API
    participant Plan as Execution Planner
    
    CEO->>HASHIRU: Analyze Repository
    HASHIRU->>CostAPI: Get Historical Costs
    HASHIRU->>Pricing: Get Current Pricing
    
    HASHIRU->>HASHIRU: Calculate Base Cost
    HASHIRU->>HASHIRU: Apply Optimizations
    
    Note over HASHIRU: Optimization Strategies:
    Note over HASHIRU: 1. Use Spot Instances (70% savings)
    Note over HASHIRU: 2. Parallel Execution
    Note over HASHIRU: 3. Agent Selection
    Note over HASHIRU: 4. Resource Right-sizing
    
    HASHIRU->>Plan: Generate Optimized Plan
    Plan->>CEO: Return Execution Plan
    
    CEO->>CEO: Execute with Cost Limits
```

## Strands Communication Protocol

### Message Flow

```mermaid
sequenceDiagram
    participant Agent as Security Agent
    participant S3 as S3 Storage
    participant SQS as SQS Queue
    participant Agg as Aggregator
    participant DDB as DynamoDB
    
    Agent->>Agent: Generate Findings
    Agent->>Agent: Create Strands Message
    
    Note over Agent: Strands Message Structure:
    Note over Agent: - Header (metadata)
    Note over Agent: - Payload (findings)
    Note over Agent: - Context (scan info)
    
    Agent->>S3: Upload Full Results
    Agent->>SQS: Send Completion Signal
    
    SQS->>Agg: Trigger Aggregation
    Agg->>S3: Fetch Results
    Agg->>Agg: Merge Findings
    Agg->>DDB: Update Status
```

### Protocol Schema

```mermaid
classDiagram
    class StrandsMessage {
        +String version
        +Header header
        +Payload payload
        +Context context
        +validate()
        +serialize()
    }
    
    class Header {
        +String message_id
        +String scan_id
        +String agent_id
        +DateTime timestamp
        +String correlation_id
    }
    
    class Payload {
        +List~Finding~ findings
        +Summary summary
        +Metrics metrics
    }
    
    class Context {
        +String repository_url
        +String branch
        +Map~String,String~ metadata
        +CostInfo cost_info
    }
    
    class Finding {
        +String id
        +String type
        +Severity severity
        +Location location
        +String description
        +Remediation remediation
    }
    
    StrandsMessage --> Header
    StrandsMessage --> Payload
    StrandsMessage --> Context
    Payload --> Finding
```

## Cost Optimization

### Cost Breakdown

```mermaid
pie title "Typical Scan Cost Distribution"
    "Lambda Execution" : 15
    "ECS Fargate" : 40
    "S3 Storage" : 10
    "Data Transfer" : 5
    "DynamoDB" : 5
    "CloudWatch Logs" : 10
    "Other Services" : 15
```

### Optimization Strategies

```mermaid
graph TD
    subgraph "Cost Optimization Techniques"
        A[Spot Instances<br/>70% cost reduction]
        B[Intelligent Caching<br/>50% reduction in re-scans]
        C[Agent Selection<br/>Only run needed agents]
        D[Parallel Execution<br/>Reduce total time]
        E[Resource Right-sizing<br/>Optimize memory/CPU]
        F[S3 Lifecycle Policies<br/>Archive old results]
        G[Reserved Capacity<br/>For predictable workloads]
    end
    
    subgraph "Implementation"
        A --> SpotFleet[ECS Spot Fleet]
        B --> S3Cache[S3 Result Cache]
        C --> HASHIRU[HASHIRU Planning]
        D --> StepFunc[Step Functions Map]
        E --> Monitoring[CloudWatch Metrics]
        F --> Lifecycle[S3 Lifecycle Rules]
        G --> Savings[Savings Plans]
    end
```

## Security & Compliance

### Security Architecture

```mermaid
graph TB
    subgraph "Network Security"
        VPC[Private VPC]
        PrivateSubnet[Private Subnets]
        NACL[Network ACLs]
        SG[Security Groups]
        Endpoints[VPC Endpoints]
    end
    
    subgraph "Identity & Access"
        IAM[IAM Roles]
        STS[STS Assume Role]
        MFA[MFA Required]
        Policies[Least Privilege]
    end
    
    subgraph "Data Protection"
        Encryption[Encryption at Rest]
        TLS[TLS in Transit]
        KMS[KMS Keys]
        Secrets[Secrets Manager]
    end
    
    subgraph "Compliance"
        CloudTrail[Audit Logging]
        Config[AWS Config]
        GuardDuty[Threat Detection]
        SecurityHub[Compliance Checks]
    end
    
    VPC --> PrivateSubnet
    PrivateSubnet --> NACL
    PrivateSubnet --> SG
    VPC --> Endpoints
    
    IAM --> STS
    IAM --> MFA
    IAM --> Policies
    
    Encryption --> KMS
    TLS --> Endpoints
    Secrets --> KMS
    
    CloudTrail --> S3
    Config --> Compliance
    GuardDuty --> SecurityHub
```

### Data Encryption Flow

```mermaid
sequenceDiagram
    participant Client
    participant API as API Gateway
    participant Lambda
    participant KMS
    participant S3
    participant DDB as DynamoDB
    
    Client->>API: HTTPS Request
    Note over Client,API: TLS 1.2+ Encryption
    
    API->>Lambda: Invoke with payload
    Lambda->>KMS: Get Data Key
    KMS->>Lambda: Encrypted Data Key
    
    Lambda->>S3: Store Encrypted Results
    Note over Lambda,S3: SSE-S3 or SSE-KMS
    
    Lambda->>DDB: Store Metadata
    Note over Lambda,DDB: Encryption at Rest
    
    S3->>Lambda: Retrieve Encrypted Data
    Lambda->>KMS: Decrypt Data Key
    KMS->>Lambda: Decrypted Data Key
    Lambda->>API: Return Results
    API->>Client: HTTPS Response
```

## Monitoring & Observability

### Monitoring Architecture

```mermaid
graph LR
    subgraph "Metrics Collection"
        CW[CloudWatch Metrics]
        XRay[X-Ray Traces]
        Logs[CloudWatch Logs]
        Events[EventBridge Events]
    end
    
    subgraph "Dashboards"
        OpsDash[Operations Dashboard]
        CostDash[Cost Dashboard]
        SecDash[Security Dashboard]
        PerfDash[Performance Dashboard]
    end
    
    subgraph "Alerting"
        SNS[SNS Topics]
        Email[Email Alerts]
        Slack[Slack Integration]
        PagerDuty[PagerDuty]
    end
    
    subgraph "Analysis"
        Insights[CloudWatch Insights]
        Athena[Athena Queries]
        QuickSight[QuickSight Reports]
    end
    
    CW --> OpsDash
    CW --> CostDash
    XRay --> PerfDash
    Events --> SecDash
    
    OpsDash --> SNS
    CostDash --> SNS
    SecDash --> SNS
    PerfDash --> SNS
    
    SNS --> Email
    SNS --> Slack
    SNS --> PagerDuty
    
    Logs --> Insights
    CW --> Athena
    Athena --> QuickSight
```

### Key Metrics

```mermaid
graph TD
    subgraph "Operational Metrics"
        ScanRate[Scans per Hour]
        SuccessRate[Success Rate %]
        AvgDuration[Avg Scan Duration]
        QueueDepth[Queue Depth]
    end
    
    subgraph "Cost Metrics"
        CostPerScan[Cost per Scan]
        DailyCost[Daily Cost]
        CostByAgent[Cost by Agent]
        SpotSavings[Spot Savings %]
    end
    
    subgraph "Security Metrics"
        CriticalFindings[Critical Findings]
        MTTR[Mean Time to Remediate]
        Coverage[Repository Coverage %]
        FalsePositives[False Positive Rate]
    end
    
    subgraph "Performance Metrics"
        LambdaDuration[Lambda Duration]
        ECSUtilization[ECS CPU/Memory]
        S3Performance[S3 GET/PUT Latency]
        APILatency[API Response Time]
    end
```

## Deployment Architecture

### Multi-Region Deployment

```mermaid
graph TB
    subgraph "Primary Region (us-east-1)"
        PrimaryAPI[API Gateway]
        PrimarySNS[SNS Topics]
        PrimaryCompute[Lambda/ECS]
        PrimaryStorage[S3/DynamoDB]
    end
    
    subgraph "Secondary Region (us-west-2)"
        SecondaryAPI[API Gateway]
        SecondarySNS[SNS Topics]
        SecondaryCompute[Lambda/ECS]
        SecondaryStorage[S3/DynamoDB]
    end
    
    subgraph "Global Services"
        Route53[Route 53]
        CloudFront[CloudFront]
        IAM[IAM]
    end
    
    subgraph "Cross-Region"
        Replication[S3 Replication]
        DDBGlobal[DynamoDB Global Tables]
        BackupVault[AWS Backup]
    end
    
    Route53 --> PrimaryAPI
    Route53 --> SecondaryAPI
    CloudFront --> PrimaryStorage
    CloudFront --> SecondaryStorage
    
    PrimaryStorage <--> Replication
    Replication <--> SecondaryStorage
    
    PrimaryStorage <--> DDBGlobal
    DDBGlobal <--> SecondaryStorage
```

## Troubleshooting Guide

### Common Issues Flow

```mermaid
graph TD
    Start[Scan Failed] --> CheckType{Failure Type?}
    
    CheckType -->|Timeout| TimeoutCheck[Check Execution Time]
    CheckType -->|Permission| PermCheck[Check IAM Roles]
    CheckType -->|Resource| ResourceCheck[Check Resource Limits]
    CheckType -->|Network| NetworkCheck[Check VPC/SG]
    
    TimeoutCheck --> IncreaseTimeout[Increase Lambda Timeout]
    TimeoutCheck --> OptimizeCode[Optimize Agent Code]
    
    PermCheck --> ReviewPolicies[Review IAM Policies]
    PermCheck --> CheckAssumeRole[Check Role Trust]
    
    ResourceCheck --> CheckLimits[Check Service Quotas]
    ResourceCheck --> ScaleResources[Scale ECS/Lambda]
    
    NetworkCheck --> CheckEndpoints[Check VPC Endpoints]
    NetworkCheck --> CheckRouting[Check Route Tables]
    
    IncreaseTimeout --> Resolved[Issue Resolved]
    OptimizeCode --> Resolved
    ReviewPolicies --> Resolved
    CheckAssumeRole --> Resolved
    CheckLimits --> Resolved
    ScaleResources --> Resolved
    CheckEndpoints --> Resolved
    CheckRouting --> Resolved
```

## Conclusion

This Security Audit Framework provides a comprehensive, scalable, and cost-effective solution for automated security scanning of Git repositories. The event-driven architecture with SNS at its core enables flexible integration with various CI/CD pipelines and security tools while maintaining high performance and reliability.

Key architectural decisions:
- **Event-driven design** for scalability and decoupling
- **Multi-agent architecture** for specialized security scanning
- **Cost optimization** through intelligent resource management
- **Security-first approach** with defense in depth
- **Observable system** with comprehensive monitoring

The framework is designed to grow with your security needs while maintaining operational excellence.