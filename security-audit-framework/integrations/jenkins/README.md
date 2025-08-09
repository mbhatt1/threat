# AI Security Scanner Jenkins Plugin

Jenkins plugin for integrating AI-powered security scanning into your CI/CD pipeline.

## Features

- 🤖 **AI-Powered Analysis**: Leverages AWS Bedrock Claude 3 for intelligent security scanning
- 📊 **Business Risk Scoring**: Prioritizes findings based on asset criticality
- 🔍 **Comprehensive Coverage**: SAST, dependency, secrets, IaC, and container scanning
- 📈 **Trend Analysis**: Track security posture over time
- 🎯 **Smart Remediation**: AI-generated fixes with explainability
- 📝 **Multiple Report Formats**: HTML, JSON, SARIF, JUnit

## Installation

### Option 1: Install from Jenkins Update Center
1. Navigate to **Manage Jenkins** → **Manage Plugins**
2. Search for "AI Security Scanner"
3. Install and restart Jenkins

### Option 2: Manual Installation
1. Download the latest `.hpi` file from releases
2. Navigate to **Manage Jenkins** → **Manage Plugins** → **Advanced**
3. Upload the `.hpi` file
4. Restart Jenkins

## Configuration

### Global Configuration
1. Go to **Manage Jenkins** → **Configure System**
2. Find the **AI Security Scanner** section
3. Configure:
   - AWS Region
   - CEO Lambda ARN or API Endpoint
   - S3 Results Bucket
   - DynamoDB Table Names

### Job Configuration

#### Freestyle Project
1. Add build step: **AI Security Scan**
2. Configure:
   - Repository URL (leave blank for workspace)
   - Branch to scan
   - Business criticality (low/normal/high/critical)
   - Failure thresholds

#### Pipeline (Declarative)
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                aiSecurityScan(
                    repository: env.GIT_URL,
                    branch: env.BRANCH_NAME,
                    businessCriticality: 'high',
                    failOnCritical: true,
                    failOnHighThreshold: 5
                )
            }
        }
    }
    
    post {
        always {
            publishHTML([
                reportDir: 'security-reports',
                reportFiles: 'security-scan-report.html',
                reportName: 'AI Security Report'
            ])
        }
    }
}
```

#### Pipeline (Scripted)
```groovy
node {
    stage('Security Scan') {
        def scanResult = aiSecurityScan(
            repository: env.GIT_URL,
            branch: env.BRANCH_NAME,
            businessCriticality: 'critical',
            incremental: true
        )
        
        if (scanResult.criticalFindings > 0) {
            error "Critical security findings detected!"
        }
    }
}
```

## Advanced Usage

### Custom Policies
```groovy
aiSecurityScan(
    customPolicies: [
        'No hardcoded API keys in configuration files',
        'All database connections must use SSL',
        'Ensure PII is encrypted at rest'
    ]
)
```

### Supply Chain Analysis
```groovy
aiSecurityScan(
    checkDependencies: true,
    transitiveDepth: 3,
    blockMaliciousPackages: true
)
```

### Incremental Scanning
```groovy
aiSecurityScan(
    incremental: true,
    baseBranch: 'main',
    costOptimization: 'aggressive'
)
```

## Output Variables

The plugin sets the following environment variables:
- `AI_SCAN_ID`: Unique scan identifier
- `AI_SCAN_STATUS`: Success/failure status
- `AI_CRITICAL_COUNT`: Number of critical findings
- `AI_HIGH_COUNT`: Number of high findings
- `AI_RISK_SCORE`: Business risk score (0-100)
- `AI_CONFIDENCE`: AI confidence score (0-100)

## Report Formats

### HTML Report
Beautiful, interactive report with:
- Executive summary
- Finding details with AI explanations
- Remediation recommendations
- Trend charts

### SARIF Report
For integration with:
- GitHub Security tab
- VS Code SARIF viewer
- Other SARIF-compatible tools

### JUnit Report
For test result tracking:
- One test per security check
- Failures for findings above threshold
- Timing information

## Troubleshooting

### AWS Credentials
Ensure Jenkins has AWS credentials configured:
- IAM role (recommended for EC2)
- AWS credentials in Jenkins credentials store
- Environment variables

### Lambda Timeouts
For large repositories, increase timeout:
```groovy
aiSecurityScan(
    timeout: 15, // minutes
    asyncMode: true
)
```

### Memory Issues
For very large scans:
```groovy
aiSecurityScan(
    chunkSize: 100, // files per chunk
    parallelAgents: 3
)
```

## Support

- 📧 Email: security-framework@example.com
- 🐛 Issues: GitHub Issues
- 💬 Slack: #ai-security-scanner