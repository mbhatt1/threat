# Security Audit Framework

A comprehensive AI-powered security audit framework for AWS environments that leverages autonomous agents, machine learning, and advanced threat intelligence to provide continuous security monitoring and assessment.

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- AWS CLI configured with appropriate credentials
- Docker and Docker Compose (for local development)
- Node.js 18+ (for CDK deployment)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/example/security-audit-framework.git
cd security-audit-framework
```

2. Install dependencies:
```bash
make install-dev
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Run tests to verify installation:
```bash
make test
```

### Local Development

Start the entire stack locally using Docker Compose:

```bash
make docker-run
```

This will start:
- LocalStack for AWS service emulation
- PostgreSQL database
- Redis cache
- API service
- All security agents
- Prometheus & Grafana for monitoring

Access the services:
- API: http://localhost:8000
- Grafana: http://localhost:3001 (admin/admin)
- Prometheus: http://localhost:9090

### AWS Deployment

1. Bootstrap CDK (first time only):
```bash
make cdk-bootstrap
```

2. Deploy to AWS:
```bash
make deploy
```

Or deploy to specific environment:
```bash
make deploy-dev  # Development environment
make deploy-prod # Production environment
```

## 📋 Features

### Autonomous Security Agents

- **SAST Agent**: Static Application Security Testing with AI-enhanced pattern recognition
- **Container Scanner**: Vulnerability scanning for Docker containers and registries
- **Threat Intelligence**: Real-time threat analysis using AWS Bedrock AI
- **Supply Chain Security**: Dependency and license compliance checking
- **Infrastructure Security**: AWS resource configuration and compliance scanning
- **Red Team Agent**: Adversarial security testing of the framework itself

### AI/ML Capabilities

- **AWS Bedrock Integration**: Claude 3 models for advanced security analysis
- **Pattern Recognition**: ML-based anomaly detection and threat prediction
- **Automated Remediation**: AI-suggested fixes and security improvements
- **Business Context Analysis**: Risk assessment aligned with business priorities

### Communication Protocol

The framework uses the **Strands Protocol** for inter-agent communication:
- Asynchronous message passing
- Task orchestration
- Result aggregation
- Cost optimization

### Reporting & Visualization

- Executive dashboards via AWS QuickSight
- Detailed security findings in multiple formats (JSON, PDF, HTML)
- Real-time alerts and notifications
- Compliance reporting (SOC2, PCI-DSS, HIPAA)

### Secure Archive Module

The framework includes a comprehensive secure archive module for backing up and protecting sensitive data with enterprise-grade encryption.

#### **Features**
- **Compression**: Automatic tar.gz compression with smart exclusions
- **Encryption Options**:
  - Password-based: AES-256-GCM with PBKDF2 key derivation
  - KMS-based: AWS KMS managed keys with envelope encryption
- **Cloud Storage**: Direct S3 integration with server-side encryption
- **Security Analysis**: On-the-fly content analysis for sensitive files
- **Stream Processing**: Analyze archives directly from S3 without full download

#### **Password-Based Encryption**

Quick backup with password encryption:
```bash
# Archive, encrypt, and upload in one command
saf-cli quick-backup ./my-project --password

# Individual operations
saf-cli archive archive ./my-project
saf-cli archive encrypt project.tar.gz --password
saf-cli archive upload project.tar.gz.enc --s3-key backups/project.enc
saf-cli archive decrypt project.tar.gz.enc --password
```

#### **KMS-Based Encryption (Recommended)**

Enterprise-grade encryption using AWS KMS:
```bash
# Set KMS key (or use --kms-key option)
export KMS_KEY_ID=alias/secure-archive-key

# Complete KMS backup
saf-cli quick-backup-kms ./my-project --s3-prefix projects/2024

# Or use the full CLI
saf-cli archive-kms backup ./my-project

# Individual KMS operations
saf-cli archive-kms encrypt archive.tar.gz
saf-cli archive-kms decrypt archive.kms.enc
saf-cli archive-kms analyze archive.kms.enc --encrypted
```

#### **Key Rotation**
```bash
# Rotate to a new KMS key
saf-cli archive-kms rotate-key old-archive.enc alias/new-key
```

#### **Security Analysis**

Analyze archive contents without extraction:
```bash
# Analyze local archive
saf-cli archive analyze project.tar.gz

# Analyze encrypted archive
saf-cli archive analyze project.enc --encrypted --password

# Stream analyze from S3 (KMS)
saf-cli archive-kms stream-analyze backups/project.kms.enc
```

Output includes:
- File type distribution
- Largest files
- Security concerns (sensitive files like .env, .key, .pem)
- Path traversal risks

#### **KMS Configuration**

1. **Create KMS Key Policy**:
```bash
saf-cli archive-kms generate-policy \
  --admin-role arn:aws:iam::123456789012:role/Admin \
  --user-role arn:aws:iam::123456789012:role/Developer \
  --output kms-policy.json
```

2. **Required IAM Permissions**:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "kms:DescribeKey"
    ],
    "Resource": "arn:aws:kms:*:*:key/*"
  }]
}
```

3. **Environment Variables**:
```bash
export KMS_KEY_ID=alias/secure-archive-key
export ARCHIVE_S3_BUCKET=my-secure-backups
export AWS_REGION=us-east-1
```

#### **Technical Implementation**

**Encryption Process (KMS)**:
1. Generate data encryption key (DEK) from KMS
2. Encrypt archive with plaintext DEK using AES-256-GCM
3. Store encrypted DEK with the encrypted data
4. Clear plaintext DEK from memory

**File Format**:
```
[4 bytes: metadata length]
[JSON metadata: encrypted_dek, nonce, tag, checksum, kms_key_id]
[Encrypted archive data]
```

**Security Features**:
- **Envelope Encryption**: Data key encrypted by KMS master key
- **Integrity Verification**: SHA-256 checksums
- **Audit Trail**: All KMS operations logged in CloudTrail
- **Access Control**: IAM policies control encryption/decryption
- **Sensitive File Detection**: Automatic scanning for credentials
- **Path Traversal Protection**: Prevents directory escape attacks

#### **Python API Usage**

```python
from src.shared.secure_archive_kms import SecureArchiveKMS

# Initialize with KMS
sa = SecureArchiveKMS(
    kms_key_id="alias/secure-archive-key",
    s3_bucket="my-secure-backups"
)

# Complete backup workflow
result = sa.secure_backup_directory_kms(
    "/sensitive/project",
    s3_key_prefix="projects/2024"
)

print(f"S3 URI: {result['s3_uri']}")
print(f"Encrypted with: {result['kms_key_arn']}")
print(f"Security concerns: {result['analysis']['security_concerns']}")
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        API Gateway                          │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                    Lambda Functions                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   CEO    │  │Aggregator│  │ Reporter │  │  Athena  │  │
│  │  Agent   │  │          │  │Generator │  │  Setup   │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────┬───────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                 Autonomous Security Agents                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   SAST   │  │Container │  │  Threat  │  │  Supply  │  │
│  │  Agent   │  │ Scanner  │  │  Intel   │  │  Chain   │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────────┐
│                      Data Storage                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │    S3    │  │ DynamoDB │  │  Athena  │  │QuickSight│  │
│  │ Buckets  │  │  Tables  │  │          │  │          │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
security-audit-framework/
├── src/
│   ├── agents/              # Autonomous security agents
│   ├── lambdas/            # AWS Lambda functions
│   ├── shared/             # Shared libraries and protocols
│   ├── api/                # FastAPI application
│   ├── cli/                # Command-line interface
│   └── ai_models/          # AI/ML models and utilities
├── cdk/                    # AWS CDK infrastructure code
├── tests/                  # Unit and integration tests
├── scripts/                # Deployment and utility scripts
├── config/                 # Configuration files
├── docs/                   # Documentation
└── mcp/                    # Model Context Protocol SDK
```

## 🛠️ Development

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific test suite
make test-unit
make test-integration
```

### Code Quality

```bash
# Run linting
make lint

# Format code
make format

# Type checking
make type-check
```

### Building Components

```bash
# Build all components
make build

# Build specific agent
cd src/agents/sast && docker build -t sast-agent .
```

## 🔧 Configuration

### Environment Variables

Key environment variables (see `.env.example` for full list):

- `AWS_REGION`: AWS region for deployment
- `BEDROCK_MODEL_ID`: AI model to use (default: anthropic.claude-3-sonnet)
- `S3_BUCKET_PREFIX`: Prefix for S3 bucket names
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `ENABLE_COST_OPTIMIZATION`: Enable/disable cost optimization features

### Agent Configuration

Each agent can be configured via environment variables or configuration files:

```yaml
# config/agents/sast.yml
agent:
  name: sast-scanner
  version: 1.0.0
  capabilities:
    - code-analysis
    - vulnerability-detection
    - pattern-matching
  settings:
    scan_depth: deep
    languages:
      - python
      - javascript
      - java
```

## 📊 Monitoring

Access Grafana dashboards at http://localhost:3001 for:

- Agent performance metrics
- Security findings trends
- Cost analysis
- System health monitoring

## 🔒 Security

This framework implements multiple security best practices:

- **Least Privilege**: IAM roles with minimal required permissions
- **Encryption**: All data encrypted at rest and in transit
- **Secrets Management**: AWS Secrets Manager for sensitive data
- **Network Isolation**: VPC with private subnets for agents
- **Audit Logging**: CloudTrail integration for compliance

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- AWS Bedrock team for AI/ML capabilities
- Open source security tools integrated into agents
- Contributors and maintainers

## 📧 Support

For issues, questions, or contributions:
- Create an issue in the GitHub repository
- Contact the security team at security@example.com
- Join our Slack channel: #security-audit-framework

## 🚧 Roadmap

- [ ] Kubernetes security scanning
- [ ] Real-time threat response automation
- [ ] Integration with SIEM systems
- [ ] Multi-cloud support (Azure, GCP)
- [ ] Enhanced ML models for threat prediction