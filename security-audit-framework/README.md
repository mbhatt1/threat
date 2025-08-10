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