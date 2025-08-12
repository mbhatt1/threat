# Security Scanner MCP Server

This directory contains MCP (Model Context Protocol) server implementations that expose the security scanning capabilities as MCP tools.

## Overview

The MCP implementation provides two approaches:

1. **Full Framework Integration** (`security-scanner-server.py`) - Uses the complete AI orchestrator and all security agents
2. **Direct Bedrock Integration** (`bedrock-security-mcp.py`) - Simpler implementation that calls AWS Bedrock directly

## Architecture

### MCP + AWS Bedrock Integration

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│   MCP Server    │────▶│  AWS Bedrock    │
│ (Claude, etc.)  │     │  (This Server)  │     │  (Claude API)   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌─────────────────┐
                        │ Security Tools  │
                        │ - Code Analysis │
                        │ - Dependency    │
                        │ - Secrets       │
                        │ - IaC Security  │
                        └─────────────────┘
```

## Available Tools

### 1. Code Security Analysis
```python
# Analyze code for vulnerabilities
result = await analyze_code_security(
    code="import os; os.system(user_input)",
    language="python",
    analysis_depth="comprehensive"
)
```

### 2. Dependency Security Check
```python
# Check dependencies for vulnerabilities
result = await check_dependencies_security(
    dependencies="flask==2.0.1\nrequests==2.25.1",
    ecosystem="python"
)
```

### 3. Infrastructure Security
```python
# Analyze IaC for misconfigurations
result = await analyze_infrastructure_security(
    iac_code=terraform_content,
    platform="aws"
)
```

### 4. Secrets Detection
```python
# Find exposed secrets
result = await find_secrets(
    content=file_content,
    file_type="config"
)
```

### 5. Security Report Generation
```python
# Generate formatted reports
result = await generate_security_report(
    findings=json_findings,
    report_type="executive"
)
```

## Setup

### Prerequisites
- Python 3.9+
- AWS credentials configured
- AWS Bedrock access enabled in your region
- MCP SDK installed

### Installation

```bash
cd security-audit-framework/mcp
pip install -r requirements.txt
```

### Configuration

Set environment variables:
```bash
export AWS_REGION=us-east-1
export BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0
export RESULTS_BUCKET=your-s3-bucket
export SCAN_TABLE=SecurityScans
```

### Running the Server

#### Option 1: Full Framework Server
```bash
python security-scanner-server.py
```

#### Option 2: Direct Bedrock Server
```bash
python bedrock-security-mcp.py
```

## Usage Examples

### With Claude Desktop

Add to your Claude configuration:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "python",
      "args": ["/path/to/security-audit-framework/mcp/bedrock-security-mcp.py"],
      "env": {
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

### With MCP CLI

```bash
# Install MCP CLI
npm install -g @modelcontextprotocol/cli

# Connect to the server
mcp connect security-scanner

# Use tools
mcp call analyze_code_security --code "..." --language "python"
```

## How It Works

### 1. MCP Protocol
The server implements the MCP protocol, exposing security scanning capabilities as tools that any MCP client can use.

### 2. AWS Bedrock Integration
Each tool creates specialized prompts for AWS Bedrock (Claude) to analyze security aspects:
- Code vulnerabilities
- Dependency risks
- Infrastructure misconfigurations
- Exposed secrets

### 3. Response Format
All tools return structured responses with:
- Findings (vulnerabilities, issues)
- Severity ratings
- Remediation advice
- Metadata (model used, timestamp)

## Benefits of MCP Approach

1. **Universal Access**: Any MCP-compatible client can use these security tools
2. **AI-Powered**: Leverages AWS Bedrock's Claude models for intelligent analysis
3. **Flexible Integration**: Can be used in IDEs, CI/CD, chat interfaces, etc.
4. **Standardized Protocol**: Consistent interface across different tools
5. **Extensible**: Easy to add new security analysis capabilities

## Comparison: Full vs Direct Implementation

### Full Framework (`security-scanner-server.py`)
- **Pros**: 
  - Complete security scanning with all agents
  - Persistent storage in DynamoDB
  - Comprehensive reporting
  - Enterprise features
- **Cons**: 
  - Requires full AWS infrastructure
  - More complex setup

### Direct Bedrock (`bedrock-security-mcp.py`)
- **Pros**: 
  - Simple, standalone implementation
  - Minimal dependencies
  - Quick to deploy
  - Direct AI analysis
- **Cons**: 
  - No persistence
  - Limited to Bedrock capabilities

## Security Considerations

1. **AWS Credentials**: Ensure proper IAM permissions for Bedrock access
2. **Data Privacy**: Code and findings are processed by AWS Bedrock
3. **Rate Limits**: Be aware of Bedrock API rate limits
4. **Cost Management**: Monitor Bedrock usage costs

## Future Enhancements

1. **Streaming Responses**: Support for real-time analysis updates
2. **Batch Operations**: Analyze multiple files/repositories
3. **Custom Policies**: User-defined security rules
4. **Integration Plugins**: Direct IDE integration
5. **Caching**: Reduce redundant Bedrock calls

## Contributing

To add new security tools:

1. Add tool definition in `_register_tools()`
2. Create specialized Bedrock prompt
3. Update `server.json` with tool metadata
4. Add usage examples to this README

## License

MIT License - See parent project for details