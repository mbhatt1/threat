# Hephaestus AI Cognitive + Bedrock Integration Guide

## Overview

The Hephaestus AI Cognitive + Bedrock module is an advanced vulnerability discovery system that combines cognitive flow innovation with AWS Bedrock's analysis capabilities to discover complex vulnerability chains in codebases. It has been integrated into the threat security scanning system as part of the AI models collection.

## Key Features

- **6-Phase Cognitive Flow**: Iteratively discovers vulnerabilities through exploration, hypothesis generation, experimentation, validation, learning, and evolution phases
- **Advanced Chain Discovery**: Finds complex multi-step vulnerability chains including runtime and deployment vulnerabilities
- **AI-Enhanced Analysis**: Uses AWS Bedrock's Claude models to analyze code and generate vulnerability hypotheses
- **Adaptive Learning**: Learns from discoveries to find similar patterns and evolve detection strategies
- **POC Generation**: Automatically generates proof-of-concept code for high-confidence vulnerabilities

## Installation

The module is now part of the threat project. Ensure you have the required dependencies installed:

```bash
cd threat/src/ai_models
pip install -r requirements.txt
```

### Required AWS Configuration

Configure your AWS credentials and region:
```bash
# Using environment variables
export AWS_DEFAULT_REGION="us-east-1"
export AWS_ACCESS_KEY_ID="your-access-key-id"
export AWS_SECRET_ACCESS_KEY="your-secret-access-key"

# Or use AWS CLI configuration
aws configure
```

### Bedrock Model Configuration

The module uses Claude 3 Sonnet by default. You can specify a different model:
```bash
export BEDROCK_MODEL_ID="anthropic.claude-3-sonnet-20240229-v1:0"
```

Ensure your AWS account has access to the Bedrock model you want to use.

## Usage

### Basic Usage

```python
from threat.src.ai_models import HephaestusCognitiveAI

# Initialize the analyzer (uses AWS credentials from environment)
hephaestus = HephaestusCognitiveAI()

# Or specify region and model explicitly
hephaestus = HephaestusCognitiveAI(
    region_name="us-east-1",
    model_id="anthropic.claude-3-sonnet-20240229-v1:0"
)

# Analyze a repository
results = await hephaestus.analyze(
    repo_path="/path/to/codebase",
    max_iterations=3  # Each iteration = 1 complete cycle through all 6 phases
)

# Access results
print(f"Found {results['total_chains']} vulnerability chains")
print(f"Critical vulnerabilities: {len([c for c in results['chains'] if c.severity == 'critical'])}")
```

### Integration with Threat Framework

The Hephaestus AI module can be integrated with other threat agents:

```python
from threat.src.ai_models import HephaestusCognitiveAI, VulnerabilityChain
from threat.src.agents.reporting_agent import ReportingAgent

# Run Hephaestus analysis
hephaestus = HephaestusCognitiveAI()
results = await hephaestus.analyze(repo_path)

# Convert to threat framework format
vulnerabilities = []
for chain in results['chains']:
    vuln = {
        'id': chain.id,
        'title': chain.title,
        'severity': chain.severity,
        'description': chain.description,
        'attack_path': chain.attack_path,
        'functions': chain.functions_involved,
        'poc': chain.poc_code,
        'source': 'hephaestus_ai_bedrock'
    }
    vulnerabilities.append(vuln)

# Generate report using threat reporting agent
reporter = ReportingAgent()
report = reporter.generate_report(vulnerabilities)
```

### Advanced Configuration

```python
# Direct access to the analyzer for fine-tuned control
from threat.src.ai_models import CognitiveBedrockAnalyzer, InnovationPhase

analyzer = CognitiveBedrockAnalyzer(
    region_name="us-east-1",
    model_id="anthropic.claude-3-sonnet-20240229-v1:0"
)

# Run specific phases
analyzer.current_phase = InnovationPhase.EXPLORATION
exploration_chains = await analyzer._exploration_phase(repo_path)

# Access learning memory
patterns = analyzer._get_learned_patterns()
```

## Innovation Phases

The system cycles through 6 innovation phases:

1. **EXPLORATION**: Broad analysis to discover attack surface and vulnerabilities
2. **HYPOTHESIS**: Generates targeted vulnerability chains based on findings
3. **EXPERIMENTATION**: Tests specific vulnerability chains with targeted analysis
4. **VALIDATION**: Validates findings and creates proof-of-concepts
5. **LEARNING**: Learns from discoveries to find similar patterns
6. **EVOLUTION**: Evolves strategies to find novel bug classes

## Vulnerability Categories

The system hunts for comprehensive bug categories including:

- **Runtime Security**: File system attacks, dynamic loading exploits, environment variable attacks
- **Deployment Vulnerabilities**: Installation flaws, inter-process attacks, configuration issues
- **Static Security**: Memory corruption, injection attacks, authentication bypasses
- **Functional Bugs**: Logic errors, state bugs, API violations
- **Performance Issues**: Memory leaks, resource exhaustion, inefficiencies
- **Concurrency Bugs**: Race conditions, deadlocks, atomicity violations

## Output Format

The module returns a comprehensive analysis result:

```python
{
    "chains": List[VulnerabilityChain],  # All discovered vulnerability chains
    "report": {
        "summary": str,
        "by_severity": Dict[str, int],
        "by_phase": Dict[str, int],
        "critical_chains": List[Dict]
    },
    "total_chains": int,
    "iterations_completed": int,
    "by_phase": Dict[str, List[VulnerabilityChain]],
    "by_iteration": Dict[int, List[VulnerabilityChain]]
}
```

### VulnerabilityChain Structure

Each vulnerability chain contains:
- Basic info: id, title, description, severity, confidence
- Attack details: steps, impact, exploit_scenario
- Technical info: code_locations, functions_involved, entry_points
- Exploitation: techniques, preconditions, post_exploitation
- Reachability analysis
- POC code (for high-confidence chains)

## Performance Considerations

- **File Loading**: The system pre-loads all files into memory for efficiency
- **Batch Processing**: Analyzes files in batches with concurrent processing
- **Adaptive Execution**: Prioritizes phases that find critical bugs
- **Early Termination**: Stops when convergence is reached or no new critical bugs found
- **AWS API Limits**: Be aware of Bedrock API rate limits and pricing

## Example Integration Script

```python
#!/usr/bin/env python3
import asyncio
import json
from pathlib import Path
from threat.src.ai_models import HephaestusCognitiveAI

async def scan_with_hephaestus(repo_path: str):
    """Run Hephaestus AI analysis on a repository using AWS Bedrock"""
    
    # Initialize Hephaestus (uses AWS credentials from environment)
    hephaestus = HephaestusCognitiveAI()
    
    # Run analysis
    print(f"🚀 Starting Hephaestus AI Bedrock analysis of {repo_path}")
    results = await hephaestus.analyze(repo_path, max_iterations=2)
    
    # Process results
    critical_chains = [c for c in results['chains'] if c.severity in ['critical', 'high']]
    
    print(f"\n📊 Analysis Complete:")
    print(f"Total vulnerabilities: {results['total_chains']}")
    print(f"Critical/High severity: {len(critical_chains)}")
    print(f"Iterations completed: {results['iterations_completed']}")
    
    # Save detailed report
    output_file = f"hephaestus_report_{Path(repo_path).name}.json"
    report_data = {
        'repository': repo_path,
        'total_chains': results['total_chains'],
        'summary': results['report'],
        'critical_chains': [
            {
                'title': c.title,
                'severity': c.severity,
                'confidence': c.confidence,
                'description': c.description,
                'attack_path': c.attack_path,
                'poc_available': bool(c.poc_code)
            }
            for c in critical_chains
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    print(f"\n📄 Report saved to: {output_file}")
    
    return results

if __name__ == "__main__":
    repo = "/path/to/your/codebase"
    asyncio.run(scan_with_hephaestus(repo))
```

## Best Practices

1. **AWS Credentials**: Use IAM roles when running in AWS environments, or secure credential storage for local development
2. **Model Selection**: Claude 3 Sonnet offers a good balance of capability and cost; consider Opus for more complex analyses
3. **Iteration Count**: Start with 2-3 iterations for most codebases; increase for deeper analysis
4. **Resource Limits**: Monitor Bedrock API usage and costs, especially for large codebases
5. **Result Validation**: Review high-confidence findings and generated POCs before taking action
6. **Integration**: Combine with other threat agents for comprehensive security analysis

## AWS Bedrock Pricing

Be aware of AWS Bedrock pricing:
- Charges are based on input/output tokens processed
- Claude 3 Sonnet pricing varies by region
- Monitor usage to control costs, especially during extensive analyses

## Troubleshooting

### Common Issues

1. **AWS Credentials Error**:
   ```
   botocore.exceptions.NoCredentialsError: Unable to locate credentials
   ```
   Solution: Configure AWS credentials using `aws configure` or environment variables

2. **Bedrock Access Error**:
   ```
   botocore.exceptions.ClientError: An error occurred (AccessDeniedException)
   ```
   Solution: Ensure your AWS account has access to Bedrock and the specific model

3. **Region Error**:
   ```
   The specified model is not available in this region
   ```
   Solution: Use a region where your desired Bedrock model is available

4. **Memory Issues with Large Codebases**:
   - The system limits file content to 10KB per file
   - Processes only first 20 files by default
   - Adjust `max_files` in `_analyze_with_prompt` if needed

5. **API Rate Limits**:
   - Implement exponential backoff for rate limit errors
   - Consider using multiple AWS accounts for parallel processing
   - Reduce batch_size to decrease concurrent API calls

## Migration from OpenAI

If migrating from the OpenAI version:
1. Remove OpenAI API key configuration
2. Set up AWS credentials
3. Update import statements to use `CognitiveBedrockAnalyzer` instead of `CognitiveOpenAIAnalyzer`
4. The rest of the API remains the same

## Future Enhancements

- Integration with threat's existing vulnerability database
- Support for additional Bedrock models (Titan, Jurassic, etc.)
- Custom prompts for domain-specific vulnerability detection
- Distributed analysis across multiple AWS regions
- Cost optimization through intelligent batching
- Integration with AWS Security Hub

## Support

For issues or questions about the Hephaestus AI Bedrock integration:
1. Check the module's docstrings and comments
2. Review AWS Bedrock documentation
3. Contact the threat project maintainers