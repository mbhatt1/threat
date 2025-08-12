#!/usr/bin/env python3
"""
Simple MCP Server for Security Scanning using AWS Bedrock directly
This demonstrates how to expose Bedrock AI capabilities as MCP tools
"""

import asyncio
import json
import boto3
from typing import Dict, Any, List, Optional
from datetime import datetime

# Import MCP SDK (simplified version for demonstration)
from mcp import Server, Tool, Resource
from mcp.types import TextContent, ToolCall, ToolResponse


class BedrockSecurityMCP:
    """MCP Server that directly uses AWS Bedrock for security analysis"""
    
    def __init__(self):
        self.server = Server("bedrock-security")
        self.bedrock = boto3.client('bedrock-runtime')
        self.model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
        
        # Register tools
        self._register_tools()
    
    def _register_tools(self):
        """Register Bedrock-powered security tools"""
        
        @self.server.tool()
        async def analyze_code_security(
            code: str,
            language: str = "python",
            analysis_depth: str = "comprehensive"
        ) -> ToolResponse:
            """
            Analyze code for security vulnerabilities using AWS Bedrock AI
            
            Args:
                code: Source code to analyze
                language: Programming language
                analysis_depth: Level of analysis (quick, standard, comprehensive)
            
            Returns:
                Security analysis from Bedrock AI
            """
            
            # Create prompt for Bedrock
            prompt = f"""You are an expert security researcher. Analyze this {language} code for security vulnerabilities.

Code to analyze:
```{language}
{code}
```

Perform a {analysis_depth} security analysis looking for:
1. Injection vulnerabilities (SQL, Command, XSS, etc.)
2. Authentication and authorization issues
3. Cryptographic weaknesses
4. Insecure data handling
5. Business logic flaws
6. Supply chain risks
7. Any other security concerns

For each finding provide:
- Vulnerability type
- Severity (Critical/High/Medium/Low)
- Line numbers affected
- Detailed description
- Proof of concept if applicable
- Remediation advice
- CWE ID if applicable

Format your response as a JSON object with a 'findings' array."""

            try:
                # Call Bedrock directly
                response = self.bedrock.invoke_model(
                    modelId=self.model_id,
                    body=json.dumps({
                        "anthropic_version": "bedrock-2023-05-31",
                        "max_tokens": 4096,
                        "messages": [{
                            "role": "user",
                            "content": prompt
                        }],
                        "temperature": 0.1  # Low temperature for consistent analysis
                    })
                )
                
                # Parse Bedrock response
                response_body = json.loads(response['body'].read())
                ai_response = response_body['content'][0]['text']
                
                # Try to parse as JSON, fallback to text
                try:
                    findings = json.loads(ai_response)
                    result_text = json.dumps(findings, indent=2)
                except:
                    result_text = ai_response
                
                return ToolResponse(
                    content=[TextContent(text=result_text)],
                    metadata={
                        "model": self.model_id,
                        "language": language,
                        "analysis_depth": analysis_depth,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                )
                
            except Exception as e:
                return ToolResponse(
                    content=[TextContent(text=f"Bedrock analysis failed: {str(e)}")],
                    is_error=True
                )
        
        @self.server.tool()
        async def check_dependencies_security(
            dependencies: str,
            ecosystem: str = "python"
        ) -> ToolResponse:
            """
            Check dependencies for vulnerabilities using Bedrock AI
            
            Args:
                dependencies: Package list (requirements.txt, package.json content, etc.)
                ecosystem: Package ecosystem (python, npm, maven, etc.)
            
            Returns:
                Dependency security analysis from Bedrock
            """
            
            prompt = f"""Analyze these {ecosystem} dependencies for known security vulnerabilities and supply chain risks.

Dependencies:
```
{dependencies}
```

Check for:
1. Known CVEs in these package versions
2. Deprecated or abandoned packages
3. Packages with suspicious characteristics
4. Supply chain attack indicators
5. License compliance issues

Provide:
- Package name and version
- Vulnerability details
- Severity rating
- Safe version to upgrade to
- Alternative packages if needed

Format as JSON with 'vulnerable_packages' array."""

            try:
                response = self.bedrock.invoke_model(
                    modelId=self.model_id,
                    body=json.dumps({
                        "anthropic_version": "bedrock-2023-05-31",
                        "max_tokens": 3000,
                        "messages": [{
                            "role": "user",
                            "content": prompt
                        }],
                        "temperature": 0.1
                    })
                )
                
                response_body = json.loads(response['body'].read())
                ai_response = response_body['content'][0]['text']
                
                return ToolResponse(
                    content=[TextContent(text=ai_response)],
                    metadata={
                        "model": self.model_id,
                        "ecosystem": ecosystem,
                        "analyzed_at": datetime.utcnow().isoformat()
                    }
                )
                
            except Exception as e:
                return ToolResponse(
                    content=[TextContent(text=f"Bedrock dependency check failed: {str(e)}")],
                    is_error=True
                )
        
        @self.server.tool()
        async def analyze_infrastructure_security(
            iac_code: str,
            platform: str = "aws"
        ) -> ToolResponse:
            """
            Analyze Infrastructure as Code for security issues using Bedrock
            
            Args:
                iac_code: Infrastructure code (Terraform, CloudFormation, etc.)
                platform: Cloud platform (aws, azure, gcp)
            
            Returns:
                Infrastructure security analysis from Bedrock
            """
            
            prompt = f"""Analyze this infrastructure as code for {platform} security misconfigurations.

Infrastructure Code:
```
{iac_code}
```

Check for:
1. Overly permissive security groups or network ACLs
2. Unencrypted storage resources
3. Public exposure of resources that should be private
4. Missing security controls (MFA, encryption, logging)
5. IAM policy issues (excessive permissions, wildcard usage)
6. Compliance violations (HIPAA, PCI-DSS, SOC2)

For each finding provide:
- Resource type and identifier
- Security issue description
- Risk level
- Impact if exploited
- Remediation steps
- Relevant compliance standards affected

Format as JSON with 'security_issues' array."""

            try:
                response = self.bedrock.invoke_model(
                    modelId=self.model_id,
                    body=json.dumps({
                        "anthropic_version": "bedrock-2023-05-31",
                        "max_tokens": 4096,
                        "messages": [{
                            "role": "user",
                            "content": prompt
                        }],
                        "temperature": 0.1
                    })
                )
                
                response_body = json.loads(response['body'].read())
                ai_response = response_body['content'][0]['text']
                
                return ToolResponse(
                    content=[TextContent(text=ai_response)],
                    metadata={
                        "model": self.model_id,
                        "platform": platform,
                        "scanned_at": datetime.utcnow().isoformat()
                    }
                )
                
            except Exception as e:
                return ToolResponse(
                    content=[TextContent(text=f"Bedrock IaC analysis failed: {str(e)}")],
                    is_error=True
                )
        
        @self.server.tool()
        async def find_secrets(
            content: str,
            file_type: Optional[str] = None
        ) -> ToolResponse:
            """
            Find exposed secrets and credentials using Bedrock AI
            
            Args:
                content: Text content to scan
                file_type: Optional file type hint
            
            Returns:
                Secret detection results from Bedrock
            """
            
            prompt = f"""Scan this content for exposed secrets, credentials, and sensitive information.

Content to scan:
```
{content[:5000]}  # Limit for token size
{'...[truncated]' if len(content) > 5000 else ''}
```

Look for:
1. API keys and tokens
2. Passwords and credentials
3. Private keys and certificates
4. Database connection strings
5. AWS/cloud credentials
6. Webhook URLs and secrets
7. Any other sensitive data

For each finding:
- Type of secret
- Approximate location/line
- Severity
- Why it's dangerous
- How to remediate

IMPORTANT: Do not include the actual secret values in your response for security reasons.

Format as JSON with 'exposed_secrets' array."""

            try:
                response = self.bedrock.invoke_model(
                    modelId=self.model_id,
                    body=json.dumps({
                        "anthropic_version": "bedrock-2023-05-31",
                        "max_tokens": 2000,
                        "messages": [{
                            "role": "user",
                            "content": prompt
                        }],
                        "temperature": 0.1
                    })
                )
                
                response_body = json.loads(response['body'].read())
                ai_response = response_body['content'][0]['text']
                
                return ToolResponse(
                    content=[TextContent(text=ai_response)],
                    metadata={
                        "model": self.model_id,
                        "file_type": file_type,
                        "scanned_at": datetime.utcnow().isoformat()
                    }
                )
                
            except Exception as e:
                return ToolResponse(
                    content=[TextContent(text=f"Bedrock secrets scan failed: {str(e)}")],
                    is_error=True
                )
        
        @self.server.tool()
        async def generate_security_report(
            findings: str,
            report_type: str = "executive"
        ) -> ToolResponse:
            """
            Generate a security report using Bedrock AI
            
            Args:
                findings: JSON string of security findings
                report_type: Type of report (executive, technical, developer)
            
            Returns:
                Formatted security report from Bedrock
            """
            
            report_prompts = {
                "executive": "Create an executive summary focusing on business impact and high-level recommendations",
                "technical": "Create a detailed technical report with specific remediation steps",
                "developer": "Create a developer-friendly report with code examples and fix instructions"
            }
            
            prompt = f"""Generate a {report_type} security report based on these findings.

Findings:
```json
{findings}
```

{report_prompts.get(report_type, report_prompts['technical'])}

Include:
1. Summary of overall security posture
2. Critical issues requiring immediate attention
3. Risk assessment and business impact
4. Prioritized remediation plan
5. Strategic recommendations

Format the report in Markdown for easy reading."""

            try:
                response = self.bedrock.invoke_model(
                    modelId=self.model_id,
                    body=json.dumps({
                        "anthropic_version": "bedrock-2023-05-31",
                        "max_tokens": 4096,
                        "messages": [{
                            "role": "user",
                            "content": prompt
                        }],
                        "temperature": 0.3  # Slightly higher for more natural reports
                    })
                )
                
                response_body = json.loads(response['body'].read())
                report = response_body['content'][0]['text']
                
                return ToolResponse(
                    content=[TextContent(text=report)],
                    metadata={
                        "model": self.model_id,
                        "report_type": report_type,
                        "generated_at": datetime.utcnow().isoformat()
                    }
                )
                
            except Exception as e:
                return ToolResponse(
                    content=[TextContent(text=f"Bedrock report generation failed: {str(e)}")],
                    is_error=True
                )
    
    async def run(self):
        """Run the MCP server"""
        await self.server.run()


def main():
    """Main entry point"""
    server = BedrockSecurityMCP()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()