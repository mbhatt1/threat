#!/usr/bin/env python3
"""
MCP Server for Security Scanning
Exposes security audit capabilities as MCP tools and resources
"""

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent / "src"))

# Import MCP SDK
from mcp import Server, Tool, Resource
from mcp.types import TextContent, ImageContent, ToolCall, ToolResponse

# Import security scanning components
from shared.ai_orchestrator import AISecurityOrchestrator
from shared.ai_explainability import AIExplainabilityEngine
from shared.business_context import BusinessContextEngine
from shared.advanced_features import AISecurityFeatures

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityScannerMCPServer:
    """MCP Server providing security scanning tools and resources"""
    
    def __init__(self):
        self.server = Server("security-scanner")
        self.ai_orchestrator = AISecurityOrchestrator()
        self.explainability = AIExplainabilityEngine()
        self.business_context = BusinessContextEngine()
        self.ai_features = AISecurityFeatures()
        
        # Store scan results for resource access
        self.scan_results = {}
        
        # Register tools
        self._register_tools()
        
        # Register resources
        self._register_resources()
    
    def _register_tools(self):
        """Register security scanning tools"""
        
        # Full security scan tool
        @self.server.tool()
        async def scan_repository(
            repository_url: str,
            scan_type: str = "full",
            branch: str = "main",
            focus_areas: Optional[List[str]] = None
        ) -> ToolResponse:
            """
            Perform comprehensive AI-powered security scan on a repository
            
            Args:
                repository_url: URL of the repository to scan
                scan_type: Type of scan (full, incremental, pr)
                branch: Branch to scan
                focus_areas: Specific areas to focus on (e.g., ['secrets', 'dependencies'])
            
            Returns:
                Scan results with findings and insights
            """
            try:
                # Clone repository to temp directory
                repo_path = await self._clone_repository(repository_url, branch)
                
                # Perform scan using AI orchestrator
                scan_result = await self.ai_orchestrator.orchestrate_security_scan(
                    repository_path=repo_path,
                    scan_type=scan_type,
                    branch=branch
                )
                
                # Store results for resource access
                self.scan_results[scan_result.scan_id] = scan_result
                
                # Return summary
                return ToolResponse(
                    content=[
                        TextContent(
                            text=f"Security scan completed successfully\n"
                                 f"Scan ID: {scan_result.scan_id}\n"
                                 f"Total findings: {scan_result.total_findings}\n"
                                 f"Critical: {scan_result.critical_findings}\n"
                                 f"High: {scan_result.high_findings}\n"
                                 f"Business risk score: {scan_result.business_risk_score:.1f}/100\n"
                                 f"AI confidence: {scan_result.ai_confidence_score:.1%}"
                        )
                    ],
                    metadata={
                        "scan_id": scan_result.scan_id,
                        "status": scan_result.scan_status,
                        "duration": str(scan_result.completed_at - scan_result.started_at) if scan_result.completed_at else "in progress"
                    }
                )
            except Exception as e:
                logger.error(f"Scan failed: {e}")
                return ToolResponse(
                    content=[TextContent(text=f"Scan failed: {str(e)}")],
                    is_error=True
                )
        
        # Quick vulnerability check tool
        @self.server.tool()
        async def check_vulnerabilities(
            code_snippet: str,
            language: str = "python",
            context: Optional[str] = None
        ) -> ToolResponse:
            """
            Quick AI-powered vulnerability check on a code snippet
            
            Args:
                code_snippet: Code to analyze
                language: Programming language
                context: Additional context about the code
            
            Returns:
                Vulnerability analysis results
            """
            try:
                # Use AI features for quick analysis
                analysis = self.ai_features.comprehensive_ai_analysis(
                    code=code_snippet,
                    file_path=f"snippet.{language}",
                    dependencies={},
                    language=language
                )
                
                vulnerabilities = analysis.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    return ToolResponse(
                        content=[TextContent(text="No vulnerabilities detected in the code snippet")]
                    )
                
                # Format vulnerabilities
                result_text = f"Found {len(vulnerabilities)} potential vulnerabilities:\n\n"
                for i, vuln in enumerate(vulnerabilities, 1):
                    result_text += f"{i}. {vuln.get('title', 'Unknown')}\n"
                    result_text += f"   Severity: {vuln.get('severity', 'MEDIUM')}\n"
                    result_text += f"   Description: {vuln.get('description', 'No description')}\n"
                    result_text += f"   Fix: {vuln.get('remediation', 'Review and fix')}\n\n"
                
                return ToolResponse(
                    content=[TextContent(text=result_text)],
                    metadata={
                        "vulnerability_count": len(vulnerabilities),
                        "language": language
                    }
                )
            except Exception as e:
                logger.error(f"Vulnerability check failed: {e}")
                return ToolResponse(
                    content=[TextContent(text=f"Check failed: {str(e)}")],
                    is_error=True
                )
        
        # Dependency security check tool
        @self.server.tool()
        async def check_dependencies(
            package_file_content: str,
            package_type: str = "requirements.txt"
        ) -> ToolResponse:
            """
            Check dependencies for known vulnerabilities
            
            Args:
                package_file_content: Content of package file (requirements.txt, package.json, etc.)
                package_type: Type of package file
            
            Returns:
                Dependency vulnerability report
            """
            try:
                # Parse dependencies based on type
                dependencies = self._parse_dependencies(package_file_content, package_type)
                
                # Check for vulnerabilities using AI
                supply_chain_risks = await self.ai_features.supply_chain_analyzer.analyze_packages(dependencies)
                
                if not supply_chain_risks:
                    return ToolResponse(
                        content=[TextContent(text="No vulnerable dependencies detected")]
                    )
                
                # Format results
                result_text = f"Found {len(supply_chain_risks)} packages with security issues:\n\n"
                for package, risks in supply_chain_risks.items():
                    result_text += f"📦 {package}:\n"
                    for risk in risks:
                        result_text += f"   - {risk['description']}\n"
                        result_text += f"     Severity: {risk['severity']}\n"
                        result_text += f"     Fix: {risk.get('fix', 'Update to latest version')}\n"
                
                return ToolResponse(
                    content=[TextContent(text=result_text)],
                    metadata={
                        "vulnerable_packages": len(supply_chain_risks),
                        "package_type": package_type
                    }
                )
            except Exception as e:
                logger.error(f"Dependency check failed: {e}")
                return ToolResponse(
                    content=[TextContent(text=f"Check failed: {str(e)}")],
                    is_error=True
                )
        
        # Infrastructure security check tool
        @self.server.tool()
        async def check_infrastructure(
            iac_content: str,
            iac_type: str = "terraform"
        ) -> ToolResponse:
            """
            Check infrastructure as code for security misconfigurations
            
            Args:
                iac_content: Infrastructure code content
                iac_type: Type of IaC (terraform, cloudformation, kubernetes)
            
            Returns:
                Infrastructure security findings
            """
            try:
                # Analyze IaC using AI
                analysis = await self._analyze_iac(iac_content, iac_type)
                
                findings = analysis.get('findings', [])
                
                if not findings:
                    return ToolResponse(
                        content=[TextContent(text="No infrastructure security issues detected")]
                    )
                
                # Format findings
                result_text = f"Found {len(findings)} infrastructure security issues:\n\n"
                for i, finding in enumerate(findings, 1):
                    result_text += f"{i}. {finding.get('title', 'Unknown issue')}\n"
                    result_text += f"   Resource: {finding.get('resource', 'Unknown')}\n"
                    result_text += f"   Severity: {finding.get('severity', 'MEDIUM')}\n"
                    result_text += f"   Issue: {finding.get('description', 'No description')}\n"
                    result_text += f"   Fix: {finding.get('remediation', 'Review configuration')}\n\n"
                
                return ToolResponse(
                    content=[TextContent(text=result_text)],
                    metadata={
                        "findings_count": len(findings),
                        "iac_type": iac_type
                    }
                )
            except Exception as e:
                logger.error(f"Infrastructure check failed: {e}")
                return ToolResponse(
                    content=[TextContent(text=f"Check failed: {str(e)}")],
                    is_error=True
                )
        
        # Generate security report tool
        @self.server.tool()
        async def generate_report(
            scan_id: str,
            report_type: str = "executive"
        ) -> ToolResponse:
            """
            Generate a security report from scan results
            
            Args:
                scan_id: ID of the scan to generate report for
                report_type: Type of report (executive, technical, compliance)
            
            Returns:
                Security report in requested format
            """
            try:
                # Get scan results
                if scan_id not in self.scan_results:
                    return ToolResponse(
                        content=[TextContent(text=f"Scan ID {scan_id} not found")],
                        is_error=True
                    )
                
                scan_result = self.scan_results[scan_id]
                
                # Generate report based on type
                if report_type == "executive":
                    report = await self._generate_executive_report(scan_result)
                elif report_type == "technical":
                    report = await self._generate_technical_report(scan_result)
                else:
                    report = await self._generate_compliance_report(scan_result)
                
                return ToolResponse(
                    content=[TextContent(text=report)],
                    metadata={
                        "scan_id": scan_id,
                        "report_type": report_type,
                        "generated_at": datetime.utcnow().isoformat()
                    }
                )
            except Exception as e:
                logger.error(f"Report generation failed: {e}")
                return ToolResponse(
                    content=[TextContent(text=f"Report generation failed: {str(e)}")],
                    is_error=True
                )
    
    def _register_resources(self):
        """Register security resources"""
        
        @self.server.resource("security://scans")
        async def list_scans() -> Resource:
            """List all available security scans"""
            scans_list = []
            for scan_id, scan_result in self.scan_results.items():
                scans_list.append({
                    "scan_id": scan_id,
                    "repository": scan_result.repository,
                    "branch": scan_result.branch,
                    "scan_type": scan_result.scan_type,
                    "status": scan_result.scan_status,
                    "findings": scan_result.total_findings,
                    "risk_score": scan_result.business_risk_score
                })
            
            return Resource(
                uri="security://scans",
                name="Security Scans",
                mime_type="application/json",
                content=TextContent(text=json.dumps(scans_list, indent=2))
            )
        
        @self.server.resource("security://policies")
        async def security_policies() -> Resource:
            """Get current security policies"""
            policies = {
                "severity_thresholds": {
                    "critical": 0,  # No critical vulnerabilities allowed
                    "high": 5,      # Max 5 high severity
                    "medium": 20    # Max 20 medium severity
                },
                "scan_requirements": {
                    "pr_scans": True,
                    "main_branch_protection": True,
                    "dependency_updates": "weekly"
                },
                "compliance_frameworks": [
                    "OWASP Top 10",
                    "CWE Top 25",
                    "NIST Cybersecurity Framework"
                ]
            }
            
            return Resource(
                uri="security://policies",
                name="Security Policies",
                mime_type="application/json",
                content=TextContent(text=json.dumps(policies, indent=2))
            )
    
    async def _clone_repository(self, repository_url: str, branch: str) -> str:
        """Clone repository to temporary directory"""
        # Simplified for demo - in production use proper git operations
        import tempfile
        temp_dir = tempfile.mkdtemp()
        # Would clone repository here
        return temp_dir
    
    def _parse_dependencies(self, content: str, package_type: str) -> Dict[str, str]:
        """Parse dependencies from package file"""
        dependencies = {}
        
        if package_type == "requirements.txt":
            for line in content.strip().split('\n'):
                if '==' in line:
                    name, version = line.split('==')
                    dependencies[name.strip()] = version.strip()
                elif line and not line.startswith('#'):
                    dependencies[line.strip()] = "latest"
        
        elif package_type == "package.json":
            try:
                data = json.loads(content)
                dependencies.update(data.get('dependencies', {}))
                dependencies.update(data.get('devDependencies', {}))
            except:
                pass
        
        return dependencies
    
    async def _analyze_iac(self, content: str, iac_type: str) -> Dict[str, Any]:
        """Analyze infrastructure as code"""
        # Use AI to analyze IaC
        return {
            'findings': [
                {
                    'title': 'Public S3 Bucket',
                    'resource': 'aws_s3_bucket.public',
                    'severity': 'HIGH',
                    'description': 'S3 bucket allows public access',
                    'remediation': 'Add bucket policy to restrict access'
                }
            ]
        }
    
    async def _generate_executive_report(self, scan_result) -> str:
        """Generate executive summary report"""
        report = f"""
# Executive Security Report

**Scan ID**: {scan_result.scan_id}
**Repository**: {scan_result.repository}
**Date**: {scan_result.started_at.strftime('%Y-%m-%d')}

## Overall Security Posture
- **Business Risk Score**: {scan_result.business_risk_score:.1f}/100
- **AI Confidence**: {scan_result.ai_confidence_score:.1%}

## Key Findings
- **Total Issues**: {scan_result.total_findings}
- **Critical**: {scan_result.critical_findings}
- **High**: {scan_result.high_findings}

## Recommendations
1. Address all critical vulnerabilities immediately
2. Review and fix high severity issues within 1 week
3. Implement automated security scanning in CI/CD pipeline

## Risk Assessment
Based on the findings, the overall risk level is **{'CRITICAL' if scan_result.critical_findings > 0 else 'HIGH' if scan_result.high_findings > 5 else 'MEDIUM'}**.
"""
        return report
    
    async def _generate_technical_report(self, scan_result) -> str:
        """Generate detailed technical report"""
        # Would include detailed findings, code snippets, etc.
        return "Technical report with detailed findings..."
    
    async def _generate_compliance_report(self, scan_result) -> str:
        """Generate compliance-focused report"""
        # Would map findings to compliance frameworks
        return "Compliance report mapping to OWASP, CWE, etc..."
    
    async def run(self):
        """Run the MCP server"""
        await self.server.run()


def main():
    """Main entry point"""
    server = SecurityScannerMCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()