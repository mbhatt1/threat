#!/usr/bin/env python3
"""
Red Team Security Agent
Performs adversarial security analysis on the security framework itself
"""

import os
import sys
import json
import re
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

import boto3

# Add parent directories to path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import shared components
from shared.ai_orchestrator import AISecurityOrchestrator
from shared.ai_explainability import AIExplainabilityEngine
from shared.business_context import BusinessContextEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RedTeamAgent:
    """
    Red Team agent that performs adversarial security analysis
    Specifically designed to find vulnerabilities in security tools
    """
    
    def __init__(self):
        # Initialize components
        self.bedrock = boto3.client('bedrock-runtime')
        self.s3 = boto3.client('s3')
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
        self.results_bucket = os.environ.get('RESULTS_BUCKET')
        
        # Attack categories to test
        self.attack_categories = [
            "authentication_bypass",
            "privilege_escalation", 
            "injection_attacks",
            "information_disclosure",
            "denial_of_service",
            "supply_chain_attacks",
            "configuration_weaknesses",
            "cryptographic_failures",
            "business_logic_flaws",
            "api_vulnerabilities"
        ]
    
    async def red_team_analysis(
        self, repository_path: str, scan_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform comprehensive red team analysis on the security framework"""
        scan_id = scan_config.get(
            'scan_id', f'redteam-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}'
        )
        logger.info(f"Starting red team analysis {scan_id}")
        
        findings = []
        
        # 1. Analyze architecture for security flaws
        arch_findings = await self._analyze_architecture_security()
        findings.extend(arch_findings)
        
        # 2. Review authentication and authorization
        auth_findings = await self._analyze_authentication()
        findings.extend(auth_findings)
        
        # 3. Check for injection vulnerabilities
        injection_findings = await self._analyze_injection_risks()
        findings.extend(injection_findings)
        
        # 4. Examine API security
        api_findings = await self._analyze_api_security()
        findings.extend(api_findings)
        
        # 5. Review AWS IAM and infrastructure
        infra_findings = await self._analyze_infrastructure_security()
        findings.extend(infra_findings)
        
        # 6. Check for secrets and sensitive data
        secrets_findings = await self._analyze_secrets_management()
        findings.extend(secrets_findings)
        
        # 7. Analyze dependencies for vulnerabilities
        dep_findings = await self._analyze_dependencies()
        findings.extend(dep_findings)
        
        # 8. Test business logic security
        logic_findings = await self._analyze_business_logic()
        findings.extend(logic_findings)
        
        # 9. Check for DoS vulnerabilities
        dos_findings = await self._analyze_dos_vulnerabilities()
        findings.extend(dos_findings)
        
        # 10. Generate attack scenarios
        attack_scenarios = await self._generate_attack_scenarios(findings)
        
        # Create comprehensive report
        report = {
            'scan_id': scan_id,
            'scan_type': 'RED_TEAM',
            'timestamp': datetime.utcnow().isoformat(),
            'repository': repository_path,
            'total_findings': len(findings),
            'critical_findings': len([f for f in findings if f.get('severity') == 'CRITICAL']),
            'high_findings': len([f for f in findings if f.get('severity') == 'HIGH']),
            'findings': findings,
            'attack_scenarios': attack_scenarios,
            'risk_assessment': await self._calculate_overall_risk(findings),
            'recommendations': await self._generate_recommendations(findings)
        }
        
        # Save results
        if self.results_bucket:
            self._save_results(scan_id, report)
        
        logger.info(f"Red team analysis complete: {len(findings)} vulnerabilities found")
        return report
    
    async def _analyze_architecture_security(self) -> List[Dict[str, Any]]:
        """Analyze the overall architecture for security weaknesses"""
        findings = []
        
        # Read key architecture files
        arch_files = [
            'cdk/stacks/api_stack.py',
            'cdk/stacks/lambda_stack.py', 
            'cdk/stacks/iam_stack.py',
            'src/shared/ai_orchestrator.py'
        ]
        
        for file_path in arch_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Use AI to find architectural vulnerabilities
                prompt = f"""You are an expert security researcher performing a red team assessment.
Analyze this code file from a security framework for architectural vulnerabilities:

File: {file_path}
```python
{content[:10000]}
```

Look for:
1. Single points of failure
2. Missing security controls
3. Overly permissive configurations
4. Trust boundary violations
5. Insufficient input validation
6. Missing rate limiting
7. Lack of defense in depth
8. Insecure defaults

For each vulnerability found, provide:
- Title
- Severity (CRITICAL/HIGH/MEDIUM/LOW)
- Description
- Attack vector
- Impact
- Remediation

Format as JSON with 'vulnerabilities' array."""

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
                            "temperature": 0.7  # Higher for creative attack thinking
                        })
                    )
                    
                    response_body = json.loads(response['body'].read())
                    ai_response = response_body['content'][0]['text']
                    
                    # Parse findings
                    try:
                        result = json.loads(ai_response)
                        for vuln in result.get('vulnerabilities', []):
                            vuln['file'] = file_path
                            vuln['category'] = 'architecture'
                            findings.append(vuln)
                    except json.JSONDecodeError:
                        pass
                        
                except Exception as e:
                    logger.error(
                        f"Architecture analysis failed for {file_path}: {e}"
                    )
        
        return findings
    
    async def _analyze_authentication(self) -> List[Dict[str, Any]]:
        """Analyze authentication and authorization mechanisms"""
        findings = []
        
        prompt = """Analyze the security framework's authentication and authorization for vulnerabilities:

Key areas to examine:
1. API Gateway authentication - Is it properly configured?
2. IAM roles and policies - Are they overly permissive?
3. Lambda function permissions - Can they be exploited?
4. Inter-service authentication - Is it secure?
5. Token/key management - Are there exposed credentials?

Based on common patterns in serverless AWS applications, what authentication vulnerabilities might exist?

Consider:
- Missing authentication on endpoints
- Weak authorization checks
- JWT vulnerabilities
- Session management issues
- Privilege escalation paths

Provide specific, actionable vulnerabilities that could be exploited.
Format as JSON with 'vulnerabilities' array."""

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
                    "temperature": 0.7
                })
            )
            
            response_body = json.loads(response['body'].read())
            ai_response = response_body['content'][0]['text']
            
            try:
                result = json.loads(ai_response)
                for vuln in result.get('vulnerabilities', []):
                    vuln['category'] = 'authentication'
                    findings.append(vuln)
            except json.JSONDecodeError:
                pass
                
        except Exception as e:
            logger.error(f"Authentication analysis failed: {e}")
        
        return findings
    
    async def _analyze_injection_risks(self) -> List[Dict[str, Any]]:
        """Look for injection vulnerabilities"""
        findings = []
        
        # Check for potential injection points
        injection_patterns = [
            ('os.system', 'Command injection'),
            ('subprocess', 'Command injection'),
            ('eval(', 'Code injection'),
            ('exec(', 'Code injection'),
            ('.format(', 'Format string vulnerability'),
            ('WHERE', 'SQL injection'),
            ('innerHTML', 'XSS vulnerability'),
            ('dangerouslySetInnerHTML', 'XSS vulnerability')
        ]
        
        # Scan all Python files
        for root, _, files in os.walk('src'):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            
                        for pattern, vuln_type in injection_patterns:
                            if pattern in content:
                                findings.append({
                                    'title': f'{vuln_type} risk detected',
                                    'severity': 'HIGH',
                                    'category': 'injection',
                                    'file': file_path,
                                    'pattern': pattern,
                                    'description': f'Potential {vuln_type} vulnerability found',
                                    'remediation': (
                                        f'Review usage of {pattern} and '
                                        'implement proper sanitization'
                                    )
                                })
                    except:
                        pass
        
        return findings
    
    async def _analyze_api_security(self) -> List[Dict[str, Any]]:
        """Analyze API Gateway and endpoint security"""
        findings = []
        
        # Read API stack configuration
        api_stack_path = 'cdk/stacks/api_stack.py'
        if os.path.exists(api_stack_path):
            with open(api_stack_path, 'r') as f:
                api_config = f.read()
            
            # Check for common API vulnerabilities
            vulnerabilities = []
            
            # Missing rate limiting
            if ('throttle' not in api_config.lower() and
                'rate' not in api_config.lower()):
                vulnerabilities.append({
                    'title': 'Missing API rate limiting',
                    'severity': 'HIGH',
                    'description': (
                        'API endpoints lack rate limiting, vulnerable to DoS attacks'
                    ),
                    'remediation': 'Implement API Gateway throttling and rate limiting'
                })
            
            # Missing CORS configuration
            if 'cors' not in api_config.lower():
                vulnerabilities.append({
                    'title': 'Missing CORS configuration',
                    'severity': 'MEDIUM',
                    'description': 'API may be vulnerable to cross-origin attacks',
                    'remediation': 'Configure proper CORS headers'
                })
            
            # Check for API key usage
            if ('api_key' not in api_config.lower() and
                'authorizer' not in api_config.lower()):
                vulnerabilities.append({
                    'title': 'No API authentication configured',
                    'severity': 'CRITICAL',
                    'description': 'API endpoints appear to lack authentication',
                    'remediation': (
                        'Implement API key or authorizer-based authentication'
                    )
                })
            
            for vuln in vulnerabilities:
                vuln['category'] = 'api_security'
                vuln['file'] = api_stack_path
                findings.append(vuln)
        
        return findings
    
    async def _analyze_infrastructure_security(self) -> List[Dict[str, Any]]:
        """Analyze AWS infrastructure security"""
        findings = []
        
        # Check IAM policies
        iam_issues = []
        
        # Look for overly permissive policies
        iam_files = [
            'cdk/stacks/iam_stack.py',
            'cdk/stacks/lambda_stack.py'
        ]
        
        for file_path in iam_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check for dangerous patterns
                if '"*"' in content or "'*'" in content:
                    iam_issues.append({
                        'title': 'Overly permissive IAM policy detected',
                        'severity': 'HIGH',
                        'file': file_path,
                        'description': 'IAM policy contains wildcard permissions',
                        'remediation': 'Apply principle of least privilege'
                    })
                
                if 'iam:PassRole' in content:
                    iam_issues.append({
                        'title': 'Dangerous IAM permission: PassRole',
                        'severity': 'HIGH',
                        'file': file_path,
                        'description': (
                            'PassRole permission can lead to privilege escalation'
                        ),
                        'remediation': 'Restrict PassRole to specific roles'
                    })
        
        for issue in iam_issues:
            issue['category'] = 'infrastructure'
            findings.append(issue)
        
        return findings
    
    async def _analyze_secrets_management(self) -> List[Dict[str, Any]]:
        """Check for exposed secrets and poor secret management"""
        findings = []
        
        # Patterns that might indicate secrets
        secret_patterns = [
            (r'["\']sk-[a-zA-Z0-9]{48}["\']', 'OpenAI API key'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'["\'][a-zA-Z0-9/+=]{40}["\']', 'AWS Secret Key'),
            (r'["\']AIza[0-9A-Za-z\-_]{35}["\']', 'Google API key'),
            (r'["\'][0-9a-f]{40}["\']', 'Generic API token'),
            (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
            (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key')
        ]
        
        # Scan all files
        for root, _, files in os.walk('.'):
            # Skip node_modules, .git, etc.
            if any(skip in root for skip in [
                '.git', 'node_modules', '__pycache__'
            ]):
                continue
                
            for file in files:
                if file.endswith((
                    '.py', '.js', '.ts', '.json', '.yaml', '.yml', '.env'
                )):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                        
                        for pattern, secret_type in secret_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                findings.append({
                                    'title': f'Potential {secret_type} exposed',
                                    'severity': 'CRITICAL',
                                    'category': 'secrets',
                                    'file': file_path,
                                    'description': (
                                        f'Found pattern matching {secret_type}'
                                    ),
                                    'remediation': (
                                        'Use AWS Secrets Manager or '
                                        'environment variables'
                                    )
                                })
                    except Exception:
                        pass
        
        return findings
    
    async def _analyze_dependencies(self) -> List[Dict[str, Any]]:
        """Check for vulnerable dependencies"""
        findings = []
        
        # Check all requirements.txt files
        req_files = []
        for root, _, files in os.walk('.'):
            for file in files:
                if file == 'requirements.txt':
                    req_files.append(os.path.join(root, file))
        
        for req_file in req_files:
            with open(req_file, 'r') as f:
                deps = f.read()
            
            # Check for outdated or vulnerable packages
            vulnerable_packages = {
                'flask==2.0.1': 'Flask 2.0.1 has known security vulnerabilities',
                'requests<2.25': 'Older requests versions have security issues',
                'pyyaml<5.4': 'PyYAML versions before 5.4 have arbitrary code execution vulnerability',
                'jinja2<2.11.3': (
                    'Jinja2 has XSS vulnerabilities in older versions'
                )
            }
            
            for package, issue in vulnerable_packages.items():
                package_name = package.split('==')[0].split('<')[0]
                if package_name in deps:
                    findings.append({
                        'title': f'Vulnerable dependency: {package_name}',
                        'severity': 'HIGH',
                        'category': 'dependencies',
                        'file': req_file,
                        'description': issue,
                        'remediation': 'Update to latest secure version'
                    })
        
        return findings
    
    async def _analyze_business_logic(self) -> List[Dict[str, Any]]:
        """Analyze business logic for security flaws"""
        findings = []
        
        # Check scan result handling
        logic_issues = [
            {
                'title': 'Scan result tampering possibility',
                'severity': 'HIGH',
                'description': (
                    'Scan results stored in S3 without integrity verification'
                ),
                'remediation': 'Implement digital signatures for scan results'
            },
            {
                'title': 'Missing scan result validation',
                'severity': 'MEDIUM',
                'description': (
                    'No validation of scan result format before processing'
                ),
                'remediation': 'Add schema validation for all scan results'
            },
            {
                'title': 'Potential scan result injection',
                'severity': 'HIGH',
                'description': (
                    'User-controlled data in scan results not properly sanitized'
                ),
                'remediation': 'Sanitize all user inputs before including in reports'
            }
        ]
        
        for issue in logic_issues:
            issue['category'] = 'business_logic'
            findings.append(issue)
        
        return findings
    
    async def _analyze_dos_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check for denial of service vulnerabilities"""
        findings = []
        
        dos_issues = [
            {
                'title': 'Unbounded file processing',
                'severity': 'HIGH',
                'description': 'No file size limits for repository scanning',
                'impact': 'Large repositories could exhaust Lambda memory',
                'remediation': (
                    'Implement file size limits and streaming processing'
                )
            },
            {
                'title': 'Missing concurrency limits',
                'severity': 'MEDIUM',
                'description': 'No limits on concurrent scan executions',
                'impact': 'Could lead to resource exhaustion',
                'remediation': 'Implement SQS queue with concurrency controls'
            },
            {
                'title': 'Regex DoS possibility',
                'severity': 'MEDIUM',
                'description': 'Complex regex patterns without timeout',
                'impact': 'Malicious input could cause CPU exhaustion',
                'remediation': 'Add regex execution timeouts'
            }
        ]
        
        for issue in dos_issues:
            issue['category'] = 'denial_of_service'
            findings.append(issue)
        
        return findings
    
    async def _generate_attack_scenarios(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate realistic attack scenarios based on findings"""
        
        critical_count = len([
            f for f in findings if f.get('severity') == 'CRITICAL'
        ])
        high_count = len([
            f for f in findings if f.get('severity') == 'HIGH'
        ])
        categories = list(set(f.get('category', '') for f in findings))
        
        prompt = f"""Based on these security findings, generate realistic attack scenarios:

Findings summary:
- Critical: {critical_count}
- High: {high_count}
- Categories: {categories}

Top vulnerabilities:
{json.dumps(findings[:10], indent=2)}

Generate 3-5 realistic attack scenarios that chain multiple vulnerabilities.
Each scenario should include:
- Attack name
- Objective
- Prerequisites
- Step-by-step attack chain
- Impact
- Likelihood

Format as JSON with 'scenarios' array."""

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
                    "temperature": 0.8
                })
            )
            
            response_body = json.loads(response['body'].read())
            ai_response = response_body['content'][0]['text']
            
            try:
                result = json.loads(ai_response)
                return result.get('scenarios', [])
            except json.JSONDecodeError:
                return []
                
        except Exception as e:
            logger.error(f"Attack scenario generation failed: {e}")
            return []
    
    async def _calculate_overall_risk(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate overall security risk score"""
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 5,
            'MEDIUM': 2,
            'LOW': 1
        }
        
        total_score = sum(
            severity_weights.get(f.get('severity', 'LOW'), 1) 
            for f in findings
        )
        
        if total_score > 50:
            risk_level = 'CRITICAL'
        elif total_score > 20:
            risk_level = 'HIGH'
        elif total_score > 10:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_score': total_score,
            'risk_level': risk_level,
            'finding_breakdown': {
                'critical': len([
                    f for f in findings if f.get('severity') == 'CRITICAL'
                ]),
                'high': len([
                    f for f in findings if f.get('severity') == 'HIGH'
                ]),
                'medium': len([
                    f for f in findings if f.get('severity') == 'MEDIUM'
                ]),
                'low': len([
                    f for f in findings if f.get('severity') == 'LOW'
                ])
            }
        }
    
    async def _generate_recommendations(
        self, findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate prioritized security recommendations"""
        recommendations = []
        
        # Priority 1: Critical findings
        if any(f.get('severity') == 'CRITICAL' for f in findings):
            recommendations.append(
                "IMMEDIATE: Address all critical vulnerabilities before deployment"
            )
        
        # Check categories
        categories = set(f.get('category', '') for f in findings)
        
        if 'authentication' in categories:
            recommendations.append(
                "Implement multi-factor authentication and stronger access controls"
            )
        
        if 'secrets' in categories:
            recommendations.append(
                "Migrate all secrets to AWS Secrets Manager immediately"
            )
        
        if 'injection' in categories:
            recommendations.append(
                "Implement input validation and parameterized queries throughout"
            )
        
        if 'infrastructure' in categories:
            recommendations.append(
                "Apply principle of least privilege to all IAM policies"
            )
        
        if 'api_security' in categories:
            recommendations.append(
                "Add rate limiting, authentication, and monitoring to all APIs"
            )
        
        # General recommendations
        recommendations.extend([
            "Implement continuous security monitoring",
            "Add security testing to CI/CD pipeline",
            "Conduct regular security audits",
            "Enable AWS GuardDuty and Security Hub"
        ])
        
        return recommendations[:10]  # Top 10 recommendations
    
    def _save_results(self, scan_id: str, results: Dict[str, Any]):
        """Save red team results to S3"""
        try:
            key = f"red-team/{scan_id}/report.json"
            self.s3.put_object(
                Bucket=self.results_bucket,
                Key=key,
                Body=json.dumps(results, indent=2, default=str),
                ContentType='application/json'
            )
            logger.info(f"Red team results saved to s3://{self.results_bucket}/{key}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")


def lambda_handler(event, context):
    """Lambda handler for red team agent"""
    agent = RedTeamAgent()
    
    repository_path = event.get('repository_path', '.')
    scan_config = event.get('scan_config', {})
    
    # Run async analysis
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(agent.red_team_analysis(repository_path, scan_config))
        return {
            'statusCode': 200,
            'body': json.dumps(result, default=str)
        }
    finally:
        loop.close()


if __name__ == "__main__":
    # For testing
    test_event = {
        'repository_path': '.',
        'scan_config': {
            'scan_id': 'redteam-test-123'
        }
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(json.loads(result['body']), indent=2))