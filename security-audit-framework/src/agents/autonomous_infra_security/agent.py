#!/usr/bin/env python3
"""
Autonomous Infrastructure Security Agent
Uses AWS Bedrock AI to analyze infrastructure configurations and identify security misconfigurations
"""

import os
import json
import sys
import logging
import boto3
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import yaml
import re
from concurrent.futures import ThreadPoolExecutor
import hashlib

# Add the shared module to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))
from shared.strands import StrandsMessage, StrandsProtocol, MessageType, SecurityFinding

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AutonomousInfraSecurityAgent:
    """AI-powered autonomous infrastructure security analysis"""
    
    def __init__(self):
        self.bedrock = boto3.client('bedrock-runtime')
        self.s3 = boto3.client('s3')
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
        self.results_bucket = os.environ.get('RESULTS_BUCKET')
        self.max_workers = int(os.environ.get('MAX_WORKERS', '15'))
        
        # Infrastructure file patterns
        self.infra_patterns = {
            'terraform': ['*.tf', '*.tfvars'],
            'cloudformation': ['*.yaml', '*.yml', '*.json'],
            'kubernetes': ['*.yaml', '*.yml'],
            'docker': ['Dockerfile*', 'docker-compose*.yml'],
            'ansible': ['*.yml', '*.yaml', 'playbook*.yml'],
            'helm': ['Chart.yaml', 'values.yaml'],
            'pulumi': ['Pulumi.yaml', '*.py', '*.ts', '*.go'],
            'cdk': ['cdk.json', '*.ts', '*.py'],
            'serverless': ['serverless.yml', 'serverless.yaml']
        }
        
    async def analyze(self, repository_path: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform autonomous infrastructure security analysis"""
        scan_id = scan_config.get('scan_id', 'unknown')
        logger.info(f"Starting autonomous infrastructure security analysis for scan {scan_id}")
        
        findings = []
        infra_metrics = {
            'total_configs': 0,
            'analyzed_configs': 0,
            'security_score': 100,  # Start at 100 and deduct
            'compliance_score': 100,
            'best_practices_score': 100
        }
        
        # Discover infrastructure configurations
        infra_files = self._discover_infra_files(repository_path)
        infra_metrics['total_configs'] = len(infra_files)
        
        # Analyze cloud provider usage
        cloud_analysis = await self._analyze_cloud_providers(infra_files)
        
        # Perform deep AI analysis on each configuration
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for file_info in infra_files:
                future = executor.submit(self._analyze_infra_file, file_info, cloud_analysis)
                futures.append((file_info, future))
            
            for file_info, future in futures:
                try:
                    file_findings, file_metrics = future.result()
                    findings.extend(file_findings)
                    infra_metrics['analyzed_configs'] += 1
                    
                    # Update scores (deduct points for issues)
                    infra_metrics['security_score'] -= file_metrics.get('security_deductions', 0)
                    infra_metrics['compliance_score'] -= file_metrics.get('compliance_deductions', 0)
                    infra_metrics['best_practices_score'] -= file_metrics.get('practice_deductions', 0)
                    
                except Exception as e:
                    logger.error(f"Error analyzing {file_info['path']}: {e}")
        
        # Ensure scores don't go below 0
        for key in ['security_score', 'compliance_score', 'best_practices_score']:
            infra_metrics[key] = max(0, infra_metrics[key])
        
        # Perform cross-configuration analysis
        cross_config_findings = await self._analyze_cross_configurations(infra_files, cloud_analysis)
        findings.extend(cross_config_findings)
        
        # Check for infrastructure drift
        drift_findings = await self._check_infrastructure_drift(infra_files)
        findings.extend(drift_findings)
        
        # Generate infrastructure insights
        insights = await self._generate_infra_insights(findings, infra_metrics, cloud_analysis)
        
        # Save results
        result = {
            'scan_id': scan_id,
            'agent': 'autonomous_infra_security',
            'timestamp': datetime.utcnow().isoformat(),
            'findings': findings,
            'metrics': infra_metrics,
            'cloud_analysis': cloud_analysis,
            'insights': insights
        }
        
        # Upload to S3
        self._save_results(scan_id, result)
        
        # Send Strands message
        self._send_strands_message(scan_id, findings)
        
        logger.info(f"Completed infrastructure analysis: {len(findings)} findings")
        return result
    
    def _discover_infra_files(self, repository_path: str) -> List[Dict[str, Any]]:
        """Discover infrastructure configuration files"""
        infra_files = []
        
        for root, dirs, files in os.walk(repository_path):
            # Skip certain directories
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', '.terraform']):
                continue
            
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repository_path)
                
                # Check against patterns
                for infra_type, patterns in self.infra_patterns.items():
                    for pattern in patterns:
                        if self._match_pattern(file, pattern):
                            infra_files.append({
                                'path': file_path,
                                'relative_path': relative_path,
                                'type': infra_type,
                                'name': file
                            })
                            break
        
        return infra_files
    
    def _match_pattern(self, filename: str, pattern: str) -> bool:
        """Match filename against pattern"""
        import fnmatch
        return fnmatch.fnmatch(filename, pattern)
    
    async def _analyze_cloud_providers(self, infra_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze which cloud providers are being used"""
        providers = {
            'aws': 0,
            'azure': 0,
            'gcp': 0,
            'multi_cloud': False,
            'on_premise': 0,
            'hybrid': False
        }
        
        # Patterns to identify cloud providers
        provider_patterns = {
            'aws': [r'aws_', r'AWS::', r'amazonaws\.com', r's3://', r'arn:aws'],
            'azure': [r'azurerm_', r'Microsoft\.', r'azure\.com', r'az '],
            'gcp': [r'google_', r'gcp_', r'googleapis\.com', r'gcr\.io']
        }
        
        for file_info in infra_files[:20]:  # Sample first 20 files
            try:
                with open(file_info['path'], 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for provider, patterns in provider_patterns.items():
                    if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                        providers[provider] += 1
            except:
                continue
        
        # Determine if multi-cloud or hybrid
        active_providers = sum(1 for p in ['aws', 'azure', 'gcp'] if providers[p] > 0)
        providers['multi_cloud'] = active_providers > 1
        providers['hybrid'] = active_providers > 0 and providers['on_premise'] > 0
        
        return providers
    
    def _analyze_infra_file(self, file_info: Dict[str, Any], 
                           cloud_analysis: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Analyze a single infrastructure file using AI"""
        findings = []
        metrics = {
            'security_deductions': 0,
            'compliance_deductions': 0,
            'practice_deductions': 0
        }
        
        try:
            with open(file_info['path'], 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if len(content) > 30000:  # Truncate very large files
                content = content[:30000] + "\n... [truncated]"
            
            # Create comprehensive prompt based on file type
            prompt = self._create_infra_prompt(file_info, content, cloud_analysis)
            
            response = self.bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 6000,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            result = json.loads(response['body'].read())
            content = result['content'][0]['text']
            
            # Parse AI response
            try:
                ai_analysis = json.loads(content)
                findings_list = ai_analysis.get('findings', [])
                
                for finding in findings_list:
                    finding['file_path'] = file_info['path']
                    finding['infra_type'] = file_info['type']
                    finding['agent'] = 'autonomous_infra_security'
                    finding['finding_id'] = hashlib.sha256(
                        f"{file_info['path']}:{finding.get('line_number', 0)}:{finding.get('title', '')}".encode()
                    ).hexdigest()[:12]
                    
                    # Update metrics based on severity
                    severity = finding.get('severity', 'low')
                    if severity == 'critical':
                        metrics['security_deductions'] += 10
                    elif severity == 'high':
                        metrics['security_deductions'] += 5
                    elif severity == 'medium':
                        metrics['security_deductions'] += 2
                    else:
                        metrics['security_deductions'] += 1
                    
                    # Check compliance issues
                    if 'compliance' in finding.get('type', '').lower():
                        metrics['compliance_deductions'] += 5
                    
                    # Check best practices
                    if 'practice' in finding.get('type', '').lower():
                        metrics['practice_deductions'] += 3
                
                findings.extend(findings_list)
                
            except json.JSONDecodeError:
                logger.error(f"Failed to parse AI response for {file_info['path']}")
                
        except Exception as e:
            logger.error(f"Error analyzing file {file_info['path']}: {e}")
        
        return findings, metrics
    
    def _create_infra_prompt(self, file_info: Dict[str, Any], content: str, 
                            cloud_analysis: Dict[str, Any]) -> str:
        """Create specialized prompt based on infrastructure type"""
        base_prompt = f"""You are an expert cloud security architect. Analyze this {file_info['type']} infrastructure configuration:

File: {file_info['path']}
Type: {file_info['type']}
Cloud Environment: {json.dumps(cloud_analysis)}

Configuration:
```
{content}
```

"""
        
        if file_info['type'] == 'terraform':
            specific_checks = """
Terraform-specific checks:
1. Hardcoded credentials or secrets
2. Overly permissive IAM policies
3. Unencrypted storage resources
4. Public exposure of resources
5. Missing security groups or NACLs
6. Default VPC usage
7. Missing resource tagging
8. Insecure remote state configuration
9. Provider version pinning
10. Module security issues
"""
        elif file_info['type'] == 'kubernetes':
            specific_checks = """
Kubernetes-specific checks:
1. Running containers as root
2. Missing resource limits
3. Privileged containers
4. Host network/PID/IPC usage
5. Insecure capabilities
6. Missing network policies
7. Default service accounts
8. Exposed dashboards
9. Missing RBAC controls
10. Insecure pod security policies
"""
        elif file_info['type'] == 'docker':
            specific_checks = """
Docker-specific checks:
1. Using latest tags
2. Running as root user
3. Exposed sensitive ports
4. Hardcoded secrets in ENV
5. Missing health checks
6. Insecure base images
7. Missing security scanning
8. Excessive privileges
9. Missing user creation
10. Cache poisoning risks
"""
        elif file_info['type'] == 'cloudformation':
            specific_checks = """
CloudFormation-specific checks:
1. Hardcoded credentials
2. Overly permissive IAM roles
3. Unencrypted resources
4. Public S3 buckets
5. Open security groups
6. Missing MFA requirements
7. Default parameter values
8. Missing stack policies
9. Insecure outputs
10. Resource drift potential
"""
        else:
            specific_checks = """
General infrastructure checks:
1. Security misconfigurations
2. Compliance violations
3. Best practice deviations
4. Hardcoded secrets
5. Overly permissive access
6. Missing encryption
7. Public exposure risks
8. Missing monitoring
9. Backup configurations
10. Disaster recovery setup
"""
        
        prompt = base_prompt + specific_checks + """

For each security issue found, provide:
- type: misconfiguration/vulnerability/compliance/practice
- severity: critical/high/medium/low
- title: descriptive title
- description: detailed explanation
- line_number: where found (if applicable)
- resource: affected resource name
- impact: security impact
- fix: specific remediation
- compliance_frameworks: affected frameworks (CIS, NIST, SOC2, etc.)
- cwe_id: if applicable
- references: links to documentation

Also check for:
- Least privilege violations
- Defense in depth failures
- Zero trust principles
- Supply chain risks
- Compliance requirements (HIPAA, PCI-DSS, SOC2, etc.)

Format as JSON with 'findings' array."""
        
        return prompt
    
    async def _analyze_cross_configurations(self, infra_files: List[Dict[str, Any]], 
                                          cloud_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze security issues across multiple configurations"""
        findings = []
        
        # Group files by type
        files_by_type = {}
        for file_info in infra_files:
            infra_type = file_info['type']
            if infra_type not in files_by_type:
                files_by_type[infra_type] = []
            files_by_type[infra_type].append(file_info)
        
        # Cross-configuration analysis
        prompt = f"""Analyze these infrastructure configurations for cross-cutting security concerns:

Infrastructure Overview:
- Total configs: {len(infra_files)}
- Types: {list(files_by_type.keys())}
- Cloud providers: {cloud_analysis}

Configuration files by type:
{json.dumps({k: [f['relative_path'] for f in v[:5]] for k, v in files_by_type.items()}, indent=2)}

Identify:
1. Inconsistent security configurations across files
2. Missing global security controls
3. Inter-service security gaps
4. Network segmentation issues
5. Cross-account/project security risks
6. Shared resource vulnerabilities
7. Missing centralized logging/monitoring
8. Inconsistent encryption standards
9. IAM/RBAC inconsistencies
10. Compliance gaps across services

For each finding provide the standard security finding format.
Focus on issues that span multiple configurations or represent systemic problems.

Format as JSON with 'findings' array."""

        try:
            response = self.bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4000,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            result = json.loads(response['body'].read())
            content = result['content'][0]['text']
            
            cross_findings = json.loads(content).get('findings', [])
            for finding in cross_findings:
                finding['agent'] = 'autonomous_infra_security'
                finding['analysis_type'] = 'cross_configuration'
            findings.extend(cross_findings)
            
        except Exception as e:
            logger.error(f"Error in cross-configuration analysis: {e}")
        
        return findings
    
    async def _check_infrastructure_drift(self, infra_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for potential infrastructure drift issues"""
        findings = []
        
        # Look for state files and lock files
        state_files = []
        lock_files = []
        
        for file_info in infra_files:
            if 'state' in file_info['name'].lower() or '.tfstate' in file_info['name']:
                state_files.append(file_info)
            elif 'lock' in file_info['name'].lower():
                lock_files.append(file_info)
        
        if state_files:
            findings.append({
                'type': 'infrastructure_drift',
                'severity': 'high',
                'title': 'Terraform state files found in repository',
                'description': 'Terraform state files contain sensitive information and should not be committed to version control',
                'files': [f['relative_path'] for f in state_files],
                'impact': 'Exposure of infrastructure secrets and potential for state conflicts',
                'fix': 'Use remote state backend (S3, Terraform Cloud, etc.) and add *.tfstate to .gitignore',
                'agent': 'autonomous_infra_security'
            })
        
        # Check for drift detection mechanisms
        has_drift_detection = any('drift' in f['name'].lower() or 'validate' in f['name'].lower() 
                                 for f in infra_files)
        
        if not has_drift_detection and len(infra_files) > 5:
            findings.append({
                'type': 'missing_control',
                'severity': 'medium',
                'title': 'No infrastructure drift detection mechanism found',
                'description': 'Large infrastructure without drift detection can lead to security misconfigurations',
                'impact': 'Undetected changes to infrastructure could introduce security vulnerabilities',
                'fix': 'Implement regular drift detection using tools like Terraform plan, AWS Config, or CloudFormation drift detection',
                'agent': 'autonomous_infra_security'
            })
        
        return findings
    
    async def _generate_infra_insights(self, findings: List[Dict[str, Any]], 
                                     metrics: Dict[str, Any], 
                                     cloud_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate infrastructure security insights using AI"""
        # Summarize findings
        summary = {
            'total': len(findings),
            'by_severity': {},
            'by_type': {},
            'by_infra_type': {}
        }
        
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            finding_type = finding.get('type', 'unknown')
            infra_type = finding.get('infra_type', 'unknown')
            
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            summary['by_type'][finding_type] = summary['by_type'].get(finding_type, 0) + 1
            summary['by_infra_type'][infra_type] = summary['by_infra_type'].get(infra_type, 0) + 1
        
        # Generate insights
        prompt = f"""Based on this infrastructure security analysis, provide strategic insights:

Findings Summary: {json.dumps(summary, indent=2)}
Infrastructure Metrics: {json.dumps(metrics, indent=2)}
Cloud Analysis: {json.dumps(cloud_analysis, indent=2)}

Top Issues:
{json.dumps([f for f in findings if f.get('severity') in ['critical', 'high']][:5], indent=2)}

Provide:
1. Overall infrastructure security posture assessment
2. Most critical areas needing attention
3. Compliance readiness (SOC2, HIPAA, PCI-DSS, etc.)
4. Cloud security best practices gaps
5. Recommended security architecture improvements
6. Estimated effort for remediation (hours)
7. Risk score (0-100, higher is riskier)
8. Maturity level (1-5)

Format as JSON with detailed insights."""

        try:
            response = self.bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 2000,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            result = json.loads(response['body'].read())
            content = result['content'][0]['text']
            insights = json.loads(content)
            insights['summary'] = summary
            
            return insights
        except Exception as e:
            logger.error(f"Error generating insights: {e}")
            return {'summary': summary}
    
    def _save_results(self, scan_id: str, results: Dict[str, Any]):
        """Save results to S3"""
        try:
            key = f"raw/{scan_id}/autonomous_infra_security/results.json"
            self.s3.put_object(
                Bucket=self.results_bucket,
                Key=key,
                Body=json.dumps(results, indent=2),
                ContentType='application/json'
            )
            logger.info(f"Saved results to s3://{self.results_bucket}/{key}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def _send_strands_message(self, scan_id: str, findings: List[Dict[str, Any]]):
        """Send findings via Strands protocol"""
        try:
            # Focus on critical infrastructure issues
            critical_findings = [f for f in findings if f.get('severity') in ['critical', 'high']]
            
            message = StrandsMessage(
                type=MessageType.FINDING,
                source="autonomous_infra_security",
                scan_id=scan_id,
                timestamp=datetime.utcnow().isoformat(),
                data={
                    'findings': findings,
                    'total_findings': len(findings),
                    'critical_count': len([f for f in findings if f.get('severity') == 'critical']),
                    'high_count': len([f for f in findings if f.get('severity') == 'high']),
                    'top_issues': critical_findings[:5]
                }
            )
            
            protocol = StrandsProtocol()
            protocol.send_message(message)
            logger.info(f"Sent Strands message with {len(findings)} infrastructure findings")
        except Exception as e:
            logger.error(f"Error sending Strands message: {e}")


def lambda_handler(event, context):
    """Lambda handler for autonomous infrastructure security agent"""
    agent = AutonomousInfraSecurityAgent()
    
    repository_path = event.get('repository_path', '/mnt/efs/repos/current')
    scan_config = event.get('scan_config', {})
    
    # Run async analysis
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(agent.analyze(repository_path, scan_config))
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }
    finally:
        loop.close()


if __name__ == "__main__":
    # For testing
    test_event = {
        'repository_path': '/tmp/test-repo',
        'scan_config': {
            'scan_id': 'test-123',
            'deep_analysis': True
        }
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))