#!/usr/bin/env python3
"""
Autonomous Supply Chain Security Agent
Uses AWS Bedrock AI to analyze dependencies, third-party risks, and supply chain vulnerabilities
"""

import os
import json
import sys
import logging
import boto3
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple
from pathlib import Path
import hashlib
import re
import requests
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import semver

# Add the shared module to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))
from shared.strands import StrandsMessage, StrandsProtocol, MessageType, SecurityFinding

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AutonomousSupplyChainAgent:
    """AI-powered autonomous supply chain security analysis"""
    
    def __init__(self):
        self.bedrock = boto3.client('bedrock-runtime')
        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-opus-20240229-v1:0')
        self.results_bucket = os.environ.get('RESULTS_BUCKET')
        self.supply_chain_table = os.environ.get('SUPPLY_CHAIN_TABLE', 'SupplyChainIntelligence')
        self.max_workers = int(os.environ.get('MAX_WORKERS', '10'))
        
        # Package managers configuration
        self.package_managers = {
            'npm': {
                'file': 'package.json',
                'lock': 'package-lock.json',
                'registry': 'https://registry.npmjs.org'
            },
            'pip': {
                'file': 'requirements.txt',
                'lock': 'requirements.lock',
                'registry': 'https://pypi.org/pypi'
            },
            'maven': {
                'file': 'pom.xml',
                'lock': None,
                'registry': 'https://repo.maven.apache.org'
            },
            'gradle': {
                'file': 'build.gradle',
                'lock': 'gradle.lockfile',
                'registry': 'https://repo.maven.apache.org'
            },
            'composer': {
                'file': 'composer.json',
                'lock': 'composer.lock',
                'registry': 'https://packagist.org'
            },
            'cargo': {
                'file': 'Cargo.toml',
                'lock': 'Cargo.lock',
                'registry': 'https://crates.io'
            },
            'go': {
                'file': 'go.mod',
                'lock': 'go.sum',
                'registry': 'https://proxy.golang.org'
            },
            'gem': {
                'file': 'Gemfile',
                'lock': 'Gemfile.lock',
                'registry': 'https://rubygems.org'
            }
        }
        
    async def analyze(self, repository_path: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform autonomous supply chain security analysis"""
        scan_id = scan_config.get('scan_id', 'unknown')
        logger.info(f"Starting autonomous supply chain analysis for scan {scan_id}")
        
        findings = []
        supply_chain_metrics = {
            'total_dependencies': 0,
            'direct_dependencies': 0,
            'transitive_dependencies': 0,
            'vulnerable_dependencies': 0,
            'outdated_dependencies': 0,
            'license_risks': 0,
            'supply_chain_score': 100  # Start at 100, deduct for issues
        }
        
        # Discover all dependency files
        dependency_files = self._discover_dependency_files(repository_path)
        
        # Analyze each dependency ecosystem
        all_dependencies = {}
        for dep_file in dependency_files:
            deps = await self._extract_dependencies(dep_file)
            ecosystem = dep_file['type']
            if ecosystem not in all_dependencies:
                all_dependencies[ecosystem] = []
            all_dependencies[ecosystem].extend(deps)
            supply_chain_metrics['total_dependencies'] += len(deps)
        
        # Perform deep supply chain analysis
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            for ecosystem, deps in all_dependencies.items():
                # Analyze each dependency
                for dep in deps:
                    future = executor.submit(self._analyze_dependency, dep, ecosystem)
                    futures.append((dep, future))
            
            for dep, future in futures:
                try:
                    dep_findings, dep_risks = future.result()
                    findings.extend(dep_findings)
                    
                    # Update metrics
                    if dep_risks.get('vulnerable'):
                        supply_chain_metrics['vulnerable_dependencies'] += 1
                        supply_chain_metrics['supply_chain_score'] -= 5
                    if dep_risks.get('outdated'):
                        supply_chain_metrics['outdated_dependencies'] += 1
                        supply_chain_metrics['supply_chain_score'] -= 2
                    if dep_risks.get('license_risk'):
                        supply_chain_metrics['license_risks'] += 1
                        supply_chain_metrics['supply_chain_score'] -= 3
                        
                except Exception as e:
                    logger.error(f"Error analyzing dependency {dep.get('name')}: {e}")
        
        # Ensure score doesn't go below 0
        supply_chain_metrics['supply_chain_score'] = max(0, supply_chain_metrics['supply_chain_score'])
        
        # Analyze dependency graph for complex attacks
        attack_vectors = await self._analyze_attack_vectors(all_dependencies)
        findings.extend(attack_vectors)
        
        # Check for supply chain specific risks
        supply_chain_risks = await self._check_supply_chain_risks(all_dependencies, dependency_files)
        findings.extend(supply_chain_risks)
        
        # Generate AI-powered insights
        insights = await self._generate_supply_chain_insights(findings, supply_chain_metrics, all_dependencies)
        
        # Update supply chain intelligence database
        await self._update_supply_chain_intelligence(all_dependencies, findings)
        
        # Save results
        result = {
            'scan_id': scan_id,
            'agent': 'autonomous_supply_chain',
            'timestamp': datetime.utcnow().isoformat(),
            'findings': findings,
            'metrics': supply_chain_metrics,
            'dependencies': all_dependencies,
            'insights': insights
        }
        
        # Upload to S3
        self._save_results(scan_id, result)
        
        # Send Strands message
        self._send_strands_message(scan_id, findings, supply_chain_metrics)
        
        logger.info(f"Completed supply chain analysis: {len(findings)} findings")
        return result
    
    def _discover_dependency_files(self, repository_path: str) -> List[Dict[str, Any]]:
        """Discover all dependency management files"""
        dep_files = []
        
        for root, _, files in os.walk(repository_path):
            # Skip certain directories
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', 'venv']):
                continue
            
            for file in files:
                for pkg_type, config in self.package_managers.items():
                    if file == config['file'] or (config['lock'] and file == config['lock']):
                        dep_files.append({
                            'path': os.path.join(root, file),
                            'name': file,
                            'type': pkg_type,
                            'is_lock': file == config['lock']
                        })
        
        return dep_files
    
    async def _extract_dependencies(self, dep_file: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract dependencies from a dependency file"""
        dependencies = []
        
        try:
            with open(dep_file['path'], 'r', encoding='utf-8') as f:
                content = f.read()
            
            if dep_file['type'] == 'npm' and dep_file['name'] == 'package.json':
                data = json.loads(content)
                for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                    if dep_type in data:
                        for name, version in data[dep_type].items():
                            dependencies.append({
                                'name': name,
                                'version': version,
                                'type': dep_type,
                                'file': dep_file['path']
                            })
                            
            elif dep_file['type'] == 'pip' and dep_file['name'] == 'requirements.txt':
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Parse requirement
                        match = re.match(r'^([a-zA-Z0-9\-_\.]+)([>=<~!]+)?(.+)?$', line)
                        if match:
                            name = match.group(1)
                            version = match.group(3) if match.group(3) else '*'
                            dependencies.append({
                                'name': name,
                                'version': version,
                                'type': 'runtime',
                                'file': dep_file['path']
                            })
                            
            elif dep_file['type'] == 'maven' and dep_file['name'] == 'pom.xml':
                # Simple XML parsing for dependencies
                import xml.etree.ElementTree as ET
                root = ET.fromstring(content)
                for dep in root.findall('.//{http://maven.apache.org/POM/4.0.0}dependency'):
                    group_id = dep.find('{http://maven.apache.org/POM/4.0.0}groupId')
                    artifact_id = dep.find('{http://maven.apache.org/POM/4.0.0}artifactId')
                    version = dep.find('{http://maven.apache.org/POM/4.0.0}version')
                    
                    if group_id is not None and artifact_id is not None:
                        name = f"{group_id.text}:{artifact_id.text}"
                        dependencies.append({
                            'name': name,
                            'version': version.text if version is not None else 'latest',
                            'type': 'compile',
                            'file': dep_file['path']
                        })
                        
            # Add more package manager parsers as needed
            
        except Exception as e:
            logger.error(f"Error extracting dependencies from {dep_file['path']}: {e}")
        
        return dependencies
    
    def _analyze_dependency(self, dependency: Dict[str, Any], 
                          ecosystem: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Analyze a single dependency for security issues"""
        findings = []
        risks = {
            'vulnerable': False,
            'outdated': False,
            'license_risk': False,
            'malicious': False,
            'abandoned': False
        }
        
        dep_name = dependency.get('name')
        dep_version = dependency.get('version', 'unknown')
        
        # Use AI to analyze the dependency
        prompt = f"""Analyze this {ecosystem} dependency for supply chain security risks:

Dependency: {dep_name}
Version: {dep_version}
Ecosystem: {ecosystem}

Check for:
1. Known vulnerabilities (CVEs)
2. Whether it's significantly outdated
3. License compatibility issues (GPL, AGPL, etc.)
4. Signs of malicious code or typosquatting
5. Whether the project is abandoned or unmaintained
6. Suspicious version patterns
7. Unexpected dependencies or behaviors
8. Security advisories
9. Supply chain attack indicators
10. Alternative safer packages

For each issue found, provide:
- issue_type: vulnerability/outdated/license/malicious/abandoned/suspicious
- severity: critical/high/medium/low
- title: descriptive title
- description: detailed explanation
- cve_id: if applicable
- fixed_version: if available
- alternative_package: if recommended
- evidence: what indicates this issue
- impact: potential security impact
- remediation: how to fix

Also provide risk assessment:
- vulnerable: true/false
- outdated: true/false
- license_risk: true/false
- malicious: true/false
- abandoned: true/false

Format as JSON with 'issues' array and 'risk_assessment' object."""

        try:
            response = self.bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 3000,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            result = json.loads(response['body'].read())
            content = result['content'][0]['text']
            
            ai_analysis = json.loads(content)
            issues = ai_analysis.get('issues', [])
            risk_assessment = ai_analysis.get('risk_assessment', {})
            
            for issue in issues:
                finding = {
                    'type': f"supply_chain_{issue.get('issue_type', 'unknown')}",
                    'severity': issue.get('severity', 'medium'),
                    'title': issue.get('title', f'Supply chain issue in {dep_name}'),
                    'description': issue.get('description'),
                    'dependency_name': dep_name,
                    'dependency_version': dep_version,
                    'ecosystem': ecosystem,
                    'file_path': dependency.get('file'),
                    'cve_id': issue.get('cve_id'),
                    'fixed_version': issue.get('fixed_version'),
                    'alternative_package': issue.get('alternative_package'),
                    'agent': 'autonomous_supply_chain',
                    'finding_id': hashlib.sha256(
                        f"{dep_name}:{dep_version}:{issue.get('issue_type')}".encode()
                    ).hexdigest()[:12]
                }
                findings.append(finding)
            
            # Update risks
            risks.update(risk_assessment)
            
        except Exception as e:
            logger.error(f"Error analyzing dependency {dep_name}: {e}")
        
        return findings, risks
    
    async def _analyze_attack_vectors(self, all_dependencies: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Analyze potential supply chain attack vectors"""
        findings = []
        
        # Create dependency summary
        dep_summary = {}
        for ecosystem, deps in all_dependencies.items():
            dep_summary[ecosystem] = {
                'count': len(deps),
                'packages': [d['name'] for d in deps[:20]]  # Sample first 20
            }
        
        prompt = f"""As a supply chain security expert, analyze these dependencies for attack vectors:

Dependencies Overview:
{json.dumps(dep_summary, indent=2)}

Identify potential supply chain attack vectors:
1. Dependency confusion attacks
2. Typosquatting risks
3. Malicious package injection points
4. Transitive dependency attacks
5. Version pinning issues
6. Registry manipulation risks
7. Build-time attack surfaces
8. CI/CD pipeline vulnerabilities
9. Package substitution attacks
10. Upstream compromise scenarios

For each attack vector:
- vector_type: type of attack
- severity: critical/high/medium/low
- title: descriptive title
- description: how the attack would work
- affected_ecosystems: which package managers
- likelihood: low/medium/high
- impact: potential damage
- detection_difficulty: easy/medium/hard
- prevention: how to prevent this attack
- indicators: what to look for

Format as JSON with 'attack_vectors' array."""

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
            
            vectors = json.loads(content).get('attack_vectors', [])
            for vector in vectors:
                finding = {
                    'type': 'supply_chain_attack_vector',
                    'severity': vector.get('severity', 'medium'),
                    'title': vector.get('title'),
                    'description': vector.get('description'),
                    'attack_vector': vector.get('vector_type'),
                    'affected_ecosystems': vector.get('affected_ecosystems', []),
                    'likelihood': vector.get('likelihood'),
                    'prevention': vector.get('prevention'),
                    'agent': 'autonomous_supply_chain'
                }
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error analyzing attack vectors: {e}")
        
        return findings
    
    async def _check_supply_chain_risks(self, all_dependencies: Dict[str, List[Dict[str, Any]]], 
                                      dependency_files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for specific supply chain security risks"""
        findings = []
        
        # Check for missing lock files
        for ecosystem, deps in all_dependencies.items():
            if deps and ecosystem in self.package_managers:
                lock_file = self.package_managers[ecosystem]['lock']
                if lock_file:
                    has_lock = any(f['name'] == lock_file for f in dependency_files)
                    if not has_lock:
                        findings.append({
                            'type': 'missing_lock_file',
                            'severity': 'high',
                            'title': f'Missing {lock_file} for {ecosystem}',
                            'description': f'No lock file found for {ecosystem} dependencies. This can lead to inconsistent builds and supply chain attacks.',
                            'ecosystem': ecosystem,
                            'impact': 'Dependencies may resolve to different versions, potentially introducing vulnerabilities',
                            'fix': f'Generate {lock_file} and commit it to version control',
                            'agent': 'autonomous_supply_chain'
                        })
        
        # Check for unpinned versions
        for ecosystem, deps in all_dependencies.items():
            unpinned = [d for d in deps if d.get('version', '').startswith('^') or 
                       d.get('version', '').startswith('~') or 
                       d.get('version', '') == '*' or
                       d.get('version', '') == 'latest']
            
            if len(unpinned) > 5:
                findings.append({
                    'type': 'unpinned_dependencies',
                    'severity': 'medium',
                    'title': f'Multiple unpinned dependencies in {ecosystem}',
                    'description': f'Found {len(unpinned)} dependencies without exact version pins',
                    'ecosystem': ecosystem,
                    'affected_dependencies': [d['name'] for d in unpinned[:10]],
                    'impact': 'Builds may pull in untested or malicious versions',
                    'fix': 'Pin all dependencies to exact versions in lock files',
                    'agent': 'autonomous_supply_chain'
                })
        
        # Check for suspicious patterns
        all_dep_names = []
        for deps in all_dependencies.values():
            all_dep_names.extend([d['name'] for d in deps])
        
        # Look for typosquatting patterns
        suspicious_patterns = await self._detect_typosquatting(all_dep_names)
        findings.extend(suspicious_patterns)
        
        return findings
    
    async def _detect_typosquatting(self, dep_names: List[str]) -> List[Dict[str, Any]]:
        """Detect potential typosquatting in dependencies"""
        findings = []
        
        # Common package names that are often typosquatted
        common_targets = [
            'react', 'angular', 'vue', 'express', 'lodash', 'jquery',
            'bootstrap', 'axios', 'webpack', 'babel', 'eslint', 'jest',
            'requests', 'numpy', 'pandas', 'tensorflow', 'django', 'flask'
        ]
        
        for dep in dep_names:
            dep_lower = dep.lower()
            
            # Check for suspicious similarities
            for target in common_targets:
                # Simple Levenshtein distance check
                if dep_lower != target and len(dep_lower) > 3:
                    # Check for common typosquatting patterns
                    if (dep_lower.replace('-', '') == target or
                        dep_lower.replace('_', '') == target or
                        dep_lower.replace('js', '') == target or
                        dep_lower.replace('py', '') == target or
                        dep_lower.startswith(target + '-') or
                        dep_lower.endswith('-' + target)):
                        
                        findings.append({
                            'type': 'potential_typosquatting',
                            'severity': 'high',
                            'title': f'Potential typosquatting: {dep}',
                            'description': f'Package "{dep}" is suspiciously similar to popular package "{target}"',
                            'suspicious_package': dep,
                            'legitimate_package': target,
                            'impact': 'Could be a malicious package masquerading as a popular library',
                            'fix': f'Verify this is the correct package. Consider using "{target}" instead',
                            'agent': 'autonomous_supply_chain'
                        })
        
        return findings
    
    async def _generate_supply_chain_insights(self, findings: List[Dict[str, Any]], 
                                            metrics: Dict[str, Any],
                                            all_dependencies: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Generate supply chain security insights using AI"""
        # Summarize findings
        summary = {
            'total_findings': len(findings),
            'by_severity': {},
            'by_type': {},
            'by_ecosystem': {}
        }
        
        for finding in findings:
            severity = finding.get('severity', 'unknown')
            finding_type = finding.get('type', 'unknown')
            ecosystem = finding.get('ecosystem', 'general')
            
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            summary['by_type'][finding_type] = summary['by_type'].get(finding_type, 0) + 1
            summary['by_ecosystem'][ecosystem] = summary['by_ecosystem'].get(ecosystem, 0) + 1
        
        # Count dependencies by ecosystem
        dep_counts = {eco: len(deps) for eco, deps in all_dependencies.items()}
        
        prompt = f"""Based on this supply chain security analysis, provide strategic insights:

Findings Summary: {json.dumps(summary, indent=2)}
Supply Chain Metrics: {json.dumps(metrics, indent=2)}
Dependencies by Ecosystem: {json.dumps(dep_counts, indent=2)}

Critical Issues:
{json.dumps([f for f in findings if f.get('severity') == 'critical'][:5], indent=2)}

Provide:
1. Overall supply chain security assessment
2. Most critical supply chain risks
3. Dependency management maturity level (1-5)
4. Third-party risk exposure level
5. Recommended immediate actions
6. Long-term supply chain security strategy
7. Estimated effort to remediate (hours)
8. Business risk assessment
9. Compliance implications (SBOM requirements, etc.)

Format as JSON with comprehensive insights."""

        try:
            response = self.bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 2500,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            result = json.loads(response['body'].read())
            content = result['content'][0]['text']
            insights = json.loads(content)
            insights['summary'] = summary
            insights['dependency_counts'] = dep_counts
            
            return insights
        except Exception as e:
            logger.error(f"Error generating insights: {e}")
            return {'summary': summary}
    
    async def _update_supply_chain_intelligence(self, all_dependencies: Dict[str, List[Dict[str, Any]]], 
                                              findings: List[Dict[str, Any]]):
        """Update supply chain intelligence database"""
        try:
            table = self.dynamodb.Table(self.supply_chain_table)
            
            # Store dependency information
            for ecosystem, deps in all_dependencies.items():
                for dep in deps[:100]:  # Limit to prevent excessive storage
                    item = {
                        'dep_id': hashlib.sha256(f"{ecosystem}:{dep['name']}:{dep['version']}".encode()).hexdigest()[:12],
                        'ecosystem': ecosystem,
                        'name': dep['name'],
                        'version': dep['version'],
                        'last_seen': datetime.utcnow().isoformat(),
                        'ttl': int((datetime.utcnow() + timedelta(days=180)).timestamp())
                    }
                    table.put_item(Item=item)
            
            # Store high-severity findings
            for finding in [f for f in findings if f.get('severity') in ['critical', 'high']]:
                item = {
                    'finding_id': finding.get('finding_id', hashlib.sha256(json.dumps(finding).encode()).hexdigest()[:12]),
                    'type': 'supply_chain_finding',
                    'data': finding,
                    'updated_at': datetime.utcnow().isoformat(),
                    'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())
                }
                table.put_item(Item=item)
                
        except Exception as e:
            logger.error(f"Error updating supply chain intelligence: {e}")
    
    def _save_results(self, scan_id: str, results: Dict[str, Any]):
        """Save results to S3"""
        try:
            key = f"raw/{scan_id}/autonomous_supply_chain/results.json"
            self.s3.put_object(
                Bucket=self.results_bucket,
                Key=key,
                Body=json.dumps(results, indent=2),
                ContentType='application/json'
            )
            logger.info(f"Saved results to s3://{self.results_bucket}/{key}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def _send_strands_message(self, scan_id: str, findings: List[Dict[str, Any]], 
                            metrics: Dict[str, Any]):
        """Send supply chain findings via Strands protocol"""
        try:
            # Prioritize critical supply chain issues
            critical_findings = [f for f in findings if f.get('severity') in ['critical', 'high']]
            
            message = StrandsMessage(
                type=MessageType.FINDING,
                source="autonomous_supply_chain",
                scan_id=scan_id,
                timestamp=datetime.utcnow().isoformat(),
                data={
                    'supply_chain_summary': {
                        'total_dependencies': metrics['total_dependencies'],
                        'vulnerable_dependencies': metrics['vulnerable_dependencies'],
                        'supply_chain_score': metrics['supply_chain_score'],
                        'critical_findings': len(critical_findings)
                    },
                    'critical_issues': critical_findings[:5],
                    'metrics': metrics
                }
            )
            
            protocol = StrandsProtocol()
            protocol.send_message(message)
            logger.info("Sent supply chain analysis via Strands protocol")
        except Exception as e:
            logger.error(f"Error sending Strands message: {e}")


def lambda_handler(event, context):
    """Lambda handler for autonomous supply chain agent"""
    agent = AutonomousSupplyChainAgent()
    
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
            'scan_id': 'test-123'
        }
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))