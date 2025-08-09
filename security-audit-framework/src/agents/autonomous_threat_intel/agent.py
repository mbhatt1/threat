#!/usr/bin/env python3
"""
Autonomous Threat Intelligence Agent
Uses AWS Bedrock AI to identify threats, analyze attack patterns, and predict potential exploits
"""

import os
import json
import sys
import logging
import boto3
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor
import hashlib
import re
from collections import defaultdict

# Add the shared module to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))
from shared.strands import StrandsMessage, StrandsProtocol, MessageType, SecurityFinding

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AutonomousThreatIntelAgent:
    """AI-powered autonomous threat intelligence analysis"""
    
    def __init__(self):
        self.bedrock = boto3.client('bedrock-runtime')
        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-opus-20240229-v1:0')
        self.results_bucket = os.environ.get('RESULTS_BUCKET')
        self.threat_db_table = os.environ.get('THREAT_DB_TABLE', 'ThreatIntelligence')
        
    async def analyze(self, repository_path: str, scan_config: Dict[str, Any], 
                     previous_findings: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform autonomous threat intelligence analysis"""
        scan_id = scan_config.get('scan_id', 'unknown')
        logger.info(f"Starting autonomous threat intelligence analysis for scan {scan_id}")
        
        # Initialize threat analysis results
        threat_analysis = {
            'active_threats': [],
            'potential_exploits': [],
            'attack_chains': [],
            'threat_actors': [],
            'risk_assessment': {},
            'recommendations': []
        }
        
        # Load threat intelligence database
        threat_intel = await self._load_threat_intelligence()
        
        # Analyze repository for threat indicators
        repo_analysis = await self._analyze_repository_threats(repository_path, threat_intel)
        
        # Correlate with previous findings if available
        if previous_findings:
            correlation_results = await self._correlate_findings(previous_findings, threat_intel)
            threat_analysis['active_threats'].extend(correlation_results.get('threats', []))
        
        # Identify potential attack chains
        attack_chains = await self._identify_attack_chains(repo_analysis, previous_findings or [])
        threat_analysis['attack_chains'] = attack_chains
        
        # Predict potential exploits using AI
        exploit_predictions = await self._predict_exploits(repo_analysis, attack_chains)
        threat_analysis['potential_exploits'] = exploit_predictions
        
        # Identify threat actors
        threat_actors = await self._identify_threat_actors(repo_analysis, threat_intel)
        threat_analysis['threat_actors'] = threat_actors
        
        # Generate risk assessment
        risk_assessment = await self._generate_risk_assessment(threat_analysis)
        threat_analysis['risk_assessment'] = risk_assessment
        
        # Generate AI-powered recommendations
        recommendations = await self._generate_recommendations(threat_analysis)
        threat_analysis['recommendations'] = recommendations
        
        # Update threat intelligence database
        await self._update_threat_intelligence(threat_analysis)
        
        # Prepare final result
        result = {
            'scan_id': scan_id,
            'agent': 'autonomous_threat_intel',
            'timestamp': datetime.utcnow().isoformat(),
            'threat_analysis': threat_analysis,
            'metrics': {
                'active_threats': len(threat_analysis['active_threats']),
                'potential_exploits': len(threat_analysis['potential_exploits']),
                'attack_chains': len(threat_analysis['attack_chains']),
                'overall_risk_score': risk_assessment.get('overall_score', 0)
            }
        }
        
        # Save results
        self._save_results(scan_id, result)
        
        # Send Strands message
        self._send_strands_message(scan_id, threat_analysis)
        
        logger.info(f"Completed threat intelligence analysis: {len(threat_analysis['active_threats'])} active threats")
        return result
    
    async def _load_threat_intelligence(self) -> Dict[str, Any]:
        """Load threat intelligence from database"""
        try:
            table = self.dynamodb.Table(self.threat_db_table)
            
            # Query recent threat intelligence
            response = table.scan(
                FilterExpression='updated_at > :date',
                ExpressionAttributeValues={
                    ':date': (datetime.utcnow() - timedelta(days=30)).isoformat()
                }
            )
            
            threat_intel = {
                'vulnerabilities': [],
                'exploits': [],
                'indicators': [],
                'tactics': []
            }
            
            for item in response.get('Items', []):
                threat_type = item.get('type')
                if threat_type in threat_intel:
                    threat_intel[threat_type].append(item)
            
            return threat_intel
            
        except Exception as e:
            logger.error(f"Error loading threat intelligence: {e}")
            return {'vulnerabilities': [], 'exploits': [], 'indicators': [], 'tactics': []}
    
    async def _analyze_repository_threats(self, repository_path: str, 
                                        threat_intel: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze repository for threat indicators"""
        analysis = {
            'suspicious_patterns': [],
            'vulnerable_components': [],
            'threat_indicators': [],
            'security_misconfigurations': []
        }
        
        # Scan for suspicious file patterns
        suspicious_files = await self._scan_suspicious_files(repository_path)
        
        # Analyze each suspicious file with AI
        for file_info in suspicious_files:
            file_path = file_info['path']
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()[:10000]  # Limit content size
                
                # Use AI to analyze for threats
                prompt = f"""You are a cybersecurity threat analyst. Analyze this file for security threats:

File: {file_path}
File Type: {file_info.get('type', 'unknown')}
Known Threat Indicators: {json.dumps(threat_intel.get('indicators', [])[:10])}

Content:
```
{content}
```

Identify:
1. Suspicious code patterns that could be malicious
2. Backdoors or hidden functionality
3. Data exfiltration attempts
4. Command injection possibilities
5. Known exploit patterns
6. Crypto mining code
7. Obfuscated or encoded malicious content
8. Suspicious network connections
9. Privilege escalation attempts
10. Supply chain attack indicators

For each threat found, provide:
- threat_type: type of threat
- severity: critical/high/medium/low
- confidence: 0-100
- description: detailed explanation
- indicators: specific code/patterns that indicate the threat
- potential_impact: what could happen if exploited
- mitigation: how to fix or mitigate

Format as JSON with 'threats' array."""

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
                
                try:
                    ai_threats = json.loads(content)
                    for threat in ai_threats.get('threats', []):
                        threat['file_path'] = file_path
                        threat['agent'] = 'autonomous_threat_intel'
                        analysis['suspicious_patterns'].append(threat)
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse AI response for {file_path}")
                    
            except Exception as e:
                logger.error(f"Error analyzing file {file_path}: {e}")
        
        # Analyze for vulnerable components
        components = await self._identify_components(repository_path)
        vulnerable_components = await self._check_vulnerable_components(components, threat_intel)
        analysis['vulnerable_components'] = vulnerable_components
        
        return analysis
    
    async def _scan_suspicious_files(self, repository_path: str) -> List[Dict[str, Any]]:
        """Scan for potentially suspicious files"""
        suspicious_patterns = [
            # Backdoor patterns
            (r'.*\.(php|asp|jsp)\..*', 'double_extension'),
            (r'.*shell.*\.(php|py|sh|ps1)', 'shell_script'),
            (r'.*backdoor.*', 'backdoor_name'),
            
            # Hidden files
            (r'\.[^/]+\.(php|py|js|exe)', 'hidden_executable'),
            
            # Suspicious scripts
            (r'.*exploit.*', 'exploit_name'),
            (r'.*payload.*', 'payload_name'),
            (r'.*malware.*', 'malware_name'),
            
            # Encoded/obfuscated
            (r'.*\.(enc|encrypted|b64)', 'encrypted_file'),
            
            # Suspicious configs
            (r'.*(shadow|passwd|htpasswd).*', 'credential_file'),
            (r'.*\.(key|pem|pfx|p12)$', 'private_key'),
        ]
        
        suspicious_files = []
        
        for root, dirs, files in os.walk(repository_path):
            # Skip common safe directories
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__']):
                continue
                
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, repository_path)
                
                for pattern, threat_type in suspicious_patterns:
                    if re.match(pattern, relative_path, re.IGNORECASE):
                        suspicious_files.append({
                            'path': file_path,
                            'relative_path': relative_path,
                            'type': threat_type,
                            'pattern': pattern
                        })
                        break
        
        return suspicious_files
    
    async def _identify_components(self, repository_path: str) -> List[Dict[str, Any]]:
        """Identify software components and dependencies"""
        components = []
        
        # Check for package files
        package_files = {
            'package.json': 'npm',
            'requirements.txt': 'pip',
            'Gemfile': 'gem',
            'pom.xml': 'maven',
            'build.gradle': 'gradle',
            'composer.json': 'composer',
            'Cargo.toml': 'cargo',
            'go.mod': 'go'
        }
        
        for root, _, files in os.walk(repository_path):
            for file in files:
                if file in package_files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                        
                        components.append({
                            'type': package_files[file],
                            'file': file_path,
                            'content': content
                        })
                    except Exception as e:
                        logger.error(f"Error reading {file_path}: {e}")
        
        return components
    
    async def _check_vulnerable_components(self, components: List[Dict[str, Any]], 
                                         threat_intel: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check components against known vulnerabilities"""
        vulnerable = []
        
        for component in components:
            prompt = f"""Analyze these dependencies for known vulnerabilities:

Package Type: {component['type']}
Content:
```
{component['content'][:2000]}
```

Known Vulnerabilities Database Sample:
{json.dumps(threat_intel.get('vulnerabilities', [])[:5])}

For each vulnerable dependency found:
1. Identify the package name and version
2. List known CVEs if any
3. Assess the severity
4. Explain the vulnerability
5. Suggest a safe version

Format as JSON with 'vulnerabilities' array."""

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
                
                vulns = json.loads(content).get('vulnerabilities', [])
                for vuln in vulns:
                    vuln['component_file'] = component['file']
                    vuln['component_type'] = component['type']
                vulnerable.extend(vulns)
                
            except Exception as e:
                logger.error(f"Error checking vulnerabilities: {e}")
        
        return vulnerable
    
    async def _correlate_findings(self, previous_findings: List[Dict[str, Any]], 
                                threat_intel: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate findings with threat intelligence"""
        correlated = {
            'threats': [],
            'patterns': []
        }
        
        # Group findings by type
        findings_by_type = defaultdict(list)
        for finding in previous_findings:
            findings_by_type[finding.get('type', 'unknown')].append(finding)
        
        # Use AI to correlate
        prompt = f"""As a threat intelligence analyst, correlate these security findings with known threats:

Security Findings Summary:
{json.dumps({k: len(v) for k, v in findings_by_type.items()})}

Sample Findings:
{json.dumps(previous_findings[:10], indent=2)}

Known Threat Intelligence:
- Exploits: {len(threat_intel.get('exploits', []))}
- Indicators: {len(threat_intel.get('indicators', []))}
- Tactics: {len(threat_intel.get('tactics', []))}

Identify:
1. Which findings indicate active threats
2. Attack patterns across multiple findings
3. Indicators of compromise (IoCs)
4. Potential threat actor TTPs (Tactics, Techniques, Procedures)
5. Risk of exploitation

Format as JSON with 'active_threats' and 'attack_patterns' arrays."""

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
            
            correlation = json.loads(content)
            correlated['threats'] = correlation.get('active_threats', [])
            correlated['patterns'] = correlation.get('attack_patterns', [])
            
        except Exception as e:
            logger.error(f"Error correlating findings: {e}")
        
        return correlated
    
    async def _identify_attack_chains(self, repo_analysis: Dict[str, Any], 
                                    previous_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potential attack chains"""
        # Combine all security issues
        all_issues = []
        all_issues.extend(repo_analysis.get('suspicious_patterns', []))
        all_issues.extend(repo_analysis.get('vulnerable_components', []))
        all_issues.extend(previous_findings)
        
        if not all_issues:
            return []
        
        # Use AI to identify attack chains
        prompt = f"""As a security expert, identify possible attack chains from these vulnerabilities:

Vulnerabilities and Issues:
{json.dumps(all_issues[:20], indent=2)}

For each attack chain:
1. List the sequence of steps an attacker would take
2. Identify required vulnerabilities for each step
3. Assess the likelihood of success
4. Estimate the potential impact
5. Determine the skill level required

Consider:
- Initial access vectors
- Privilege escalation paths
- Lateral movement possibilities
- Data exfiltration methods
- Persistence mechanisms

Format as JSON with 'attack_chains' array, each containing:
- name: descriptive name
- steps: array of attack steps
- vulnerabilities_used: list of vulns used
- likelihood: low/medium/high
- impact: low/medium/high/critical
- skill_required: low/medium/high
- mitigation_priority: 1-10"""

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
            
            attack_chains = json.loads(content).get('attack_chains', [])
            return attack_chains
            
        except Exception as e:
            logger.error(f"Error identifying attack chains: {e}")
            return []
    
    async def _predict_exploits(self, repo_analysis: Dict[str, Any], 
                              attack_chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict potential future exploits using AI"""
        prompt = f"""As a threat researcher, predict potential exploits based on the current security state:

Identified Vulnerabilities:
{json.dumps(repo_analysis.get('vulnerable_components', [])[:10])}

Attack Chains:
{json.dumps(attack_chains[:5])}

Predict:
1. Which vulnerabilities are most likely to be exploited
2. New exploit techniques that could emerge
3. Zero-day possibilities based on code patterns
4. Supply chain attack vectors
5. Time to exploitation estimates

For each prediction provide:
- exploit_type: type of exploit
- target_vulnerability: which vuln it targets
- probability: 0-100
- time_to_exploit: estimated days
- sophistication: low/medium/high
- potential_damage: description
- detection_difficulty: easy/medium/hard
- prevention_measures: list of measures

Format as JSON with 'predictions' array."""

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
            
            predictions = json.loads(content).get('predictions', [])
            return predictions
            
        except Exception as e:
            logger.error(f"Error predicting exploits: {e}")
            return []
    
    async def _identify_threat_actors(self, repo_analysis: Dict[str, Any], 
                                    threat_intel: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify potential threat actors based on patterns"""
        prompt = f"""Based on the security analysis, identify potential threat actors:

Suspicious Patterns Found:
{json.dumps(repo_analysis.get('suspicious_patterns', [])[:10])}

Known Threat Actor Tactics:
{json.dumps(threat_intel.get('tactics', [])[:5])}

Identify:
1. Threat actor groups that might target this system
2. Their typical tactics, techniques, and procedures (TTPs)
3. Motivation (financial, espionage, hacktivism, etc.)
4. Sophistication level
5. Geographic origin if identifiable

For each threat actor:
- name: actor name or designation
- type: nation-state/criminal/hacktivist/insider
- motivation: primary motivation
- sophistication: low/medium/high/advanced
- ttps: list of tactics
- indicators: what suggests their involvement
- likelihood: probability they would target this system

Format as JSON with 'threat_actors' array."""

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
            
            threat_actors = json.loads(content).get('threat_actors', [])
            return threat_actors
            
        except Exception as e:
            logger.error(f"Error identifying threat actors: {e}")
            return []
    
    async def _generate_risk_assessment(self, threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive risk assessment"""
        prompt = f"""Generate a comprehensive security risk assessment based on:

Active Threats: {len(threat_analysis['active_threats'])}
Potential Exploits: {len(threat_analysis['potential_exploits'])}
Attack Chains: {len(threat_analysis['attack_chains'])}
Threat Actors: {len(threat_analysis['threat_actors'])}

Sample Data:
- Top Threats: {json.dumps(threat_analysis['active_threats'][:3])}
- Critical Attack Chains: {json.dumps(threat_analysis['attack_chains'][:2])}

Provide:
1. Overall risk score (0-100)
2. Risk level (low/medium/high/critical)
3. Immediate threats requiring action
4. Long-term security concerns
5. Business impact assessment
6. Compliance implications
7. Remediation timeline recommendations

Format as JSON with detailed risk breakdown."""

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
            
            risk_assessment = json.loads(content)
            return risk_assessment
            
        except Exception as e:
            logger.error(f"Error generating risk assessment: {e}")
            return {'overall_score': 0, 'risk_level': 'unknown'}
    
    async def _generate_recommendations(self, threat_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate AI-powered security recommendations"""
        prompt = f"""Based on the threat analysis, provide actionable security recommendations:

Risk Assessment: {json.dumps(threat_analysis['risk_assessment'])}
Active Threats: {len(threat_analysis['active_threats'])}
Attack Chains: {len(threat_analysis['attack_chains'])}

Provide prioritized recommendations:
1. Immediate actions (within 24 hours)
2. Short-term fixes (within 1 week)
3. Long-term improvements (within 1 month)
4. Strategic security enhancements

For each recommendation:
- priority: critical/high/medium/low
- timeframe: immediate/short/long
- action: specific action to take
- rationale: why this is important
- effort: hours estimated
- cost: estimated cost if applicable
- effectiveness: how much it reduces risk (percentage)

Format as JSON with 'recommendations' array."""

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
            
            recommendations = json.loads(content).get('recommendations', [])
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return []
    
    async def _update_threat_intelligence(self, threat_analysis: Dict[str, Any]):
        """Update threat intelligence database with new findings"""
        try:
            table = self.dynamodb.Table(self.threat_db_table)
            
            # Store new threats
            for threat in threat_analysis['active_threats']:
                item = {
                    'threat_id': hashlib.sha256(json.dumps(threat).encode()).hexdigest()[:12],
                    'type': 'threat',
                    'data': threat,
                    'updated_at': datetime.utcnow().isoformat(),
                    'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())
                }
                table.put_item(Item=item)
            
            # Store new exploits
            for exploit in threat_analysis['potential_exploits']:
                item = {
                    'threat_id': hashlib.sha256(json.dumps(exploit).encode()).hexdigest()[:12],
                    'type': 'exploit',
                    'data': exploit,
                    'updated_at': datetime.utcnow().isoformat(),
                    'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())
                }
                table.put_item(Item=item)
                
        except Exception as e:
            logger.error(f"Error updating threat intelligence: {e}")
    
    def _save_results(self, scan_id: str, results: Dict[str, Any]):
        """Save results to S3"""
        try:
            key = f"raw/{scan_id}/autonomous_threat_intel/results.json"
            self.s3.put_object(
                Bucket=self.results_bucket,
                Key=key,
                Body=json.dumps(results, indent=2),
                ContentType='application/json'
            )
            logger.info(f"Saved results to s3://{self.results_bucket}/{key}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def _send_strands_message(self, scan_id: str, threat_analysis: Dict[str, Any]):
        """Send threat intelligence via Strands protocol"""
        try:
            # Create critical findings for immediate attention
            critical_findings = []
            
            # Add high-risk threats
            for threat in threat_analysis['active_threats']:
                if threat.get('severity') in ['critical', 'high']:
                    critical_findings.append({
                        'type': 'active_threat',
                        'severity': threat.get('severity'),
                        'title': threat.get('description', 'Active Threat Detected'),
                        'details': threat
                    })
            
            # Add high-probability exploits
            for exploit in threat_analysis['potential_exploits']:
                if exploit.get('probability', 0) > 75:
                    critical_findings.append({
                        'type': 'potential_exploit',
                        'severity': 'high',
                        'title': f"High probability exploit: {exploit.get('exploit_type')}",
                        'details': exploit
                    })
            
            message = StrandsMessage(
                type=MessageType.FINDING,
                source="autonomous_threat_intel",
                scan_id=scan_id,
                timestamp=datetime.utcnow().isoformat(),
                data={
                    'threat_summary': {
                        'active_threats': len(threat_analysis['active_threats']),
                        'potential_exploits': len(threat_analysis['potential_exploits']),
                        'attack_chains': len(threat_analysis['attack_chains']),
                        'overall_risk': threat_analysis['risk_assessment'].get('overall_score', 0)
                    },
                    'critical_findings': critical_findings,
                    'recommendations': threat_analysis['recommendations'][:5]  # Top 5 recommendations
                }
            )
            
            protocol = StrandsProtocol()
            protocol.send_message(message)
            logger.info("Sent threat intelligence via Strands protocol")
        except Exception as e:
            logger.error(f"Error sending Strands message: {e}")


def lambda_handler(event, context):
    """Lambda handler for autonomous threat intelligence agent"""
    agent = AutonomousThreatIntelAgent()
    
    repository_path = event.get('repository_path', '/mnt/efs/repos/current')
    scan_config = event.get('scan_config', {})
    previous_findings = event.get('previous_findings', [])
    
    # Run async analysis
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(
            agent.analyze(repository_path, scan_config, previous_findings)
        )
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
        },
        'previous_findings': []
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))