"""
Autonomous Container Scanner Agent
Fully AI-powered container and infrastructure security analysis
"""

import os
import sys
import json
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import hashlib
from collections import defaultdict

# Add parent directories to path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import AI components
from shared.ai_orchestrator import AISecurityOrchestrator
from shared.ai_explainability import AIExplainabilityEngine
from shared.vulnerability_chains import VulnerabilityChainAnalyzer
from ai_models.pure_ai_detector import PureAIVulnerabilityDetector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AutonomousContainerScanner:
    """
    Fully AI-powered autonomous agent for container and infrastructure security
    Uses advanced AI models to detect:
    - Container vulnerabilities without predefined patterns
    - Complex multi-stage attack vectors
    - Zero-day vulnerabilities in container configurations
    - Supply chain attacks through AI reasoning
    - Runtime security issues through behavioral analysis
    """
    
    def __init__(self):
        # Initialize AI components
        self.ai_orchestrator = AISecurityOrchestrator()
        self.explainability = AIExplainabilityEngine()
        self.chain_analyzer = VulnerabilityChainAnalyzer()
        self.ai_detector = PureAIVulnerabilityDetector()
        
        # AI model context for container security
        self.container_context = {
            'domain': 'container_security',
            'analysis_depth': 'deep',
            'include_zero_days': True,
            'behavioral_analysis': True
        }
        
    async def analyze(self, repository_path: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform fully AI-powered container security analysis
        """
        scan_id = scan_config.get('scan_id', 'unknown')
        logger.info(f"Starting AI-powered container analysis for scan {scan_id}")
        
        analysis_results = {
            'scan_id': scan_id,
            'agent': 'autonomous_container_scanner',
            'analysis_type': 'fully_ai_powered',
            'started_at': datetime.utcnow().isoformat(),
            'findings': [],
            'ai_insights': {},
            'vulnerability_chains': [],
            'risk_assessment': {},
            'container_inventory': {}
        }
        
        try:
            # Phase 1: AI-powered artifact discovery
            container_artifacts = await self._ai_discover_artifacts(repository_path)
            analysis_results['container_inventory'] = container_artifacts
            
            # Phase 2: Deep AI analysis of Dockerfiles
            dockerfile_findings = await self._ai_analyze_dockerfiles(
                container_artifacts.get('dockerfiles', [])
            )
            analysis_results['findings'].extend(dockerfile_findings)
            
            # Phase 3: AI-powered container image analysis
            image_findings = await self._ai_analyze_images(
                container_artifacts.get('images', [])
            )
            analysis_results['findings'].extend(image_findings)
            
            # Phase 4: AI analysis of Kubernetes configurations
            k8s_findings = await self._ai_analyze_kubernetes(
                container_artifacts.get('kubernetes_manifests', [])
            )
            analysis_results['findings'].extend(k8s_findings)
            
            # Phase 5: AI-powered Infrastructure as Code analysis
            iac_findings = await self._ai_analyze_iac(
                container_artifacts.get('iac_files', [])
            )
            analysis_results['findings'].extend(iac_findings)
            
            # Phase 6: AI-driven supply chain analysis
            supply_chain_analysis = await self._ai_analyze_supply_chain(
                repository_path, container_artifacts
            )
            analysis_results['findings'].extend(supply_chain_analysis['findings'])
            analysis_results['ai_insights']['supply_chain'] = supply_chain_analysis['insights']
            
            # Phase 7: AI behavioral security analysis
            behavioral_findings = await self._ai_behavioral_analysis(
                repository_path, container_artifacts
            )
            analysis_results['findings'].extend(behavioral_findings)
            
            # Phase 8: AI vulnerability chain detection
            chain_analysis = await self._ai_analyze_attack_chains(
                analysis_results['findings']
            )
            analysis_results['vulnerability_chains'] = chain_analysis
            
            # Phase 9: AI risk assessment and prioritization
            risk_assessment = await self._ai_risk_assessment(
                analysis_results['findings'],
                chain_analysis
            )
            analysis_results['risk_assessment'] = risk_assessment
            
            # Phase 10: Generate AI insights and recommendations
            ai_insights = await self._generate_ai_insights(analysis_results)
            analysis_results['ai_insights'].update(ai_insights)
            
            analysis_results['completed_at'] = datetime.utcnow().isoformat()
            analysis_results['status'] = 'completed'
            
        except Exception as e:
            logger.error(f"AI container analysis failed: {e}")
            analysis_results['status'] = 'failed'
            analysis_results['error'] = str(e)
        
        return analysis_results
    
    async def _ai_discover_artifacts(self, repository_path: str) -> Dict[str, Any]:
        """Use AI to intelligently discover container-related artifacts"""
        
        artifacts = {
            'dockerfiles': [],
            'compose_files': [],
            'kubernetes_manifests': [],
            'helm_charts': [],
            'iac_files': [],
            'images': [],
            'ai_discovered': []
        }
        
        # AI-powered file analysis
        for root, dirs, files in os.walk(repository_path):
            # Skip obviously non-relevant directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__']]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Use AI to classify file type
                file_classification = await self._ai_classify_file(file_path)
                
                if file_classification['is_container_related']:
                    artifact_type = file_classification['artifact_type']
                    
                    if artifact_type == 'dockerfile':
                        artifacts['dockerfiles'].append(file_path)
                    elif artifact_type == 'compose':
                        artifacts['compose_files'].append(file_path)
                    elif artifact_type == 'kubernetes':
                        artifacts['kubernetes_manifests'].append(file_path)
                    elif artifact_type == 'helm':
                        artifacts['helm_charts'].append(file_path)
                    elif artifact_type == 'iac':
                        artifacts['iac_files'].append(file_path)
                    elif artifact_type == 'unknown_container':
                        artifacts['ai_discovered'].append({
                            'path': file_path,
                            'confidence': file_classification['confidence'],
                            'ai_reasoning': file_classification['reasoning']
                        })
                
                # Extract image references using AI
                if file_classification.get('contains_images'):
                    images = await self._ai_extract_images(file_path)
                    artifacts['images'].extend(images)
        
        return artifacts
    
    async def _ai_classify_file(self, file_path: str) -> Dict[str, Any]:
        """Use AI to classify if a file is container-related"""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(5000)  # Read first 5KB for classification
            
            # Prepare context for AI
            context = {
                'task': 'file_classification',
                'domain': 'container_security',
                'file_path': file_path,
                'file_name': os.path.basename(file_path)
            }
            
            # Use AI to analyze file
            ai_response = await self.ai_orchestrator.analyze(
                content=content,
                context=context,
                prompt="""
                Analyze this file and determine:
                1. Is it container/infrastructure related?
                2. What type of container artifact is it? (dockerfile, compose, kubernetes, helm, iac, etc.)
                3. Does it contain image references?
                4. Confidence level (0-1)
                5. Reasoning for classification
                
                Focus on actual content, not just filename.
                """
            )
            
            return ai_response
            
        except Exception as e:
            logger.debug(f"Could not classify {file_path}: {e}")
            return {
                'is_container_related': False,
                'confidence': 0
            }
    
    async def _ai_extract_images(self, file_path: str) -> List[str]:
        """Use AI to extract container image references"""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Use AI to extract images
            ai_response = await self.ai_orchestrator.analyze(
                content=content,
                context={'task': 'image_extraction'},
                prompt="Extract all container image references from this file. Include base images, service images, and any referenced images."
            )
            
            return ai_response.get('images', [])
            
        except Exception:
            return []
    
    async def _ai_analyze_dockerfiles(self, dockerfile_paths: List[str]) -> List[Dict[str, Any]]:
        """Use AI to analyze Dockerfiles for security issues"""
        
        findings = []
        
        for dockerfile_path in dockerfile_paths:
            try:
                with open(dockerfile_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Deep AI analysis
                context = {
                    'file_type': 'dockerfile',
                    'file_path': dockerfile_path,
                    'analysis_type': 'security_vulnerabilities'
                }
                
                # Use pure AI detector for comprehensive analysis
                ai_vulnerabilities = await self.ai_detector.detect_vulnerabilities(
                    content, context
                )
                
                for vuln in ai_vulnerabilities:
                    finding = {
                        'finding_id': vuln.vuln_id,
                        'finding_type': f"container_{vuln.vulnerability_type}",
                        'severity': vuln.severity,
                        'confidence': vuln.confidence,
                        'file_path': dockerfile_path,
                        'line_numbers': vuln.line_numbers,
                        'description': vuln.description,
                        'ai_reasoning': vuln.ai_reasoning,
                        'exploitation_scenario': vuln.exploitation_scenario,
                        'remediation': vuln.fix_recommendation,
                        'ai_detected': True,
                        'zero_day_potential': vuln.is_zero_day
                    }
                    findings.append(finding)
                
                # Additional AI analysis for container-specific issues
                container_analysis = await self._ai_container_specific_analysis(
                    content, dockerfile_path
                )
                findings.extend(container_analysis)
                
            except Exception as e:
                logger.error(f"AI analysis failed for {dockerfile_path}: {e}")
        
        return findings
    
    async def _ai_container_specific_analysis(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """AI analysis for container-specific security concerns"""
        
        findings = []
        
        # AI prompt for container-specific analysis
        ai_response = await self.ai_orchestrator.analyze(
            content=content,
            context={
                'analysis_focus': 'container_security',
                'file_path': file_path
            },
            prompt="""
            Perform deep security analysis focusing on:
            1. Container escape vulnerabilities
            2. Supply chain attacks through base images
            3. Secret exposure risks
            4. Runtime security configurations
            5. Resource abuse potential
            6. Network exposure risks
            7. Privilege escalation paths
            8. Container-to-host attack vectors
            
            Identify both known patterns and potential zero-day vulnerabilities.
            Consider attack chains and combined vulnerabilities.
            """
        )
        
        # Process AI findings
        for ai_finding in ai_response.get('findings', []):
            finding = {
                'finding_id': self._generate_finding_id(file_path, ai_finding),
                'finding_type': f"ai_container_{ai_finding['type']}",
                'severity': ai_finding['severity'],
                'confidence': ai_finding['confidence'],
                'file_path': file_path,
                'description': ai_finding['description'],
                'ai_reasoning': ai_finding['reasoning'],
                'attack_vector': ai_finding.get('attack_vector'),
                'remediation': ai_finding['remediation'],
                'ai_detected': True,
                'container_specific': True
            }
            findings.append(finding)
        
        return findings
    
    async def _ai_analyze_images(self, images: List[str]) -> List[Dict[str, Any]]:
        """AI-powered container image security analysis"""
        
        findings = []
        analyzed_images = set()
        
        for image in images:
            if image in analyzed_images:
                continue
            analyzed_images.add(image)
            
            # AI analysis of image security
            ai_response = await self.ai_orchestrator.analyze(
                content=image,
                context={
                    'analysis_type': 'container_image',
                    'check_supply_chain': True
                },
                prompt=f"""
                Analyze the security of container image: {image}
                
                Consider:
                1. Known vulnerabilities in the image or its base layers
                2. Supply chain risks (compromised base images, typosquatting)
                3. Outdated or end-of-life components
                4. Suspicious image sources or registries
                5. Missing security updates
                6. Potential backdoors or malicious packages
                7. Image signing and verification issues
                
                Provide detailed findings with severity and confidence scores.
                """
            )
            
            # Process image findings
            for ai_finding in ai_response.get('findings', []):
                finding = {
                    'finding_id': self._generate_finding_id(image, ai_finding),
                    'finding_type': f"image_{ai_finding['type']}",
                    'severity': ai_finding['severity'],
                    'confidence': ai_finding['confidence'],
                    'image': image,
                    'description': ai_finding['description'],
                    'ai_reasoning': ai_finding['reasoning'],
                    'supply_chain_risk': ai_finding.get('supply_chain_risk', False),
                    'remediation': ai_finding['remediation'],
                    'ai_detected': True
                }
                findings.append(finding)
        
        return findings
    
    async def _ai_analyze_kubernetes(self, k8s_paths: List[str]) -> List[Dict[str, Any]]:
        """AI-powered Kubernetes security analysis"""
        
        findings = []
        
        for k8s_path in k8s_paths:
            try:
                with open(k8s_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Deep AI analysis for Kubernetes
                ai_response = await self.ai_orchestrator.analyze(
                    content=content,
                    context={
                        'file_type': 'kubernetes_manifest',
                        'file_path': k8s_path
                    },
                    prompt="""
                    Perform comprehensive Kubernetes security analysis:
                    
                    1. RBAC misconfigurations and overly permissive roles
                    2. Network policy gaps and exposed services
                    3. Pod security policy violations
                    4. Secrets management issues
                    5. Resource limits and DoS potential
                    6. Admission controller bypasses
                    7. Service mesh security gaps
                    8. Multi-tenancy isolation issues
                    9. Supply chain attacks through init containers
                    10. Cluster takeover paths
                    
                    Identify both configuration issues and potential attack chains.
                    Consider Kubernetes-specific CVEs and zero-day patterns.
                    """
                )
                
                # Process Kubernetes findings
                for ai_finding in ai_response.get('findings', []):
                    finding = {
                        'finding_id': self._generate_finding_id(k8s_path, ai_finding),
                        'finding_type': f"k8s_{ai_finding['type']}",
                        'severity': ai_finding['severity'],
                        'confidence': ai_finding['confidence'],
                        'file_path': k8s_path,
                        'resource_type': ai_finding.get('resource_type'),
                        'resource_name': ai_finding.get('resource_name'),
                        'description': ai_finding['description'],
                        'ai_reasoning': ai_finding['reasoning'],
                        'attack_scenario': ai_finding.get('attack_scenario'),
                        'remediation': ai_finding['remediation'],
                        'ai_detected': True
                    }
                    findings.append(finding)
                
            except Exception as e:
                logger.error(f"AI K8s analysis failed for {k8s_path}: {e}")
        
        return findings
    
    async def _ai_analyze_iac(self, iac_paths: List[str]) -> List[Dict[str, Any]]:
        """AI-powered Infrastructure as Code security analysis"""
        
        findings = []
        
        for iac_path in iac_paths:
            try:
                with open(iac_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Detect IaC type
                iac_type = await self._ai_detect_iac_type(content, iac_path)
                
                # Deep AI analysis for IaC
                ai_response = await self.ai_orchestrator.analyze(
                    content=content,
                    context={
                        'file_type': iac_type,
                        'file_path': iac_path
                    },
                    prompt=f"""
                    Perform deep security analysis of this {iac_type} infrastructure code:
                    
                    1. Misconfigurations leading to security vulnerabilities
                    2. Overly permissive IAM policies and roles
                    3. Unencrypted data storage and transmission
                    4. Public exposure of resources
                    5. Missing security controls (WAF, GuardDuty, etc.)
                    6. Compliance violations (HIPAA, PCI-DSS, SOC2)
                    7. Cross-account access risks
                    8. Supply chain attacks through modules/providers
                    9. State file security issues
                    10. Drift detection and remediation gaps
                    
                    Consider cloud-specific security best practices and emerging threats.
                    Identify both obvious issues and subtle security gaps.
                    """
                )
                
                # Process IaC findings
                for ai_finding in ai_response.get('findings', []):
                    finding = {
                        'finding_id': self._generate_finding_id(iac_path, ai_finding),
                        'finding_type': f"iac_{ai_finding['type']}",
                        'severity': ai_finding['severity'],
                        'confidence': ai_finding['confidence'],
                        'file_path': iac_path,
                        'iac_type': iac_type,
                        'resource': ai_finding.get('affected_resource'),
                        'description': ai_finding['description'],
                        'ai_reasoning': ai_finding['reasoning'],
                        'compliance_impact': ai_finding.get('compliance_impact', []),
                        'remediation': ai_finding['remediation'],
                        'ai_detected': True
                    }
                    findings.append(finding)
                
            except Exception as e:
                logger.error(f"AI IaC analysis failed for {iac_path}: {e}")
        
        return findings
    
    async def _ai_detect_iac_type(self, content: str, file_path: str) -> str:
        """Use AI to detect Infrastructure as Code type"""
        
        ai_response = await self.ai_orchestrator.analyze(
            content=content[:1000],  # First 1KB
            context={'file_path': file_path},
            prompt="Identify the Infrastructure as Code type: Terraform, CloudFormation, Ansible, Pulumi, CDK, or other. Return just the type name."
        )
        
        return ai_response.get('iac_type', 'unknown')
    
    async def _ai_analyze_supply_chain(self, repository_path: str, artifacts: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered supply chain security analysis"""
        
        supply_chain_results = {
            'findings': [],
            'insights': {}
        }
        
        # Comprehensive supply chain analysis
        ai_response = await self.ai_orchestrator.analyze(
            content=json.dumps(artifacts, default=str),
            context={
                'repository_path': repository_path,
                'analysis_type': 'supply_chain_security'
            },
            prompt="""
            Perform comprehensive supply chain security analysis:
            
            1. Analyze all dependencies and their sources
            2. Identify potentially compromised or malicious packages
            3. Detect typosquatting attempts
            4. Check for outdated dependencies with known vulnerabilities
            5. Identify unsigned or unverified images/packages
            6. Detect dependency confusion attacks
            7. Analyze build pipeline security
            8. Check for secrets in dependency management files
            9. Identify risky third-party integrations
            10. Detect potential backdoors or suspicious patterns
            
            Consider the entire dependency tree and transitive dependencies.
            Look for subtle indicators of compromise.
            """
        )
        
        # Process supply chain findings
        for ai_finding in ai_response.get('findings', []):
            finding = {
                'finding_id': self._generate_finding_id('supply_chain', ai_finding),
                'finding_type': f"supply_chain_{ai_finding['type']}",
                'severity': ai_finding['severity'],
                'confidence': ai_finding['confidence'],
                'component': ai_finding.get('affected_component'),
                'description': ai_finding['description'],
                'ai_reasoning': ai_finding['reasoning'],
                'indicators_of_compromise': ai_finding.get('iocs', []),
                'remediation': ai_finding['remediation'],
                'ai_detected': True,
                'supply_chain': True
            }
            supply_chain_results['findings'].append(finding)
        
        # Extract insights
        supply_chain_results['insights'] = ai_response.get('insights', {})
        
        return supply_chain_results
    
    async def _ai_behavioral_analysis(self, repository_path: str, artifacts: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI-powered behavioral security analysis"""
        
        findings = []
        
        # Analyze runtime behavior patterns
        ai_response = await self.ai_orchestrator.analyze(
            content=json.dumps(artifacts, default=str),
            context={
                'repository_path': repository_path,
                'analysis_type': 'behavioral_security'
            },
            prompt="""
            Perform behavioral security analysis:
            
            1. Identify suspicious runtime behaviors
            2. Detect potential container escape patterns
            3. Analyze network communication patterns
            4. Identify data exfiltration risks
            5. Detect cryptocurrency mining indicators
            6. Identify persistence mechanisms
            7. Analyze resource consumption patterns
            8. Detect anti-analysis techniques
            9. Identify command and control patterns
            10. Analyze container-to-container attack paths
            
            Focus on behavioral patterns that indicate malicious activity.
            Consider both obvious and subtle indicators.
            """
        )
        
        # Process behavioral findings
        for ai_finding in ai_response.get('findings', []):
            finding = {
                'finding_id': self._generate_finding_id('behavioral', ai_finding),
                'finding_type': f"behavioral_{ai_finding['type']}",
                'severity': ai_finding['severity'],
                'confidence': ai_finding['confidence'],
                'behavior_pattern': ai_finding.get('pattern'),
                'description': ai_finding['description'],
                'ai_reasoning': ai_finding['reasoning'],
                'indicators': ai_finding.get('behavioral_indicators', []),
                'attack_timeline': ai_finding.get('attack_timeline'),
                'remediation': ai_finding['remediation'],
                'ai_detected': True,
                'behavioral_analysis': True
            }
            findings.append(finding)
        
        return findings
    
    async def _ai_analyze_attack_chains(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """AI-powered attack chain analysis"""
        
        # Use AI to identify complex attack chains
        ai_response = await self.ai_orchestrator.analyze(
            content=json.dumps(findings, default=str),
            context={'analysis_type': 'attack_chain_analysis'},
            prompt="""
            Analyze the findings to identify complex attack chains:
            
            1. Identify vulnerabilities that can be chained together
            2. Map out complete attack paths from initial access to impact
            3. Calculate combined severity when vulnerabilities are chained
            4. Identify pivot points and lateral movement opportunities
            5. Detect defense evasion chains
            6. Map privilege escalation paths
            7. Identify data exfiltration chains
            8. Detect persistence and backdoor chains
            9. Calculate probability of successful exploitation
            10. Prioritize chains by real-world impact
            
            Consider both technical and business impact.
            Focus on realistic attack scenarios.
            """
        )
        
        chains = []
        for chain in ai_response.get('attack_chains', []):
            chains.append({
                'chain_id': self._generate_finding_id('chain', chain),
                'name': chain['name'],
                'description': chain['description'],
                'vulnerabilities': chain['vulnerability_sequence'],
                'attack_path': chain['attack_path'],
                'combined_severity': chain['combined_severity'],
                'exploitation_probability': chain['exploitation_probability'],
                'business_impact': chain['business_impact'],
                'ai_reasoning': chain['reasoning'],
                'mitigation_strategy': chain['mitigation_strategy']
            })
        
        return chains
    
    async def _ai_risk_assessment(self, findings: List[Dict[str, Any]], chains: List[Dict[str, Any]]) -> Dict[str, Any]:
        """AI-powered risk assessment and prioritization"""
        
        # Comprehensive risk assessment
        ai_response = await self.ai_orchestrator.analyze(
            content=json.dumps({
                'findings': findings,
                'attack_chains': chains
            }, default=str),
            context={'analysis_type': 'risk_assessment'},
            prompt="""
            Perform comprehensive risk assessment:
            
            1. Calculate overall security posture score (0-100)
            2. Identify critical risks requiring immediate attention
            3. Assess business impact of identified vulnerabilities
            4. Consider threat actor capabilities and motivation
            5. Evaluate compensating controls
            6. Calculate risk scores for each finding
            7. Prioritize remediation efforts
            8. Identify quick wins vs long-term improvements
            9. Assess compliance and regulatory impact
            10. Provide executive summary of risks
            
            Consider both technical and business context.
            Provide actionable recommendations.
            """
        )
        
        return {
            'overall_risk_score': ai_response.get('risk_score', 0),
            'risk_level': ai_response.get('risk_level', 'unknown'),
            'critical_risks': ai_response.get('critical_risks', []),
            'prioritized_findings': ai_response.get('prioritized_findings', []),
            'business_impact': ai_response.get('business_impact', {}),
            'compliance_gaps': ai_response.get('compliance_gaps', []),
            'remediation_roadmap': ai_response.get('remediation_roadmap', []),
            'executive_summary': ai_response.get('executive_summary', ''),
            'ai_confidence': ai_response.get('confidence', 0)
        }
    
    async def _generate_ai_insights(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive AI insights"""
        
        # Generate deep insights
        ai_response = await self.ai_orchestrator.analyze(
            content=json.dumps(results, default=str),
            context={'analysis_type': 'insight_generation'},
            prompt="""
            Generate comprehensive security insights:
            
            1. Identify security patterns and trends
            2. Highlight unique or unusual vulnerabilities
            3. Provide strategic security recommendations
            4. Identify security architecture improvements
            5. Suggest security tooling enhancements
            6. Recommend security training areas
            7. Identify automation opportunities
            8. Provide industry-specific insights
            9. Suggest security metrics to track
            10. Provide forward-looking security guidance
            
            Focus on actionable insights that provide real value.
            Consider emerging threats and future risks.
            """
        )
        
        return {
            'patterns': ai_response.get('security_patterns', []),
            'trends': ai_response.get('security_trends', []),
            'unique_findings': ai_response.get('unique_findings', []),
            'strategic_recommendations': ai_response.get('strategic_recommendations', []),
            'architecture_improvements': ai_response.get('architecture_improvements', []),
            'metrics_recommendations': ai_response.get('metrics_recommendations', []),
            'emerging_threats': ai_response.get('emerging_threats', []),
            'ai_observations': ai_response.get('ai_observations', [])
        }
    
    def _generate_finding_id(self, identifier: str, finding_data: Any) -> str:
        """Generate unique finding ID"""
        
        data = f"{identifier}:{str(finding_data)}"
        return hashlib.md5(data.encode()).hexdigest()[:16]
    
    def _extract_component(self, finding: Dict[str, Any]) -> str:
        """Extract component identifier from finding"""
        
        return finding.get('file_path', finding.get('image', 'unknown'))
    
    def _generate_exploitation_path(self, chain: Dict[str, Any]) -> List[str]:
        """Generate exploitation path for attack chain"""
        
        # This would be enhanced by AI in production
        return chain.get('steps', [])


def lambda_handler(event, context):
    """Lambda handler for autonomous container scanner"""
    
    import asyncio
    
    scanner = AutonomousContainerScanner()
    
    repository_path = event.get('repository_path', '/mnt/efs/repos/current')
    scan_config = event.get('scan_config', {})
    
    # Run async analysis
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(scanner.analyze(repository_path, scan_config))
        return {
            'statusCode': 200,
            'body': json.dumps(result, default=str)
        }
    finally:
        loop.close()


if __name__ == "__main__":
    # For testing
    test_event = {
        'repository_path': '/tmp/test-repo',
        'scan_config': {
            'scan_id': 'test-container-ai-analysis-123'
        }
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))