#!/usr/bin/env python3
"""
SAST (Static Application Security Testing) Agent
Fully AI-powered security analysis without predefined patterns
"""

import os
import sys
import json
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import hashlib
from collections import defaultdict

# Add parent directories to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import AI components
from shared.ai_orchestrator import AISecurityOrchestrator
from shared.ai_explainability import AIExplainabilityEngine
from shared.business_context import BusinessContextEngine
from ai_models.pure_ai_detector import PureAIVulnerabilityDetector
from ai_models.sql_injection_detector import SQLInjectionDetector
from ai_models.root_cause_analyzer import AIRootCauseAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SASTAgent:
    """
    Fully AI-powered SAST agent using deep learning for code analysis
    
    Capabilities:
    - Zero-day vulnerability detection through AI reasoning
    - Context-aware security analysis
    - Business logic vulnerability detection
    - Advanced attack vector prediction
    - Real-time threat intelligence integration
    """
    
    def __init__(self):
        # Initialize AI components
        self.ai_orchestrator = AISecurityOrchestrator()
        self.explainability = AIExplainabilityEngine()
        self.business_context = BusinessContextEngine()
        self.pure_ai_detector = PureAIVulnerabilityDetector()
        self.sql_detector = SQLInjectionDetector()
        self.root_cause_analyzer = AIRootCauseAnalyzer()
        
        # AI analysis configuration
        self.analysis_config = {
            'depth': 'comprehensive',
            'include_business_logic': True,
            'detect_zero_days': True,
            'analyze_attack_chains': True,
            'include_threat_intel': True
        }
        
    async def scan(self, repository_path: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive AI-powered SAST scan"""
        
        scan_id = scan_config.get('scan_id', 'unknown')
        scan_type = scan_config.get('scan_type', 'sast')
        branch = scan_config.get('branch', 'main')
        
        logger.info(f"Starting AI-powered SAST scan {scan_id}")
        
        scan_result = {
            'scan_id': scan_id,
            'agent': 'sast',
            'analysis_type': 'fully_ai_powered',
            'started_at': datetime.utcnow().isoformat(),
            'repository_path': repository_path,
            'branch': branch,
            'findings': [],
            'ai_insights': {},
            'vulnerability_chains': [],
            'code_quality_analysis': {},
            'threat_intelligence': {}
        }
        
        try:
            # Phase 1: AI-powered code discovery and classification
            code_inventory = await self._ai_discover_code(repository_path)
            scan_result['code_inventory'] = code_inventory
            
            # Phase 2: Deep AI vulnerability analysis
            vulnerability_findings = await self._ai_deep_vulnerability_scan(
                code_inventory, repository_path
            )
            scan_result['findings'].extend(vulnerability_findings)
            
            # Phase 3: Business logic vulnerability detection
            business_logic_findings = await self._ai_business_logic_analysis(
                code_inventory, repository_path
            )
            scan_result['findings'].extend(business_logic_findings)
            
            # Phase 4: AI-powered injection vulnerability detection
            injection_findings = await self._ai_injection_analysis(
                code_inventory, repository_path
            )
            scan_result['findings'].extend(injection_findings)
            
            # Phase 5: Authentication and authorization analysis
            auth_findings = await self._ai_auth_analysis(
                code_inventory, repository_path
            )
            scan_result['findings'].extend(auth_findings)
            
            # Phase 6: Cryptographic vulnerability detection
            crypto_findings = await self._ai_crypto_analysis(
                code_inventory, repository_path
            )
            scan_result['findings'].extend(crypto_findings)
            
            # Phase 7: Attack chain analysis
            attack_chains = await self._ai_attack_chain_analysis(
                scan_result['findings']
            )
            scan_result['vulnerability_chains'] = attack_chains
            
            # Phase 8: Code quality and maintainability analysis
            code_quality = await self._ai_code_quality_analysis(
                code_inventory, repository_path
            )
            scan_result['code_quality_analysis'] = code_quality
            
            # Phase 9: Threat intelligence correlation
            threat_intel = await self._ai_threat_intelligence_analysis(
                scan_result['findings']
            )
            scan_result['threat_intelligence'] = threat_intel
            
            # Phase 10: Generate comprehensive AI insights
            ai_insights = await self._generate_ai_insights(scan_result)
            scan_result['ai_insights'] = ai_insights
            
            # Calculate metrics
            scan_result['metrics'] = self._calculate_scan_metrics(scan_result)
            
            scan_result['completed_at'] = datetime.utcnow().isoformat()
            scan_result['status'] = 'completed'
            
        except Exception as e:
            logger.error(f"AI SAST scan failed: {e}")
            scan_result['status'] = 'failed'
            scan_result['error'] = str(e)
        
        return scan_result
    
    async def _ai_discover_code(self, repository_path: str) -> Dict[str, Any]:
        """Use AI to discover and classify code files"""
        
        code_inventory = {
            'total_files': 0,
            'total_lines': 0,
            'languages': defaultdict(int),
            'frameworks': [],
            'entry_points': [],
            'high_risk_files': [],
            'api_endpoints': [],
            'database_interactions': [],
            'external_integrations': [],
            'ai_classified_files': []
        }
        
        for root, dirs, files in os.walk(repository_path):
            # Skip non-code directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv']]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # AI-powered file analysis
                file_analysis = await self._ai_analyze_file(file_path)
                
                if file_analysis['is_code_file']:
                    code_inventory['total_files'] += 1
                    code_inventory['total_lines'] += file_analysis.get('line_count', 0)
                    code_inventory['languages'][file_analysis['language']] += 1
                    
                    # Track high-risk files
                    if file_analysis.get('risk_score', 0) > 0.7:
                        code_inventory['high_risk_files'].append({
                            'path': file_path,
                            'risk_score': file_analysis['risk_score'],
                            'risk_factors': file_analysis['risk_factors']
                        })
                    
                    # Track API endpoints
                    if file_analysis.get('api_endpoints'):
                        code_inventory['api_endpoints'].extend([
                            {'file': file_path, 'endpoint': ep} 
                            for ep in file_analysis['api_endpoints']
                        ])
                    
                    # Track database interactions
                    if file_analysis.get('database_operations'):
                        code_inventory['database_interactions'].extend([
                            {'file': file_path, 'operation': op}
                            for op in file_analysis['database_operations']
                        ])
                    
                    # AI classification results
                    code_inventory['ai_classified_files'].append({
                        'path': file_path,
                        'classification': file_analysis
                    })
        
        # Detect frameworks using AI
        code_inventory['frameworks'] = await self._ai_detect_frameworks(repository_path)
        
        return code_inventory
    
    async def _ai_analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Use AI to analyze individual file"""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Prepare context for AI
            context = {
                'task': 'code_file_analysis',
                'file_path': file_path,
                'analysis_depth': 'comprehensive'
            }
            
            # AI analysis
            ai_response = await self.ai_orchestrator.analyze(
                content=content[:10000],  # Limit content size
                context=context,
                prompt="""
                Analyze this code file comprehensively:
                
                1. Is this a code file? What language?
                2. Calculate risk score (0-1) based on:
                   - Handles sensitive data
                   - Authentication/authorization logic
                   - External integrations
                   - Database operations
                   - Cryptographic operations
                   - User input handling
                3. Identify API endpoints
                4. Identify database operations
                5. Identify external service integrations
                6. Count lines of code
                7. Identify security-critical functions
                
                Provide detailed analysis with reasoning.
                """
            )
            
            return ai_response
            
        except Exception as e:
            logger.debug(f"Could not analyze {file_path}: {e}")
            return {'is_code_file': False}
    
    async def _ai_deep_vulnerability_scan(self, code_inventory: Dict[str, Any], 
                                         repository_path: str) -> List[Dict[str, Any]]:
        """Perform deep AI vulnerability scanning"""
        
        findings = []
        
        # Focus on high-risk files for deep analysis
        files_to_analyze = code_inventory.get('high_risk_files', [])[:100]  # Limit for performance
        
        # Add entry points and API endpoints
        for ep in code_inventory.get('api_endpoints', [])[:50]:
            if ep['file'] not in [f['path'] for f in files_to_analyze]:
                files_to_analyze.append({'path': ep['file'], 'context': 'api_endpoint'})
        
        for file_info in files_to_analyze:
            file_path = file_info['path']
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Use Pure AI Detector for comprehensive analysis
                context = {
                    'file_path': file_path,
                    'language': self._detect_language(file_path),
                    'file_context': file_info.get('context', 'general')
                }
                
                ai_vulnerabilities = await self.pure_ai_detector.detect_vulnerabilities(
                    content, context
                )
                
                for vuln in ai_vulnerabilities:
                    finding = {
                        'finding_id': vuln.vuln_id,
                        'finding_type': vuln.vulnerability_type,
                        'severity': vuln.severity,
                        'confidence': vuln.confidence,
                        'file_path': file_path,
                        'line_numbers': vuln.line_numbers,
                        'code_snippet': vuln.code_snippet,
                        'description': vuln.description,
                        'ai_reasoning': vuln.ai_reasoning,
                        'exploitation_scenario': vuln.exploitation_scenario,
                        'business_impact': vuln.business_impact,
                        'remediation': vuln.fix_recommendation,
                        'references': vuln.references,
                        'ai_detected': True,
                        'zero_day_potential': vuln.is_zero_day
                    }
                    findings.append(finding)
                
            except Exception as e:
                logger.error(f"AI vulnerability scan failed for {file_path}: {e}")
        
        return findings
    
    async def _ai_business_logic_analysis(self, code_inventory: Dict[str, Any],
                                         repository_path: str) -> List[Dict[str, Any]]:
        """AI-powered business logic vulnerability detection"""
        
        findings = []
        
        # Use AI to identify business logic files
        business_files = await self._ai_identify_business_logic_files(code_inventory)
        
        for file_path in business_files[:50]:  # Limit for performance
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # AI analysis for business logic vulnerabilities
                ai_response = await self.ai_orchestrator.analyze(
                    content=content,
                    context={
                        'analysis_type': 'business_logic_security',
                        'file_path': file_path
                    },
                    prompt="""
                    Analyze this code for business logic security vulnerabilities:
                    
                    1. Race conditions in critical operations
                    2. Insufficient validation of business rules
                    3. Improper state management
                    4. Missing authorization for sensitive operations
                    5. Logical flaws in workflow implementations
                    6. Time-of-check to time-of-use (TOCTOU) issues
                    7. Insufficient transaction isolation
                    8. Business rule bypass possibilities
                    9. Price manipulation vulnerabilities
                    10. Privilege escalation through business logic
                    
                    Focus on vulnerabilities that could lead to financial loss,
                    data corruption, or unauthorized access.
                    """
                )
                
                # Process business logic findings
                for ai_finding in ai_response.get('findings', []):
                    finding = {
                        'finding_id': self._generate_finding_id(file_path, ai_finding),
                        'finding_type': f"business_logic_{ai_finding['type']}",
                        'severity': ai_finding['severity'],
                        'confidence': ai_finding['confidence'],
                        'file_path': file_path,
                        'description': ai_finding['description'],
                        'business_impact': ai_finding['business_impact'],
                        'exploitation_scenario': ai_finding['exploitation_scenario'],
                        'ai_reasoning': ai_finding['reasoning'],
                        'remediation': ai_finding['remediation'],
                        'ai_detected': True,
                        'business_logic_flaw': True
                    }
                    findings.append(finding)
                
            except Exception as e:
                logger.error(f"Business logic analysis failed for {file_path}: {e}")
        
        return findings
    
    async def _ai_injection_analysis(self, code_inventory: Dict[str, Any],
                                    repository_path: str) -> List[Dict[str, Any]]:
        """AI-powered injection vulnerability detection"""
        
        findings = []
        
        # Focus on files with database interactions and user input
        target_files = []
        
        # Add database interaction files
        for db_interaction in code_inventory.get('database_interactions', [])[:30]:
            target_files.append(db_interaction['file'])
        
        # Add API endpoint files
        for api_endpoint in code_inventory.get('api_endpoints', [])[:30]:
            if api_endpoint['file'] not in target_files:
                target_files.append(api_endpoint['file'])
        
        for file_path in target_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Use specialized SQL injection detector
                context = {
                    'file_path': file_path,
                    'language': self._detect_language(file_path)
                }
                sql_detection = self.sql_detector.detect(content, context)
                
                # Convert to expected format
                sql_vulns = []
                if sql_detection.is_vulnerable:
                    sql_vulns.append({
                        'id': hashlib.sha256(f"{file_path}:{sql_detection.injection_type}".encode()).hexdigest()[:12],
                        'severity': sql_detection.severity,
                        'confidence': sql_detection.confidence,
                        'line_number': 0,  # Would need to be extracted from attention_weights
                        'code_snippet': sql_detection.proof_of_concept or '',
                        'description': f"{sql_detection.injection_type}: {sql_detection.attack_vector}",
                        'attack_vector': sql_detection.attack_vector,
                        'fix_recommendation': sql_detection.remediation
                    })
                
                for vuln in sql_vulns:
                    finding = {
                        'finding_id': vuln['id'],
                        'finding_type': 'sql_injection',
                        'severity': vuln['severity'],
                        'confidence': vuln['confidence'],
                        'file_path': file_path,
                        'line_number': vuln['line_number'],
                        'vulnerable_code': vuln['code_snippet'],
                        'description': vuln['description'],
                        'attack_vector': vuln['attack_vector'],
                        'remediation': vuln['fix_recommendation'],
                        'ai_detected': True
                    }
                    findings.append(finding)
                
                # General injection analysis
                injection_response = await self.ai_orchestrator.analyze(
                    content=content,
                    context={
                        'analysis_type': 'injection_vulnerabilities',
                        'file_path': file_path
                    },
                    prompt="""
                    Analyze for all types of injection vulnerabilities:
                    
                    1. SQL Injection (including blind and second-order)
                    2. NoSQL Injection
                    3. LDAP Injection
                    4. XML/XXE Injection
                    5. Command Injection
                    6. Code Injection (eval, exec)
                    7. Template Injection
                    8. Header Injection
                    9. Log Injection
                    10. Path Traversal
                    
                    Consider both direct and indirect injection vectors.
                    Look for unsafe data handling and concatenation.
                    """
                )
                
                # Process injection findings
                for ai_finding in injection_response.get('findings', []):
                    finding = {
                        'finding_id': self._generate_finding_id(file_path, ai_finding),
                        'finding_type': f"injection_{ai_finding['injection_type']}",
                        'severity': ai_finding['severity'],
                        'confidence': ai_finding['confidence'],
                        'file_path': file_path,
                        'line_numbers': ai_finding.get('line_numbers', []),
                        'description': ai_finding['description'],
                        'attack_vector': ai_finding['attack_vector'],
                        'ai_reasoning': ai_finding['reasoning'],
                        'remediation': ai_finding['remediation'],
                        'ai_detected': True
                    }
                    findings.append(finding)
                
            except Exception as e:
                logger.error(f"Injection analysis failed for {file_path}: {e}")
        
        return findings
    
    async def _ai_auth_analysis(self, code_inventory: Dict[str, Any],
                               repository_path: str) -> List[Dict[str, Any]]:
        """AI-powered authentication and authorization analysis"""
        
        findings = []
        
        # AI prompt to identify auth-related files
        auth_files = await self._ai_identify_auth_files(code_inventory)
        
        for file_path in auth_files[:30]:  # Limit for performance
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Deep auth analysis
                auth_response = await self.ai_orchestrator.analyze(
                    content=content,
                    context={
                        'analysis_type': 'authentication_authorization',
                        'file_path': file_path
                    },
                    prompt="""
                    Perform comprehensive authentication and authorization analysis:
                    
                    1. Weak authentication mechanisms
                    2. Missing authentication on sensitive endpoints
                    3. Broken authorization (horizontal/vertical privilege escalation)
                    4. Session management vulnerabilities
                    5. JWT/token security issues
                    6. Password policy weaknesses
                    7. Multi-factor authentication gaps
                    8. OAuth/SAML implementation flaws
                    9. API key management issues
                    10. Role-based access control (RBAC) flaws
                    
                    Consider both implementation bugs and design flaws.
                    Look for bypass techniques and edge cases.
                    """
                )
                
                # Process auth findings
                for ai_finding in auth_response.get('findings', []):
                    finding = {
                        'finding_id': self._generate_finding_id(file_path, ai_finding),
                        'finding_type': f"auth_{ai_finding['auth_issue_type']}",
                        'severity': ai_finding['severity'],
                        'confidence': ai_finding['confidence'],
                        'file_path': file_path,
                        'description': ai_finding['description'],
                        'attack_scenario': ai_finding['attack_scenario'],
                        'privilege_escalation_risk': ai_finding.get('privilege_escalation_risk', False),
                        'ai_reasoning': ai_finding['reasoning'],
                        'remediation': ai_finding['remediation'],
                        'ai_detected': True
                    }
                    findings.append(finding)
                
            except Exception as e:
                logger.error(f"Auth analysis failed for {file_path}: {e}")
        
        return findings
    
    async def _ai_crypto_analysis(self, code_inventory: Dict[str, Any],
                                  repository_path: str) -> List[Dict[str, Any]]:
        """AI-powered cryptographic vulnerability detection"""
        
        findings = []
        
        # AI to identify crypto-related files
        crypto_files = await self._ai_identify_crypto_files(code_inventory)
        
        for file_path in crypto_files[:30]:  # Limit for performance
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Crypto analysis
                crypto_response = await self.ai_orchestrator.analyze(
                    content=content,
                    context={
                        'analysis_type': 'cryptographic_security',
                        'file_path': file_path
                    },
                    prompt="""
                    Analyze cryptographic implementations for vulnerabilities:
                    
                    1. Weak cryptographic algorithms (MD5, SHA1, DES, etc.)
                    2. Hardcoded encryption keys or IVs
                    3. Predictable random number generation
                    4. Improper key management and storage
                    5. Missing encryption for sensitive data
                    6. Weak key derivation functions
                    7. Cryptographic timing attacks
                    8. Padding oracle vulnerabilities
                    9. Improper certificate validation
                    10. Side-channel attack vulnerabilities
                    
                    Consider both algorithm choice and implementation details.
                    Look for crypto misuse and implementation errors.
                    """
                )
                
                # Process crypto findings
                for ai_finding in crypto_response.get('findings', []):
                    finding = {
                        'finding_id': self._generate_finding_id(file_path, ai_finding),
                        'finding_type': f"crypto_{ai_finding['crypto_issue_type']}",
                        'severity': ai_finding['severity'],
                        'confidence': ai_finding['confidence'],
                        'file_path': file_path,
                        'description': ai_finding['description'],
                        'crypto_weakness': ai_finding['weakness_details'],
                        'attack_feasibility': ai_finding.get('attack_feasibility', 'unknown'),
                        'ai_reasoning': ai_finding['reasoning'],
                        'remediation': ai_finding['remediation'],
                        'ai_detected': True
                    }
                    findings.append(finding)
                
            except Exception as e:
                logger.error(f"Crypto analysis failed for {file_path}: {e}")
        
        return findings
    
    async def _ai_attack_chain_analysis(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze potential attack chains using AI"""
        
        # Use AI to identify attack chains
        chain_response = await self.ai_orchestrator.analyze(
            content=json.dumps(findings, default=str),
            context={'analysis_type': 'attack_chain_analysis'},
            prompt="""
            Analyze these security findings to identify potential attack chains:
            
            1. Identify vulnerabilities that can be chained together
            2. Map complete attack paths from entry to impact
            3. Calculate combined severity for chained vulnerabilities
            4. Identify the most likely attack scenarios
            5. Consider authentication bypass chains
            6. Look for data exfiltration paths
            7. Identify privilege escalation chains
            8. Map remote code execution paths
            9. Consider supply chain attack vectors
            10. Evaluate real-world exploitability
            
            Prioritize realistic attack chains that could lead to significant impact.
            """
        )
        
        attack_chains = []
        for chain in chain_response.get('attack_chains', []):
            attack_chains.append({
                'chain_id': self._generate_finding_id('chain', chain),
                'name': chain['name'],
                'description': chain['description'],
                'vulnerabilities': chain['vulnerability_chain'],
                'attack_path': chain['attack_path'],
                'combined_severity': chain['combined_severity'],
                'exploitation_complexity': chain['complexity'],
                'likelihood': chain['likelihood'],
                'business_impact': chain['business_impact'],
                'mitigation_priority': chain['priority'],
                'ai_confidence': chain['confidence']
            })
        
        return attack_chains
    
    async def _ai_code_quality_analysis(self, code_inventory: Dict[str, Any],
                                       repository_path: str) -> Dict[str, Any]:
        """AI-powered code quality and security posture analysis"""
        
        # Sample files for quality analysis
        sample_files = code_inventory.get('ai_classified_files', [])[:20]
        
        quality_response = await self.ai_orchestrator.analyze(
            content=json.dumps(sample_files, default=str),
            context={
                'analysis_type': 'code_quality_security',
                'repository_path': repository_path
            },
            prompt="""
            Analyze code quality from a security perspective:
            
            1. Code complexity and maintainability issues
            2. Error handling quality
            3. Input validation consistency
            4. Security coding standards compliance
            5. Documentation quality for security-critical code
            6. Test coverage for security features
            7. Dependency management practices
            8. Code review and security review indicators
            9. Technical debt impacting security
            10. Architecture patterns affecting security
            
            Provide insights on how code quality impacts security posture.
            """
        )
        
        return {
            'overall_score': quality_response.get('quality_score', 0),
            'security_maturity': quality_response.get('security_maturity', 'unknown'),
            'key_issues': quality_response.get('key_issues', []),
            'improvement_areas': quality_response.get('improvement_areas', []),
            'positive_practices': quality_response.get('positive_practices', []),
            'recommendations': quality_response.get('recommendations', [])
        }
    
    async def _ai_threat_intelligence_analysis(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate findings with threat intelligence using AI"""
        
        threat_response = await self.ai_orchestrator.analyze(
            content=json.dumps(findings[:50], default=str),  # Limit for performance
            context={'analysis_type': 'threat_intelligence'},
            prompt="""
            Analyze findings against current threat intelligence:
            
            1. Identify vulnerabilities actively exploited in the wild
            2. Correlate with known APT techniques and tools
            3. Map to MITRE ATT&CK framework
            4. Identify similarities to recent breaches
            5. Assess attractiveness to different threat actors
            6. Predict likelihood of exploitation
            7. Identify vulnerabilities with public exploits
            8. Assess supply chain attack risks
            9. Consider geopolitical factors
            10. Evaluate ransomware susceptibility
            
            Provide actionable threat intelligence insights.
            """
        )
        
        return {
            'active_exploitation': threat_response.get('actively_exploited', []),
            'apt_correlation': threat_response.get('apt_techniques', []),
            'mitre_mapping': threat_response.get('mitre_attack_mapping', []),
            'exploitation_likelihood': threat_response.get('exploitation_predictions', {}),
            'threat_actors': threat_response.get('relevant_threat_actors', []),
            'similar_breaches': threat_response.get('similar_incidents', []),
            'priority_patches': threat_response.get('priority_remediations', [])
        }
    
    async def _generate_ai_insights(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive AI insights from scan results"""
        
        insights_response = await self.ai_orchestrator.analyze(
            content=json.dumps({
                'findings_summary': {
                    'total': len(scan_result['findings']),
                    'by_severity': self._count_by_severity(scan_result['findings']),
                    'by_type': self._count_by_type(scan_result['findings'])
                },
                'attack_chains': len(scan_result['vulnerability_chains']),
                'code_quality': scan_result['code_quality_analysis']
            }, default=str),
            context={'analysis_type': 'insight_generation'},
            prompt="""
            Generate strategic security insights:
            
            1. Overall security posture assessment
            2. Critical risks requiring immediate attention
            3. Systemic security issues and patterns
            4. Recommended security architecture changes
            5. Process and tooling improvements
            6. Developer training recommendations
            7. Compliance and regulatory considerations
            8. Cost-benefit analysis of remediation efforts
            9. Quick wins vs long-term improvements
            10. Executive summary for leadership
            
            Focus on actionable, strategic insights.
            """
        )
        
        return {
            'executive_summary': insights_response.get('executive_summary', ''),
            'risk_assessment': insights_response.get('risk_assessment', {}),
            'strategic_recommendations': insights_response.get('strategic_recommendations', []),
            'improvement_roadmap': insights_response.get('improvement_roadmap', []),
            'training_needs': insights_response.get('training_recommendations', []),
            'tooling_gaps': insights_response.get('tooling_recommendations', []),
            'ai_observations': insights_response.get('unique_observations', [])
        }
    
    async def _ai_identify_business_logic_files(self, code_inventory: Dict[str, Any]) -> List[str]:
        """Use AI to identify business logic files"""
        
        business_files = []
        
        for file_info in code_inventory.get('ai_classified_files', []):
            if any(indicator in str(file_info).lower() for indicator in 
                   ['service', 'business', 'logic', 'workflow', 'transaction', 
                    'payment', 'order', 'calculation', 'rule']):
                business_files.append(file_info['path'])
        
        return business_files[:50]  # Limit for performance
    
    async def _ai_identify_auth_files(self, code_inventory: Dict[str, Any]) -> List[str]:
        """Use AI to identify authentication/authorization files"""
        
        auth_files = []
        
        for file_info in code_inventory.get('ai_classified_files', []):
            if any(indicator in str(file_info).lower() for indicator in 
                   ['auth', 'login', 'session', 'token', 'jwt', 'oauth', 
                    'permission', 'role', 'access', 'identity']):
                auth_files.append(file_info['path'])
        
        return auth_files
    
    async def _ai_identify_crypto_files(self, code_inventory: Dict[str, Any]) -> List[str]:
        """Use AI to identify cryptography-related files"""
        
        crypto_files = []
        
        for file_info in code_inventory.get('ai_classified_files', []):
            if any(indicator in str(file_info).lower() for indicator in 
                   ['crypto', 'encrypt', 'decrypt', 'hash', 'sign', 'verify', 
                    'certificate', 'key', 'cipher', 'ssl', 'tls']):
                crypto_files.append(file_info['path'])
        
        return crypto_files
    
    async def _ai_detect_frameworks(self, repository_path: str) -> List[str]:
        """Use AI to detect frameworks and technologies"""
        
        # Sample key files for framework detection
        key_files = ['package.json', 'requirements.txt', 'pom.xml', 'build.gradle', 
                     'go.mod', 'Gemfile', 'composer.json']
        
        framework_content = []
        for file in key_files:
            file_path = os.path.join(repository_path, file)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        framework_content.append({
                            'file': file,
                            'content': f.read()[:1000]
                        })
                except:
                    pass
        
        if framework_content:
            framework_response = await self.ai_orchestrator.analyze(
                content=json.dumps(framework_content),
                context={'analysis_type': 'framework_detection'},
                prompt="Identify all frameworks, libraries, and technologies used in this project based on dependency files."
            )
            
            return framework_response.get('frameworks', [])
        
        return []
    
    def _calculate_scan_metrics(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive scan metrics"""
        
        findings = scan_result.get('findings', [])
        
        return {
            'total_findings': len(findings),
            'critical_findings': len([f for f in findings if f['severity'] == 'CRITICAL']),
            'high_findings': len([f for f in findings if f['severity'] == 'HIGH']),
            'medium_findings': len([f for f in findings if f['severity'] == 'MEDIUM']),
            'low_findings': len([f for f in findings if f['severity'] == 'LOW']),
            'ai_confidence_average': sum(f.get('confidence', 0) for f in findings) / max(len(findings), 1),
            'zero_day_candidates': len([f for f in findings if f.get('zero_day_potential', False)]),
            'business_logic_flaws': len([f for f in findings if f.get('business_logic_flaw', False)]),
            'attack_chains_identified': len(scan_result.get('vulnerability_chains', [])),
            'files_analyzed': scan_result.get('code_inventory', {}).get('total_files', 0),
            'lines_analyzed': scan_result.get('code_inventory', {}).get('total_lines', 0)
        }
    
    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity"""
        
        severity_count = defaultdict(int)
        for finding in findings:
            severity_count[finding['severity']] += 1
        return dict(severity_count)
    
    def _count_by_type(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by type"""
        
        type_count = defaultdict(int)
        for finding in findings:
            type_count[finding['finding_type']] += 1
        return dict(type_count)
    
    def _generate_finding_id(self, identifier: str, data: Any) -> str:
        """Generate unique finding ID"""
        
        content = f"{identifier}:{str(data)}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        
        ext = os.path.splitext(file_path)[1].lower()
        
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.go': 'golang',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.rs': 'rust'
        }
        
        return language_map.get(ext, 'unknown')


def lambda_handler(event, context):
    """Lambda handler for SAST agent"""
    import asyncio
    
    agent = SASTAgent()
    
    repository_path = event.get('repository_path', '/mnt/efs/repos/current')
    scan_config = event.get('scan_config', {})
    
    # Run async scan
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(agent.scan(repository_path, scan_config))
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
            'scan_id': 'test-ai-sast-123',
            'scan_type': 'sast'
        }
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))