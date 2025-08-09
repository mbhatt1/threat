#!/usr/bin/env python3
"""
Dependency Security Agent
Fully AI-powered supply chain and dependency vulnerability analysis
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
import re

# Add parent directories to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import AI components
from shared.ai_orchestrator import AISecurityOrchestrator
from shared.ai_explainability import AIExplainabilityEngine
from shared.business_context import BusinessContextEngine
from ai_models.pure_ai_detector import PureAIVulnerabilityDetector
from shared.vulnerability_chains import VulnerabilityChainAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DependencyAgent:
    """
    Fully AI-powered dependency and supply chain security agent
    
    Capabilities:
    - AI-driven vulnerability detection in dependencies
    - Supply chain attack detection
    - Typosquatting and dependency confusion detection
    - License compliance analysis
    - Transitive dependency risk assessment
    - Zero-day prediction in dependencies
    - Behavioral analysis of packages
    """
    
    def __init__(self):
        # Initialize AI components
        self.ai_orchestrator = AISecurityOrchestrator()
        self.explainability = AIExplainabilityEngine()
        self.business_context = BusinessContextEngine()
        self.ai_detector = PureAIVulnerabilityDetector()
        self.chain_analyzer = VulnerabilityChainAnalyzer()
        
        # AI analysis configuration
        self.analysis_config = {
            'analysis_depth': 'comprehensive',
            'include_transitive': True,
            'check_supply_chain': True,
            'behavioral_analysis': True,
            'predict_vulnerabilities': True
        }
        
    async def scan(self, repository_path: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive AI-powered dependency scan"""
        
        scan_id = scan_config.get('scan_id', 'unknown')
        logger.info(f"Starting AI-powered dependency scan {scan_id}")
        
        scan_result = {
            'scan_id': scan_id,
            'agent': 'dependency',
            'analysis_type': 'fully_ai_powered',
            'started_at': datetime.utcnow().isoformat(),
            'repository_path': repository_path,
            'findings': [],
            'dependency_tree': {},
            'supply_chain_analysis': {},
            'license_analysis': {},
            'ai_insights': {},
            'risk_assessment': {}
        }
        
        try:
            # Phase 1: AI-powered dependency discovery
            dependency_inventory = await self._ai_discover_dependencies(repository_path)
            scan_result['dependency_tree'] = dependency_inventory
            
            # Phase 2: Deep vulnerability analysis
            vulnerability_findings = await self._ai_vulnerability_analysis(
                dependency_inventory
            )
            scan_result['findings'].extend(vulnerability_findings)
            
            # Phase 3: Supply chain security analysis
            supply_chain_findings = await self._ai_supply_chain_analysis(
                dependency_inventory, repository_path
            )
            scan_result['findings'].extend(supply_chain_findings['findings'])
            scan_result['supply_chain_analysis'] = supply_chain_findings['analysis']
            
            # Phase 4: Typosquatting and confusion detection
            typo_findings = await self._ai_typosquatting_detection(
                dependency_inventory
            )
            scan_result['findings'].extend(typo_findings)
            
            # Phase 5: License compliance analysis
            license_analysis = await self._ai_license_analysis(
                dependency_inventory
            )
            scan_result['license_analysis'] = license_analysis
            scan_result['findings'].extend(license_analysis.get('violations', []))
            
            # Phase 6: Transitive dependency analysis
            transitive_findings = await self._ai_transitive_analysis(
                dependency_inventory
            )
            scan_result['findings'].extend(transitive_findings)
            
            # Phase 7: Behavioral analysis of packages
            behavioral_findings = await self._ai_behavioral_analysis(
                dependency_inventory
            )
            scan_result['findings'].extend(behavioral_findings)
            
            # Phase 8: Outdated dependency analysis
            outdated_findings = await self._ai_outdated_analysis(
                dependency_inventory
            )
            scan_result['findings'].extend(outdated_findings)
            
            # Phase 9: Vulnerability prediction
            predicted_vulnerabilities = await self._ai_predict_vulnerabilities(
                dependency_inventory
            )
            scan_result['findings'].extend(predicted_vulnerabilities)
            
            # Phase 10: Risk assessment and prioritization
            risk_assessment = await self._ai_risk_assessment(
                scan_result['findings'], dependency_inventory
            )
            scan_result['risk_assessment'] = risk_assessment
            
            # Generate comprehensive AI insights
            ai_insights = await self._generate_ai_insights(scan_result)
            scan_result['ai_insights'] = ai_insights
            
            # Calculate metrics
            scan_result['metrics'] = self._calculate_scan_metrics(scan_result)
            
            scan_result['completed_at'] = datetime.utcnow().isoformat()
            scan_result['status'] = 'completed'
            
        except Exception as e:
            logger.error(f"AI dependency scan failed: {e}")
            scan_result['status'] = 'failed'
            scan_result['error'] = str(e)
        
        return scan_result
    
    async def _ai_discover_dependencies(self, repository_path: str) -> Dict[str, Any]:
        """Use AI to discover and analyze all dependencies"""
        
        dependency_inventory = {
            'direct_dependencies': {},
            'transitive_dependencies': {},
            'dev_dependencies': {},
            'total_packages': 0,
            'package_managers': [],
            'dependency_files': [],
            'ai_discovered_dependencies': []
        }
        
        # Look for dependency files
        dependency_patterns = {
            'package.json': 'npm',
            'package-lock.json': 'npm',
            'yarn.lock': 'yarn',
            'requirements.txt': 'pip',
            'Pipfile': 'pipenv',
            'Pipfile.lock': 'pipenv',
            'poetry.lock': 'poetry',
            'pom.xml': 'maven',
            'build.gradle': 'gradle',
            'go.mod': 'go',
            'go.sum': 'go',
            'Cargo.toml': 'cargo',
            'Cargo.lock': 'cargo',
            'composer.json': 'composer',
            'composer.lock': 'composer',
            'Gemfile': 'bundler',
            'Gemfile.lock': 'bundler'
        }
        
        for root, dirs, files in os.walk(repository_path):
            # Skip non-relevant directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__']]
            
            for file in files:
                if file in dependency_patterns:
                    file_path = os.path.join(root, file)
                    package_manager = dependency_patterns[file]
                    
                    if package_manager not in dependency_inventory['package_managers']:
                        dependency_inventory['package_managers'].append(package_manager)
                    
                    dependency_inventory['dependency_files'].append({
                        'path': file_path,
                        'type': file,
                        'package_manager': package_manager
                    })
                    
                    # AI-powered dependency extraction
                    dependencies = await self._ai_extract_dependencies(file_path, package_manager)
                    
                    # Categorize dependencies
                    for dep in dependencies:
                        if dep['is_dev']:
                            dependency_inventory['dev_dependencies'][dep['name']] = dep
                        elif dep['is_transitive']:
                            dependency_inventory['transitive_dependencies'][dep['name']] = dep
                        else:
                            dependency_inventory['direct_dependencies'][dep['name']] = dep
        
        # Use AI to discover hidden or unusual dependencies
        ai_discovered = await self._ai_discover_hidden_dependencies(repository_path)
        dependency_inventory['ai_discovered_dependencies'] = ai_discovered
        
        # Calculate totals
        dependency_inventory['total_packages'] = (
            len(dependency_inventory['direct_dependencies']) +
            len(dependency_inventory['transitive_dependencies']) +
            len(dependency_inventory['dev_dependencies'])
        )
        
        return dependency_inventory
    
    async def _ai_extract_dependencies(self, file_path: str, package_manager: str) -> List[Dict[str, Any]]:
        """Use AI to extract dependencies from file"""
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # AI analysis
            ai_response = await self.ai_orchestrator.analyze(
                content=content,
                context={
                    'file_type': 'dependency_file',
                    'package_manager': package_manager,
                    'file_path': file_path
                },
                prompt=f"""
                Extract all dependencies from this {package_manager} file:
                
                1. Package name and version
                2. Whether it's a dev/test dependency
                3. Whether it's a direct or transitive dependency
                4. Any security concerns about the package
                5. License information if available
                6. Repository/source URL if available
                7. Installation constraints or special requirements
                
                Also identify:
                - Suspicious package names (typosquatting indicators)
                - Packages from non-standard registries
                - Packages with unusual version constraints
                - Private/internal packages
                """
            )
            
            dependencies = []
            for dep in ai_response.get('dependencies', []):
                dependencies.append({
                    'name': dep['name'],
                    'version': dep['version'],
                    'is_dev': dep.get('is_dev', False),
                    'is_transitive': dep.get('is_transitive', False),
                    'license': dep.get('license', 'unknown'),
                    'repository': dep.get('repository', ''),
                    'registry': dep.get('registry', 'default'),
                    'constraints': dep.get('constraints', []),
                    'security_concerns': dep.get('security_concerns', []),
                    'ai_risk_score': dep.get('risk_score', 0)
                })
            
            return dependencies
            
        except Exception as e:
            logger.error(f"Failed to extract dependencies from {file_path}: {e}")
            return []
    
    async def _ai_discover_hidden_dependencies(self, repository_path: str) -> List[Dict[str, Any]]:
        """Use AI to discover hidden or unusual dependencies"""
        
        # Sample code files for hidden dependency analysis
        code_files = []
        for root, dirs, files in os.walk(repository_path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__']]
            
            for file in files[:20]:  # Limit for performance
                if file.endswith(('.py', '.js', '.java', '.go', '.rb')):
                    code_files.append(os.path.join(root, file))
        
        hidden_dependencies = []
        
        for code_file in code_files[:10]:  # Further limit
            try:
                with open(code_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # AI analysis for hidden dependencies
                ai_response = await self.ai_orchestrator.analyze(
                    content=content,
                    context={'file_path': code_file},
                    prompt="""
                    Analyze this code for hidden or implicit dependencies:
                    
                    1. Dynamic imports or requires
                    2. Shell commands installing packages
                    3. Git submodules or vendored dependencies
                    4. Downloads of external libraries
                    5. References to private package registries
                    6. Embedded binary dependencies
                    7. Runtime dependency loading
                    8. Configuration-based dependencies
                    
                    Identify any dependency that might not be in standard dependency files.
                    """
                )
                
                for hidden_dep in ai_response.get('hidden_dependencies', []):
                    hidden_dependencies.append({
                        'name': hidden_dep['name'],
                        'type': hidden_dep['type'],
                        'location': code_file,
                        'discovery_method': 'ai_code_analysis',
                        'risk_level': hidden_dep.get('risk_level', 'unknown'),
                        'description': hidden_dep['description']
                    })
                    
            except Exception as e:
                logger.debug(f"Failed to analyze {code_file} for hidden dependencies: {e}")
        
        return hidden_dependencies
    
    async def _ai_vulnerability_analysis(self, dependency_inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI-powered vulnerability analysis of dependencies"""
        
        findings = []
        
        # Analyze all dependencies
        all_dependencies = {
            **dependency_inventory['direct_dependencies'],
            **dependency_inventory['transitive_dependencies'],
            **dependency_inventory['dev_dependencies']
        }
        
        for dep_name, dep_info in list(all_dependencies.items())[:100]:  # Limit for performance
            # AI vulnerability analysis
            ai_response = await self.ai_orchestrator.analyze(
                content=json.dumps(dep_info),
                context={
                    'analysis_type': 'dependency_vulnerability',
                    'package_name': dep_name
                },
                prompt=f"""
                Analyze the security of dependency: {dep_name} version {dep_info.get('version', 'unknown')}
                
                Check for:
                1. Known CVEs and security advisories
                2. Suspicious package characteristics
                3. Maintainer reputation and activity
                4. Recent security incidents
                5. Code quality indicators
                6. Update frequency and support status
                7. Dependencies of this dependency (transitive risks)
                8. Potential for supply chain attacks
                9. License compatibility issues
                10. Zero-day vulnerability indicators
                
                Provide detailed findings with severity and confidence.
                """
            )
            
            for vuln in ai_response.get('vulnerabilities', []):
                finding = {
                    'finding_id': self._generate_finding_id(dep_name, vuln),
                    'finding_type': f"dependency_{vuln['type']}",
                    'severity': vuln['severity'],
                    'confidence': vuln['confidence'],
                    'package': dep_name,
                    'version': dep_info.get('version', 'unknown'),
                    'description': vuln['description'],
                    'cve_id': vuln.get('cve_id'),
                    'exploitation_poc': vuln.get('exploitation_poc'),
                    'ai_reasoning': vuln['reasoning'],
                    'remediation': vuln['remediation'],
                    'safe_version': vuln.get('safe_version'),
                    'ai_detected': True
                }
                findings.append(finding)
        
        return findings
    
    async def _ai_supply_chain_analysis(self, dependency_inventory: Dict[str, Any], 
                                       repository_path: str) -> Dict[str, Any]:
        """AI-powered supply chain security analysis"""
        
        supply_chain_results = {
            'findings': [],
            'analysis': {}
        }
        
        # Comprehensive supply chain analysis
        ai_response = await self.ai_orchestrator.analyze(
            content=json.dumps(dependency_inventory, default=str),
            context={
                'analysis_type': 'supply_chain_security',
                'repository_path': repository_path
            },
            prompt="""
            Perform comprehensive supply chain security analysis:
            
            1. Identify packages with suspicious maintainer changes
            2. Detect packages from compromised registries
            3. Find packages with unusual publish patterns
            4. Identify abandoned or unmaintained packages
            5. Detect packages with suspicious install scripts
            6. Find packages that phone home or have telemetry
            7. Identify packages with obfuscated code
            8. Detect potential backdoors or malicious code
            9. Find packages vulnerable to dependency confusion
            10. Identify supply chain attack indicators
            
            Consider the entire dependency tree and recent threat intelligence.
            Look for both obvious and subtle indicators of compromise.
            """
        )
        
        # Process supply chain findings
        for finding in ai_response.get('supply_chain_risks', []):
            supply_chain_results['findings'].append({
                'finding_id': self._generate_finding_id('supply_chain', finding),
                'finding_type': f"supply_chain_{finding['risk_type']}",
                'severity': finding['severity'],
                'confidence': finding['confidence'],
                'affected_packages': finding['affected_packages'],
                'description': finding['description'],
                'indicators': finding['indicators'],
                'attack_vector': finding.get('attack_vector'),
                'ai_reasoning': finding['reasoning'],
                'remediation': finding['remediation'],
                'ai_detected': True,
                'supply_chain_specific': True
            })
        
        # Supply chain analysis insights
        supply_chain_results['analysis'] = {
            'risk_score': ai_response.get('overall_risk_score', 0),
            'compromised_packages': ai_response.get('compromised_packages', []),
            'risky_registries': ai_response.get('risky_registries', []),
            'suspicious_patterns': ai_response.get('suspicious_patterns', []),
            'recommendations': ai_response.get('recommendations', [])
        }
        
        return supply_chain_results
    
    async def _ai_typosquatting_detection(self, dependency_inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI-powered typosquatting and dependency confusion detection"""
        
        findings = []
        
        # Get all package names
        all_packages = []
        for deps in [dependency_inventory['direct_dependencies'],
                    dependency_inventory['transitive_dependencies'],
                    dependency_inventory['dev_dependencies']]:
            all_packages.extend(deps.keys())
        
        # AI typosquatting analysis
        ai_response = await self.ai_orchestrator.analyze(
            content=json.dumps(all_packages),
            context={'analysis_type': 'typosquatting_detection'},
            prompt="""
            Analyze these package names for typosquatting and dependency confusion:
            
            1. Identify packages with names similar to popular packages
            2. Detect character substitution attacks (l/1, o/0, etc.)
            3. Find packages with extra/missing characters
            4. Identify namespace confusion attempts
            5. Detect homograph attacks (unicode lookalikes)
            6. Find packages mimicking internal package names
            7. Identify packages with suspicious prefixes/suffixes
            8. Detect combo-squatting (combining legitimate names)
            9. Find packages with misleading scopes
            10. Identify reputation hijacking attempts
            
            Check against known popular packages and common naming patterns.
            Consider both public and potential private package confusion.
            """
        )
        
        for typo_finding in ai_response.get('typosquatting_risks', []):
            finding = {
                'finding_id': self._generate_finding_id('typosquatting', typo_finding),
                'finding_type': 'typosquatting_risk',
                'severity': typo_finding['severity'],
                'confidence': typo_finding['confidence'],
                'suspicious_package': typo_finding['package_name'],
                'legitimate_package': typo_finding.get('legitimate_target'),
                'attack_type': typo_finding['attack_type'],
                'description': typo_finding['description'],
                'similarity_score': typo_finding.get('similarity_score', 0),
                'ai_reasoning': typo_finding['reasoning'],
                'remediation': typo_finding['remediation'],
                'ai_detected': True
            }
            findings.append(finding)
        
        return findings
    
    async def _ai_license_analysis(self, dependency_inventory: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered license compliance analysis"""
        
        # Collect all licenses
        all_licenses = []
        for deps in [dependency_inventory['direct_dependencies'],
                    dependency_inventory['transitive_dependencies']]:
            for dep_name, dep_info in deps.items():
                if dep_info.get('license'):
                    all_licenses.append({
                        'package': dep_name,
                        'license': dep_info['license']
                    })
        
        # AI license analysis
        ai_response = await self.ai_orchestrator.analyze(
            content=json.dumps(all_licenses),
            context={'analysis_type': 'license_compliance'},
            prompt="""
            Perform comprehensive license compliance analysis:
            
            1. Identify license compatibility issues
            2. Detect copyleft license obligations
            3. Find commercial use restrictions
            4. Identify attribution requirements
            5. Detect license conflicts in dependency tree
            6. Find packages with unclear or missing licenses
            7. Identify high-risk licenses for commercial use
            8. Detect custom or non-standard licenses
            9. Find license changes between versions
            10. Identify potential legal risks
            
            Consider the project's intended use (commercial/open-source).
            Check for transitive license requirements.
            """
        )
        
        license_analysis = {
            'compliant': ai_response.get('is_compliant', True),
            'risk_level': ai_response.get('risk_level', 'low'),
            'conflicts': ai_response.get('license_conflicts', []),
            'obligations': ai_response.get('obligations', []),
            'high_risk_licenses': ai_response.get('high_risk_licenses', []),
            'missing_licenses': ai_response.get('missing_licenses', []),
            'recommendations': ai_response.get('recommendations', []),
            'violations': []
        }
        
        # Create findings for violations
        for violation in ai_response.get('violations', []):
            license_analysis['violations'].append({
                'finding_id': self._generate_finding_id('license', violation),
                'finding_type': 'license_violation',
                'severity': violation['severity'],
                'confidence': violation['confidence'],
                'packages_involved': violation['packages'],
                'description': violation['description'],
                'legal_risk': violation['legal_risk'],
                'remediation': violation['remediation'],
                'ai_detected': True
            })
        
        return license_analysis
    
    async def _ai_transitive_analysis(self, dependency_inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI-powered transitive dependency analysis"""
        
        findings = []
        
        # Focus on transitive dependencies
        transitive_deps = dependency_inventory.get('transitive_dependencies', {})
        
        if transitive_deps:
            # AI analysis of transitive dependency risks
            ai_response = await self.ai_orchestrator.analyze(
                content=json.dumps(list(transitive_deps.items())[:50]),  # Limit for performance
                context={'analysis_type': 'transitive_dependency_risk'},
                prompt="""
                Analyze transitive dependency security risks:
                
                1. Identify deeply nested vulnerable dependencies
                2. Detect hidden security risks in dependency chains
                3. Find unmaintained transitive dependencies
                4. Identify version conflicts and resolution issues
                5. Detect circular dependencies
                6. Find dependencies pulled from multiple sources
                7. Identify phantom dependencies (unused but included)
                8. Detect transitive dependencies with critical CVEs
                9. Find dependencies that increase attack surface
                10. Identify update cascading risks
                
                Focus on risks that are often overlooked in direct dependency analysis.
                Consider the full dependency tree depth.
                """
            )
            
            for trans_finding in ai_response.get('transitive_risks', []):
                finding = {
                    'finding_id': self._generate_finding_id('transitive', trans_finding),
                    'finding_type': f"transitive_{trans_finding['risk_type']}",
                    'severity': trans_finding['severity'],
                    'confidence': trans_finding['confidence'],
                    'package': trans_finding['package'],
                    'dependency_chain': trans_finding.get('chain', []),
                    'depth': trans_finding.get('depth', 0),
                    'description': trans_finding['description'],
                    'hidden_risk': trans_finding.get('hidden_risk', False),
                    'ai_reasoning': trans_finding['reasoning'],
                    'remediation': trans_finding['remediation'],
                    'ai_detected': True
                }
                findings.append(finding)
        
        return findings
    
    async def _ai_behavioral_analysis(self, dependency_inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI-powered behavioral analysis of packages"""
        
        findings = []
        
        # Select high-risk packages for behavioral analysis
        high_risk_packages = []
        for deps in [dependency_inventory['direct_dependencies'],
                    dependency_inventory['transitive_dependencies']]:
            for dep_name, dep_info in deps.items():
                if dep_info.get('ai_risk_score', 0) > 0.5:
                    high_risk_packages.append((dep_name, dep_info))
        
        # Limit analysis for performance
        for dep_name, dep_info in high_risk_packages[:20]:
            # AI behavioral analysis
            ai_response = await self.ai_orchestrator.analyze(
                content=json.dumps({
                    'package': dep_name,
                    'info': dep_info
                }),
                context={'analysis_type': 'package_behavior'},
                prompt=f"""
                Perform behavioral analysis of package: {dep_name}
                
                Analyze for:
                1. Suspicious install/post-install scripts
                2. Network connections during installation
                3. File system modifications outside package directory
                4. Environment variable access/modification
                5. Process spawning or code execution
                6. Data collection or telemetry behavior
                7. Cryptocurrency mining indicators
                8. Backdoor or reverse shell patterns
                9. Obfuscation or anti-analysis techniques
                10. Unusual resource consumption
                
                Consider both installation and runtime behavior.
                Look for indicators of malicious or unwanted behavior.
                """
            )
            
            for behavior in ai_response.get('suspicious_behaviors', []):
                finding = {
                    'finding_id': self._generate_finding_id('behavior', behavior),
                    'finding_type': f"behavioral_{behavior['behavior_type']}",
                    'severity': behavior['severity'],
                    'confidence': behavior['confidence'],
                    'package': dep_name,
                    'behavior_description': behavior['description'],
                    'indicators': behavior['indicators'],
                    'malicious_probability': behavior.get('malicious_probability', 0),
                    'ai_reasoning': behavior['reasoning'],
                    'remediation': behavior['remediation'],
                    'ai_detected': True,
                    'behavioral_analysis': True
                }
                findings.append(finding)
        
        return findings
    
    async def _ai_outdated_analysis(self, dependency_inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI-powered analysis of outdated dependencies"""
        
        findings = []
        
        # Analyze all dependencies for outdated versions
        all_deps = {
            **dependency_inventory['direct_dependencies'],
            **dependency_inventory['transitive_dependencies']
        }
        
        # Batch analysis for efficiency
        ai_response = await self.ai_orchestrator.analyze(
            content=json.dumps(list(all_deps.items())[:50]),  # Limit for performance
            context={'analysis_type': 'outdated_dependency_analysis'},
            prompt="""
            Analyze these dependencies for version currency and update risks:
            
            1. Identify severely outdated packages (multiple major versions behind)
            2. Find packages using deprecated versions
            3. Detect packages with known security issues in current version
            4. Identify packages that haven't been updated in years
            5. Find packages with breaking changes in newer versions
            6. Detect packages nearing end-of-life
            7. Identify packages with better alternatives available
            8. Find packages with security improvements in newer versions
            9. Detect update paths that might introduce conflicts
            10. Identify packages that should be replaced entirely
            
            Consider both security and stability implications of updates.
            Provide actionable update recommendations.
            """
        )
        
        for outdated in ai_response.get('outdated_packages', []):
            finding = {
                'finding_id': self._generate_finding_id('outdated', outdated),
                'finding_type': 'outdated_dependency',
                'severity': outdated['severity'],
                'confidence': outdated['confidence'],
                'package': outdated['package'],
                'current_version': outdated['current_version'],
                'latest_version': outdated.get('latest_version'),
                'versions_behind': outdated.get('versions_behind'),
                'security_fixes_available': outdated.get('security_fixes', []),
                'update_complexity': outdated.get('update_complexity', 'unknown'),
                'breaking_changes': outdated.get('breaking_changes', []),
                'description': outdated['description'],
                'ai_reasoning': outdated['reasoning'],
                'remediation': outdated['remediation'],
                'ai_detected': True
            }
            findings.append(finding)
        
        return findings
    
    async def _ai_predict_vulnerabilities(self, dependency_inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI-powered prediction of future vulnerabilities"""
        
        findings = []
        
        # Select packages for prediction analysis
        packages_to_analyze = []
        for deps in [dependency_inventory['direct_dependencies'],
                    dependency_inventory['transitive_dependencies']]:
            for dep_name, dep_info in list(deps.items())[:30]:  # Limit for performance
                packages_to_analyze.append({
                    'name': dep_name,
                    'version': dep_info.get('version', 'unknown'),
                    'info': dep_info
                })
        
        # AI prediction analysis
        ai_response = await self.ai_orchestrator.analyze(
            content=json.dumps(packages_to_analyze),
            context={'analysis_type': 'vulnerability_prediction'},
            prompt="""
            Predict future vulnerabilities in these packages:
            
            1. Analyze code complexity and quality indicators
            2. Consider historical vulnerability patterns
            3. Evaluate maintainer responsiveness to security issues
            4. Assess dependency complexity and attack surface
            5. Consider language/framework-specific vulnerability trends
            6. Evaluate security practices of the project
            7. Analyze update frequency and patch history
            8. Consider similar packages' vulnerability history
            9. Assess exposure to common vulnerability classes
            10. Predict likelihood and timeline of future CVEs
            
            Focus on actionable predictions that can guide security planning.
            Consider both technical and human factors.
            """
        )
        
        for prediction in ai_response.get('vulnerability_predictions', []):
            finding = {
                'finding_id': self._generate_finding_id('prediction', prediction),
                'finding_type': 'predicted_vulnerability',
                'severity': prediction['predicted_severity'],
                'confidence': prediction['confidence'],
                'package': prediction['package'],
                'prediction_timeframe': prediction.get('timeframe', 'unknown'),
                'vulnerability_class': prediction.get('vulnerability_class'),
                'risk_factors': prediction['risk_factors'],
                'probability_score': prediction['probability'],
                'description': prediction['description'],
                'preventive_measures': prediction['prevention'],
                'ai_reasoning': prediction['reasoning'],
                'ai_detected': True,
                'predictive_analysis': True
            }
            findings.append(finding)
        
        return findings
    
    async def _ai_risk_assessment(self, findings: List[Dict[str, Any]], 
                                 dependency_inventory: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered comprehensive risk assessment"""
        
        # Comprehensive risk assessment
        ai_response = await self.ai_orchestrator.analyze(
            content=json.dumps({
                'findings': findings[:100],  # Limit for performance
                'dependency_count': dependency_inventory['total_packages'],
                'package_managers': dependency_inventory['package_managers']
            }, default=str),
            context={'analysis_type': 'dependency_risk_assessment'},
            prompt="""
            Perform comprehensive dependency risk assessment:
            
            1. Calculate overall supply chain risk score (0-100)
            2. Identify critical dependencies that pose highest risk
            3. Assess business impact of dependency vulnerabilities
            4. Evaluate ease of exploitation for identified issues
            5. Consider cumulative risk from all dependencies
            6. Identify single points of failure in dependency tree
            7. Assess remediation complexity and effort
            8. Prioritize updates based on risk and impact
            9. Evaluate alternative packages for high-risk dependencies
            10. Provide executive-level risk summary
            
            Consider both immediate and long-term risks.
            Provide actionable recommendations for risk reduction.
            """
        )
        
        return {
            'overall_risk_score': ai_response.get('risk_score', 0),
            'risk_level': ai_response.get('risk_level', 'unknown'),
            'critical_dependencies': ai_response.get('critical_dependencies', []),
            'single_points_of_failure': ai_response.get('spof', []),
            'immediate_actions': ai_response.get('immediate_actions', []),
            'remediation_plan': ai_response.get('remediation_plan', []),
            'alternative_packages': ai_response.get('alternatives', {}),
            'business_impact': ai_response.get('business_impact', {}),
            'executive_summary': ai_response.get('executive_summary', ''),
            'risk_trends': ai_response.get('risk_trends', [])
        }
    
    async def _generate_ai_insights(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive AI insights"""
        
        insights_response = await self.ai_orchestrator.analyze(
            content=json.dumps({
                'findings_count': len(scan_result['findings']),
                'dependency_count': scan_result['dependency_tree']['total_packages'],
                'risk_assessment': scan_result['risk_assessment']
            }, default=str),
            context={'analysis_type': 'dependency_insights'},
            prompt="""
            Generate strategic dependency security insights:
            
            1. Overall dependency health assessment
            2. Supply chain security posture
            3. Technical debt from outdated dependencies
            4. Security culture indicators
            5. Dependency management maturity
            6. Automation opportunities
            7. Cost-benefit analysis of updates
            8. Industry comparison and benchmarks
            9. Future security challenges
            10. Strategic recommendations
            
            Focus on actionable insights for security improvement.
            """
        )
        
        return {
            'health_score': insights_response.get('health_score', 0),
            'maturity_level': insights_response.get('maturity_level', 'unknown'),
            'key_observations': insights_response.get('observations', []),
            'improvement_areas': insights_response.get('improvements', []),
            'automation_opportunities': insights_response.get('automation', []),
            'strategic_recommendations': insights_response.get('recommendations', []),
            'industry_comparison': insights_response.get('benchmarks', {}),
            'future_considerations': insights_response.get('future_risks', [])
        }
    
    def _calculate_scan_metrics(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate dependency scan metrics"""
        
        findings = scan_result.get('findings', [])
        
        return {
            'total_findings': len(findings),
            'critical_findings': len([f for f in findings if f['severity'] == 'CRITICAL']),
            'high_findings': len([f for f in findings if f['severity'] == 'HIGH']),
            'supply_chain_risks': len([f for f in findings if f.get('supply_chain_specific')]),
            'behavioral_risks': len([f for f in findings if f.get('behavioral_analysis')]),
            'predicted_vulnerabilities': len([f for f in findings if f.get('predictive_analysis')]),
            'packages_analyzed': scan_result['dependency_tree']['total_packages'],
            'package_managers': len(scan_result['dependency_tree']['package_managers']),
            'ai_confidence_average': sum(f.get('confidence', 0) for f in findings) / max(len(findings), 1)
        }
    
    def _generate_finding_id(self, category: str, data: Any) -> str:
        """Generate unique finding ID"""
        
        content = f"{category}:{str(data)}"
        return hashlib.md5(content.encode()).hexdigest()[:16]


def lambda_handler(event, context):
    """Lambda handler for dependency agent"""
    import asyncio
    
    agent = DependencyAgent()
    
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
            'scan_id': 'test-ai-dep-123',
            'scan_type': 'dependency'
        }
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))