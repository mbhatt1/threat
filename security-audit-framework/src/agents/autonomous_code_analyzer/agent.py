"""
Autonomous Code Analyzer Agent
Advanced AI-powered code analysis for security vulnerabilities
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
import re
from collections import defaultdict

# Add parent directories to path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import AI components
from shared.ai_orchestrator import AISecurityOrchestrator
from shared.ai_explainability import AIExplainabilityEngine
from shared.business_context import BusinessContextEngine
from ai_models.pure_ai_detector import PureAIVulnerabilityDetector
from ai_models.sql_injection_detector import SQLInjectionDetector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AutonomousCodeAnalyzer:
    """
    Autonomous agent for deep code analysis using AI
    Focuses on:
    - Complex vulnerability patterns
    - Cross-file analysis
    - Business logic flaws
    - Security best practices
    """
    
    def __init__(self):
        # Initialize AI components
        self.ai_orchestrator = AISecurityOrchestrator()
        self.explainability = AIExplainabilityEngine()
        self.business_context = BusinessContextEngine()
        self.pure_ai_detector = PureAIVulnerabilityDetector()
        self.sql_detector = SQLInjectionDetector()
        
        # Analysis patterns
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        self.security_rules = self._load_security_rules()
        
    async def analyze(self, repository_path: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform autonomous code analysis
        """
        scan_id = scan_config.get('scan_id', 'unknown')
        logger.info(f"Starting autonomous code analysis for scan {scan_id}")
        
        analysis_results = {
            'scan_id': scan_id,
            'agent': 'autonomous_code_analyzer',
            'started_at': datetime.utcnow().isoformat(),
            'findings': [],
            'metrics': {},
            'insights': {}
        }
        
        try:
            # Phase 1: Code structure analysis
            structure_analysis = await self._analyze_code_structure(repository_path)
            analysis_results['structure'] = structure_analysis
            
            # Phase 2: Vulnerability pattern detection
            pattern_findings = await self._detect_vulnerability_patterns(repository_path)
            analysis_results['findings'].extend(pattern_findings)
            
            # Phase 3: Business logic analysis
            business_logic_findings = await self._analyze_business_logic(repository_path)
            analysis_results['findings'].extend(business_logic_findings)
            
            # Phase 4: Cross-file vulnerability analysis
            cross_file_findings = await self._analyze_cross_file_vulnerabilities(repository_path)
            analysis_results['findings'].extend(cross_file_findings)
            
            # Phase 5: Security best practices check
            best_practices_findings = await self._check_security_best_practices(repository_path)
            analysis_results['findings'].extend(best_practices_findings)
            
            # Phase 6: AI-powered deep analysis
            ai_findings = await self._perform_ai_deep_analysis(repository_path)
            analysis_results['findings'].extend(ai_findings)
            
            # Generate insights
            analysis_results['insights'] = self._generate_analysis_insights(analysis_results)
            
            # Calculate metrics
            analysis_results['metrics'] = self._calculate_analysis_metrics(analysis_results)
            
            analysis_results['completed_at'] = datetime.utcnow().isoformat()
            analysis_results['status'] = 'completed'
            
        except Exception as e:
            logger.error(f"Code analysis failed: {e}")
            analysis_results['status'] = 'failed'
            analysis_results['error'] = str(e)
        
        return analysis_results
    
    async def _analyze_code_structure(self, repository_path: str) -> Dict[str, Any]:
        """Analyze overall code structure and architecture"""
        
        structure = {
            'total_files': 0,
            'total_lines': 0,
            'languages': defaultdict(int),
            'frameworks': [],
            'entry_points': [],
            'sensitive_files': [],
            'api_endpoints': [],
            'database_interactions': []
        }
        
        for root, dirs, files in os.walk(repository_path):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv']]
            
            for file in files:
                file_path = os.path.join(root, file)
                structure['total_files'] += 1
                
                # Detect language
                ext = os.path.splitext(file)[1].lower()
                if ext in ['.py', '.js', '.java', '.go', '.rb', '.php', '.cs']:
                    structure['languages'][ext] += 1
                
                # Analyze file
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.splitlines()
                        structure['total_lines'] += len(lines)
                        
                        # Detect entry points
                        if self._is_entry_point(file, content):
                            structure['entry_points'].append(file_path)
                        
                        # Detect sensitive files
                        if self._is_sensitive_file(file, content):
                            structure['sensitive_files'].append(file_path)
                        
                        # Detect API endpoints
                        endpoints = self._extract_api_endpoints(content, ext)
                        structure['api_endpoints'].extend(endpoints)
                        
                        # Detect database interactions
                        db_interactions = self._extract_database_interactions(content, ext)
                        structure['database_interactions'].extend(db_interactions)
                        
                except Exception as e:
                    logger.warning(f"Failed to analyze file {file_path}: {e}")
        
        # Detect frameworks
        structure['frameworks'] = self._detect_frameworks(repository_path)
        
        return structure
    
    async def _detect_vulnerability_patterns(self, repository_path: str) -> List[Dict[str, Any]]:
        """Detect vulnerability patterns in code"""
        
        findings = []
        
        for root, dirs, files in os.walk(repository_path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv']]
            
            for file in files:
                if not self._is_code_file(file):
                    continue
                
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Check each vulnerability pattern
                        for pattern in self.vulnerability_patterns:
                            matches = self._check_pattern(content, pattern)
                            for match in matches:
                                finding = {
                                    'finding_id': self._generate_finding_id(file_path, pattern, match),
                                    'finding_type': pattern['type'],
                                    'severity': pattern['severity'],
                                    'confidence': pattern['confidence'],
                                    'file_path': file_path,
                                    'line_number': match['line_number'],
                                    'code_snippet': match['code_snippet'],
                                    'description': pattern['description'],
                                    'remediation': pattern['remediation']
                                }
                                findings.append(finding)
                                
                except Exception as e:
                    logger.error(f"Failed to analyze file {file_path}: {e}")
        
        return findings
    
    async def _analyze_business_logic(self, repository_path: str) -> List[Dict[str, Any]]:
        """Analyze business logic for security flaws"""
        
        findings = []
        
        # Identify business logic files
        business_files = self._identify_business_logic_files(repository_path)
        
        for file_path in business_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Check for authorization issues
                    auth_issues = self._check_authorization_logic(content, file_path)
                    findings.extend(auth_issues)
                    
                    # Check for race conditions
                    race_conditions = self._check_race_conditions(content, file_path)
                    findings.extend(race_conditions)
                    
                    # Check for improper state management
                    state_issues = self._check_state_management(content, file_path)
                    findings.extend(state_issues)
                    
                    # Check for business rule violations
                    rule_violations = self._check_business_rules(content, file_path)
                    findings.extend(rule_violations)
                    
            except Exception as e:
                logger.error(f"Failed to analyze business logic in {file_path}: {e}")
        
        return findings
    
    async def _analyze_cross_file_vulnerabilities(self, repository_path: str) -> List[Dict[str, Any]]:
        """Analyze vulnerabilities that span multiple files"""
        
        findings = []
        
        # Build dependency graph
        dependency_graph = self._build_dependency_graph(repository_path)
        
        # Check for vulnerable data flows
        data_flow_issues = self._analyze_data_flows(dependency_graph)
        findings.extend(data_flow_issues)
        
        # Check for inconsistent security checks
        inconsistent_checks = self._check_inconsistent_security(dependency_graph)
        findings.extend(inconsistent_checks)
        
        # Check for privilege escalation paths
        priv_escalation = self._check_privilege_escalation_paths(dependency_graph)
        findings.extend(priv_escalation)
        
        return findings
    
    async def _check_security_best_practices(self, repository_path: str) -> List[Dict[str, Any]]:
        """Check for security best practices violations"""
        
        findings = []
        
        # Check for missing security headers
        header_issues = self._check_security_headers(repository_path)
        findings.extend(header_issues)
        
        # Check for insecure configurations
        config_issues = self._check_insecure_configurations(repository_path)
        findings.extend(config_issues)
        
        # Check for missing input validation
        validation_issues = self._check_input_validation(repository_path)
        findings.extend(validation_issues)
        
        # Check for improper error handling
        error_handling_issues = self._check_error_handling(repository_path)
        findings.extend(error_handling_issues)
        
        # Check for missing encryption
        encryption_issues = self._check_encryption_usage(repository_path)
        findings.extend(encryption_issues)
        
        return findings
    
    async def _perform_ai_deep_analysis(self, repository_path: str) -> List[Dict[str, Any]]:
        """Perform AI-powered deep analysis"""
        
        findings = []
        
        # Select high-risk files for deep analysis
        high_risk_files = self._identify_high_risk_files(repository_path)
        
        for file_path in high_risk_files[:50]:  # Limit to prevent timeout
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Use Pure AI Detector
                    context = {
                        'file_path': file_path,
                        'language': self._detect_language(file_path)
                    }
                    
                    ai_vulns = await self.pure_ai_detector.detect_vulnerabilities(content, context)
                    
                    for vuln in ai_vulns:
                        finding = {
                            'finding_id': vuln.vuln_id,
                            'finding_type': vuln.vulnerability_type,
                            'severity': vuln.severity,
                            'confidence': vuln.confidence,
                            'file_path': file_path,
                            'line_numbers': vuln.line_numbers,
                            'description': vuln.description,
                            'exploitation_scenario': vuln.exploitation_scenario,
                            'remediation': vuln.fix_recommendation,
                            'ai_detected': True
                        }
                        findings.append(finding)
                        
            except Exception as e:
                logger.error(f"AI analysis failed for {file_path}: {e}")
        
        return findings
    
    def _load_vulnerability_patterns(self) -> List[Dict[str, Any]]:
        """Load vulnerability detection patterns"""
        
        return [
            {
                'type': 'hardcoded_secret',
                'pattern': r'(?i)(api[_-]?key|api[_-]?secret|password|passwd|pwd|token|secret[_-]?key)\s*=\s*["\'][^"\']+["\']',
                'severity': 'HIGH',
                'confidence': 0.8,
                'description': 'Hardcoded secret detected',
                'remediation': 'Use environment variables or secure secret management'
            },
            {
                'type': 'sql_injection',
                'pattern': r'(?i)(query|execute)\s*\(\s*["\'].*?\+.*?["\']',
                'severity': 'CRITICAL',
                'confidence': 0.9,
                'description': 'Potential SQL injection vulnerability',
                'remediation': 'Use parameterized queries or prepared statements'
            },
            {
                'type': 'command_injection',
                'pattern': r'(?i)(exec|system|eval|subprocess\.call)\s*\([^)]*\+[^)]*\)',
                'severity': 'CRITICAL',
                'confidence': 0.85,
                'description': 'Potential command injection vulnerability',
                'remediation': 'Validate and sanitize user input, use safe APIs'
            },
            {
                'type': 'path_traversal',
                'pattern': r'(?i)(open|file|read|write)\s*\([^)]*\.\.[/\\][^)]*\)',
                'severity': 'HIGH',
                'confidence': 0.75,
                'description': 'Potential path traversal vulnerability',
                'remediation': 'Validate file paths and use safe path joining methods'
            },
            {
                'type': 'weak_crypto',
                'pattern': r'(?i)(md5|sha1|des|rc4)\s*\(',
                'severity': 'MEDIUM',
                'confidence': 0.9,
                'description': 'Weak cryptographic algorithm detected',
                'remediation': 'Use strong cryptographic algorithms (SHA-256, AES, etc.)'
            }
        ]
    
    def _load_security_rules(self) -> List[Dict[str, Any]]:
        """Load security best practice rules"""
        
        return [
            {
                'rule': 'missing_authentication',
                'description': 'API endpoint without authentication',
                'severity': 'HIGH'
            },
            {
                'rule': 'missing_authorization',
                'description': 'Missing authorization checks',
                'severity': 'HIGH'
            },
            {
                'rule': 'sensitive_data_logging',
                'description': 'Logging sensitive data',
                'severity': 'MEDIUM'
            },
            {
                'rule': 'insecure_random',
                'description': 'Using insecure random number generation',
                'severity': 'MEDIUM'
            }
        ]
    
    def _is_entry_point(self, filename: str, content: str) -> bool:
        """Check if file is an application entry point"""
        
        entry_indicators = [
            'if __name__ == "__main__"',
            'app.run(',
            'main()',
            'server.listen(',
            'http.createServer('
        ]
        
        return any(indicator in content for indicator in entry_indicators)
    
    def _is_sensitive_file(self, filename: str, content: str) -> bool:
        """Check if file contains sensitive information"""
        
        sensitive_names = ['config', 'secret', 'credential', 'auth', 'key', 'token']
        
        return any(name in filename.lower() for name in sensitive_names)
    
    def _extract_api_endpoints(self, content: str, ext: str) -> List[str]:
        """Extract API endpoints from code"""
        
        endpoints = []
        
        # Python Flask/Django
        if ext == '.py':
            patterns = [
                r'@app\.route\(["\']([^"\']+)["\']',
                r'@router\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                r'path\(["\']([^"\']+)["\']'
            ]
            
        # JavaScript/Node.js
        elif ext in ['.js', '.ts']:
            patterns = [
                r'app\.(get|post|put|delete)\(["\']([^"\']+)["\']',
                r'router\.(get|post|put|delete)\(["\']([^"\']+)["\']'
            ]
            
        else:
            patterns = []
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            endpoints.extend([m[1] if isinstance(m, tuple) else m for m in matches])
        
        return endpoints
    
    def _extract_database_interactions(self, content: str, ext: str) -> List[str]:
        """Extract database interaction points"""
        
        interactions = []
        
        # SQL queries
        sql_patterns = [
            r'(?i)SELECT\s+.*?\s+FROM\s+(\w+)',
            r'(?i)INSERT\s+INTO\s+(\w+)',
            r'(?i)UPDATE\s+(\w+)\s+SET',
            r'(?i)DELETE\s+FROM\s+(\w+)'
        ]
        
        for pattern in sql_patterns:
            matches = re.findall(pattern, content)
            interactions.extend(matches)
        
        return interactions
    
    def _detect_frameworks(self, repository_path: str) -> List[str]:
        """Detect frameworks used in the repository"""
        
        frameworks = []
        
        # Check for framework-specific files
        framework_files = {
            'package.json': ['nodejs', 'express', 'react', 'angular', 'vue'],
            'requirements.txt': ['python', 'django', 'flask', 'fastapi'],
            'pom.xml': ['java', 'spring'],
            'build.gradle': ['java', 'spring'],
            'go.mod': ['golang'],
            'Gemfile': ['ruby', 'rails'],
            'composer.json': ['php', 'laravel', 'symfony']
        }
        
        for file, fw_list in framework_files.items():
            if os.path.exists(os.path.join(repository_path, file)):
                frameworks.extend(fw_list[:1])  # Add primary language
        
        return frameworks
    
    def _is_code_file(self, filename: str) -> bool:
        """Check if file is a code file"""
        
        code_extensions = [
            '.py', '.js', '.ts', '.java', '.go', '.rb', '.php',
            '.cs', '.cpp', '.c', '.h', '.swift', '.kt', '.scala'
        ]
        
        return any(filename.endswith(ext) for ext in code_extensions)
    
    def _check_pattern(self, content: str, pattern: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check content against vulnerability pattern"""
        
        matches = []
        lines = content.splitlines()
        
        for i, line in enumerate(lines):
            if re.search(pattern['pattern'], line):
                matches.append({
                    'line_number': i + 1,
                    'code_snippet': line.strip()
                })
        
        return matches
    
    def _generate_finding_id(self, file_path: str, pattern: Dict, match: Dict) -> str:
        """Generate unique finding ID"""
        
        data = f"{file_path}:{pattern['type']}:{match['line_number']}"
        return hashlib.md5(data.encode()).hexdigest()[:16]
    
    def _identify_business_logic_files(self, repository_path: str) -> List[str]:
        """Identify files containing business logic"""
        
        business_files = []
        business_indicators = [
            'service', 'controller', 'handler', 'manager',
            'processor', 'validator', 'auth', 'payment'
        ]
        
        for root, dirs, files in os.walk(repository_path):
            for file in files:
                if any(indicator in file.lower() for indicator in business_indicators):
                    business_files.append(os.path.join(root, file))
        
        return business_files
    
    def _check_authorization_logic(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for authorization issues"""
        
        findings = []
        
        # Look for missing authorization checks
        auth_patterns = [
            r'(?i)def\s+\w+.*?:\s*\n(?!.*?(authorize|permission|auth|role))',
            r'(?i)function\s+\w+.*?\{(?!.*?(authorize|permission|auth|role))'
        ]
        
        for pattern in auth_patterns:
            if re.search(pattern, content, re.MULTILINE | re.DOTALL):
                findings.append({
                    'finding_id': self._generate_finding_id(file_path, {'type': 'missing_auth'}, {'line_number': 0}),
                    'finding_type': 'missing_authorization',
                    'severity': 'HIGH',
                    'confidence': 0.7,
                    'file_path': file_path,
                    'description': 'Function may be missing authorization checks',
                    'remediation': 'Add proper authorization checks before processing'
                })
        
        return findings
    
    def _check_race_conditions(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for potential race conditions"""
        
        findings = []
        
        # Look for non-atomic operations
        race_patterns = [
            r'(?i)if.*?exists.*?:\s*\n.*?create',  # Check-then-act
            r'(?i)read.*?\n.*?write.*?\n.*?same\s+variable'  # Read-modify-write
        ]
        
        # Simplified check - in production, use more sophisticated analysis
        if 'thread' in content.lower() or 'async' in content.lower():
            if not ('lock' in content.lower() or 'mutex' in content.lower()):
                findings.append({
                    'finding_id': self._generate_finding_id(file_path, {'type': 'race_condition'}, {'line_number': 0}),
                    'finding_type': 'potential_race_condition',
                    'severity': 'MEDIUM',
                    'confidence': 0.6,
                    'file_path': file_path,
                    'description': 'Concurrent code without proper synchronization',
                    'remediation': 'Use locks, mutexes, or atomic operations'
                })
        
        return findings
    
    def _check_state_management(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for state management issues"""
        
        findings = []
        
        # Check for global mutable state
        if re.search(r'(?i)global\s+\w+\s*=', content):
            findings.append({
                'finding_id': self._generate_finding_id(file_path, {'type': 'global_state'}, {'line_number': 0}),
                'finding_type': 'global_mutable_state',
                'severity': 'MEDIUM',
                'confidence': 0.8,
                'file_path': file_path,
                'description': 'Global mutable state detected',
                'remediation': 'Use proper state management patterns'
            })
        
        return findings
    
    def _check_business_rules(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Check for business rule violations"""
        
        findings = []
        
        # Example: Check for missing validation
        if 'price' in content.lower() or 'amount' in content.lower():
            if not re.search(r'(?i)(validate|check|verify).*?(price|amount)', content):
                findings.append({
                    'finding_id': self._generate_finding_id(file_path, {'type': 'missing_validation'}, {'line_number': 0}),
                    'finding_type': 'missing_business_validation',
                    'severity': 'HIGH',
                    'confidence': 0.7,
                    'file_path': file_path,
                    'description': 'Missing validation for financial values',
                    'remediation': 'Add proper validation for all financial calculations'
                })
        
        return findings
    
    def _build_dependency_graph(self, repository_path: str) -> Dict[str, Any]:
        """Build dependency graph for the codebase"""
        
        # Simplified dependency graph
        graph = {
            'nodes': {},
            'edges': []
        }
        
        # This would be more sophisticated in production
        return graph
    
    def _analyze_data_flows(self, dependency_graph: Dict) -> List[Dict[str, Any]]:
        """Analyze data flows for vulnerabilities"""
        
        # Placeholder for data flow analysis
        return []
    
    def _check_inconsistent_security(self, dependency_graph: Dict) -> List[Dict[str, Any]]:
        """Check for inconsistent security checks"""
        
        # Placeholder for inconsistent security analysis
        return []
    
    def _check_privilege_escalation_paths(self, dependency_graph: Dict) -> List[Dict[str, Any]]:
        """Check for privilege escalation paths"""
        
        # Placeholder for privilege escalation analysis
        return []
    
    def _check_security_headers(self, repository_path: str) -> List[Dict[str, Any]]:
        """Check for missing security headers"""
        
        findings = []
        
        # Look for web framework files
        for root, dirs, files in os.walk(repository_path):
            for file in files:
                if 'server' in file.lower() or 'app' in file.lower():
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Check for security headers
                            security_headers = [
                                'X-Frame-Options',
                                'X-Content-Type-Options',
                                'Content-Security-Policy',
                                'Strict-Transport-Security'
                            ]
                            
                            for header in security_headers:
                                if header not in content:
                                    findings.append({
                                        'finding_id': self._generate_finding_id(file_path, {'type': f'missing_{header}'}, {'line_number': 0}),
                                        'finding_type': 'missing_security_header',
                                        'severity': 'MEDIUM',
                                        'confidence': 0.7,
                                        'file_path': file_path,
                                        'description': f'Missing security header: {header}',
                                        'remediation': f'Add {header} header to HTTP responses'
                                    })
                    except:
                        pass
        
        return findings
    
    def _check_insecure_configurations(self, repository_path: str) -> List[Dict[str, Any]]:
        """Check for insecure configurations"""
        
        findings = []
        
        # Check configuration files
        config_patterns = {
            'debug_enabled': (r'(?i)debug\s*=\s*true', 'Debug mode enabled in production'),
            'weak_secret': (r'(?i)secret.{0,10}=.{1,10}$', 'Weak secret key detected'),
            'permissive_cors': (r'(?i)cors.*?\*', 'Permissive CORS configuration')
        }
        
        for root, dirs, files in os.walk(repository_path):
            for file in files:
                if 'config' in file.lower() or file.endswith(('.yml', '.yaml', '.json', '.env')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for config_type, (pattern, description) in config_patterns.items():
                                if re.search(pattern, content):
                                    findings.append({
                                        'finding_id': self._generate_finding_id(file_path, {'type': config_type}, {'line_number': 0}),
                                        'finding_type': 'insecure_configuration',
                                        'severity': 'MEDIUM',
                                        'confidence': 0.8,
                                        'file_path': file_path,
                                        'description': description,
                                        'remediation': 'Review and secure configuration settings'
                                    })
                    except:
                        pass
        
        return findings
    
    def _check_input_validation(self, repository_path: str) -> List[Dict[str, Any]]:
        """Check for missing input validation"""
        
        # Placeholder - would check for validation patterns
        return []
    
    def _check_error_handling(self, repository_path: str) -> List[Dict[str, Any]]:
        """Check for improper error handling"""
        
        findings = []
        
        error_patterns = [
            (r'except\s*:', 'Bare except clause that catches all exceptions'),
            (r'catch\s*\(\s*\)', 'Empty catch block'),
            (r'(?i)print.*?exception', 'Printing sensitive exception information')
        ]
        
        for root, dirs, files in os.walk(repository_path):
            for file in files:
                if self._is_code_file(file):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for pattern, description in error_patterns:
                                if re.search(pattern, content):
                                    findings.append({
                                        'finding_id': self._generate_finding_id(file_path, {'type': 'error_handling'}, {'line_number': 0}),
                                        'finding_type': 'improper_error_handling',
                                        'severity': 'LOW',
                                        'confidence': 0.7,
                                        'file_path': file_path,
                                        'description': description,
                                        'remediation': 'Implement proper error handling and logging'
                                    })
                    except:
                        pass
        
        return findings
    
    def _check_encryption_usage(self, repository_path: str) -> List[Dict[str, Any]]:
        """Check for missing or weak encryption"""
        
        # Placeholder - would check for encryption patterns
        return []
    
    def _identify_high_risk_files(self, repository_path: str) -> List[str]:
        """Identify high-risk files for deep analysis"""
        
        high_risk_files = []
        risk_indicators = ['auth', 'login', 'payment', 'admin', 'api', 'database', 'security']
        
        for root, dirs, files in os.walk(repository_path):
            for file in files:
                if any(indicator in file.lower() for indicator in risk_indicators):
                    high_risk_files.append(os.path.join(root, file))
        
        return high_risk_files
    
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
            '.c': 'c'
        }
        
        return language_map.get(ext, 'unknown')
    
    def _generate_analysis_insights(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate insights from analysis results"""
        
        findings = results.get('findings', [])
        
        insights = {
            'total_findings': len(findings),
            'severity_distribution': {},
            'top_vulnerability_types': [],
            'high_risk_areas': [],
            'recommendations': []
        }
        
        # Calculate severity distribution
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        for finding in findings:
            severity_counts[finding['severity']] += 1
            type_counts[finding['finding_type']] += 1
        
        insights['severity_distribution'] = dict(severity_counts)
        insights['top_vulnerability_types'] = sorted(
            type_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        # Generate recommendations
        if severity_counts['CRITICAL'] > 0:
            insights['recommendations'].append(
                'Address critical vulnerabilities immediately'
            )
        
        if type_counts.get('missing_authorization', 0) > 3:
            insights['recommendations'].append(
                'Implement comprehensive authorization framework'
            )
        
        return insights
    
    def _calculate_analysis_metrics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate analysis metrics"""
        
        structure = results.get('structure', {})
        findings = results.get('findings', [])
        
        metrics = {
            'code_coverage': {
                'files_analyzed': structure.get('total_files', 0),
                'lines_analyzed': structure.get('total_lines', 0)
            },
            'finding_density': len(findings) / max(structure.get('total_lines', 1), 1) * 1000,
            'risk_score': self._calculate_risk_score(findings),
            'confidence_average': sum(f.get('confidence', 0) for f in findings) / max(len(findings), 1)
        }
        
        return metrics
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score"""
        
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 5,
            'MEDIUM': 2,
            'LOW': 1
        }
        
        total_score = sum(
            severity_weights.get(f['severity'], 1) * f.get('confidence', 0.5)
            for f in findings
        )
        
        # Normalize to 0-100 scale
        return min(total_score, 100)


def lambda_handler(event, context):
    """Lambda handler for autonomous code analyzer"""
    
    import asyncio
    
    analyzer = AutonomousCodeAnalyzer()
    
    repository_path = event.get('repository_path', '/mnt/efs/repos/current')
    scan_config = event.get('scan_config', {})
    
    # Run async analysis
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(analyzer.analyze(repository_path, scan_config))
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
            'scan_id': 'test-code-analysis-123'
        }
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))