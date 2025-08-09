"""
AI Orchestrator
Central orchestration for all AI-powered security features
"""
import json
import asyncio
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import boto3
import logging
from pathlib import Path
import os
from concurrent.futures import ThreadPoolExecutor
import hashlib
import sys

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from .ai_explainability import AIExplainabilityEngine, ConfidenceLevel
from .advanced_features import AISecurityFeatures
from .business_context import BusinessContextEngine
from .incremental_scanner import IncrementalScanner

# Import new AI models
from ai_models.sql_injection_detector import SQLInjectionDetector
from ai_models.threat_intelligence import AISecurityIntelligence
from ai_models.root_cause_analyzer import AIRootCauseAnalyzer
from ai_models.pure_ai_detector import PureAIVulnerabilityDetector
from ai_models.ai_security_sandbox import AISecuritySandbox

logger = logging.getLogger(__name__)

# AWS clients
dynamodb = boto3.resource('dynamodb')
bedrock = boto3.client('bedrock-runtime')
s3 = boto3.client('s3')
step_functions = boto3.client('stepfunctions')

@dataclass
class AIScanResult:
    """Comprehensive AI scan result"""
    scan_id: str
    repository: str
    branch: str
    commit_sha: str
    scan_type: str  # full, incremental, pr, scheduled
    started_at: datetime
    completed_at: Optional[datetime]
    total_findings: int
    critical_findings: int
    high_findings: int
    business_risk_score: float
    ai_confidence_score: float
    scan_status: str  # running, completed, failed
    error_message: Optional[str] = None

class AISecurityOrchestrator:
    """
    Central orchestrator for AI-powered security scanning
    """
    
    def __init__(self):
        # Initialize all AI components
        self.explainability = AIExplainabilityEngine()
        self.ai_features = AISecurityFeatures()
        self.business_context = BusinessContextEngine()
        self.incremental_scanner = IncrementalScanner()
        
        # Initialize new AI models
        self.sql_injection_detector = SQLInjectionDetector()
        self.threat_intelligence = AISecurityIntelligence()
        self.root_cause_analyzer = AIRootCauseAnalyzer()
        self.pure_ai_detector = PureAIVulnerabilityDetector()
        self.ai_sandbox = AISecuritySandbox()
        
        # DynamoDB tables
        self.scans_table = dynamodb.Table(
            os.environ.get('AI_SCANS_TABLE', 'SecurityAuditAIScans')
        )
        self.findings_table = dynamodb.Table(
            os.environ.get('AI_FINDINGS_TABLE', 'SecurityAuditAIFindings')
        )
        
        # Configuration
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
        self.scan_bucket = os.environ.get('SCAN_BUCKET', 'security-audit-scans')
        
        # Thread pool for parallel processing
        self.executor = ThreadPoolExecutor(max_workers=10)
    
    async def orchestrate_security_scan(self,
                                      repository_path: str,
                                      scan_type: str = 'full',
                                      branch: str = 'main',
                                      base_branch: str = None) -> AIScanResult:
        """
        Orchestrate a comprehensive AI-powered security scan
        """
        scan_id = self._generate_scan_id(repository_path, branch)
        scan_result = AIScanResult(
            scan_id=scan_id,
            repository=repository_path,
            branch=branch,
            commit_sha=self._get_current_commit(repository_path),
            scan_type=scan_type,
            started_at=datetime.utcnow(),
            completed_at=None,
            total_findings=0,
            critical_findings=0,
            high_findings=0,
            business_risk_score=0.0,
            ai_confidence_score=0.0,
            scan_status='running'
        )
        
        try:
            # Store scan start
            self._store_scan_start(scan_result)
            
            # Determine files to scan
            files_to_scan = await self._determine_files_to_scan(
                repository_path, scan_type, branch, base_branch
            )
            
            logger.info(f"Scanning {len(files_to_scan)} files for {repository_path}")
            
            # Parallel AI analysis
            findings = await self._parallel_ai_analysis(files_to_scan, scan_id)
            
            # Aggregate results
            scan_result = await self._aggregate_results(scan_result, findings)
            
            # Generate AI insights
            insights = await self._generate_ai_insights(findings, scan_result)
            
            # Store results
            await self._store_scan_results(scan_result, findings, insights)
            
            scan_result.scan_status = 'completed'
            scan_result.completed_at = datetime.utcnow()
            
        except Exception as e:
            logger.error(f"Scan orchestration failed: {e}")
            scan_result.scan_status = 'failed'
            scan_result.error_message = str(e)
        
        finally:
            # Update scan status
            self._update_scan_status(scan_result)
        
        return scan_result
    
    async def _determine_files_to_scan(self,
                                     repository_path: str,
                                     scan_type: str,
                                     branch: str,
                                     base_branch: Optional[str]) -> List[str]:
        """Determine which files to scan based on scan type"""
        
        if scan_type == 'incremental':
            # Use incremental scanner
            files = self.incremental_scanner.get_files_to_scan(repository_path)
        elif scan_type == 'pr' and base_branch:
            # Get files changed in PR
            files = self._get_pr_changed_files(repository_path, branch, base_branch)
        else:
            # Full scan - get all code files
            files = self._get_all_code_files(repository_path)
        
        return files
    
    async def _parallel_ai_analysis(self, 
                                  files: List[str], 
                                  scan_id: str) -> List[Dict[str, Any]]:
        """Perform parallel AI analysis on files"""
        
        # Create tasks for parallel processing
        tasks = []
        for file_path in files:
            task = asyncio.create_task(
                self._analyze_file_with_ai(file_path, scan_id)
            )
            tasks.append(task)
        
        # Process in batches to avoid overwhelming the system
        batch_size = 10
        all_findings = []
        
        for i in range(0, len(tasks), batch_size):
            batch_tasks = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"File analysis failed: {result}")
                elif result:
                    all_findings.extend(result)
        
        return all_findings
    
    async def _analyze_file_with_ai(self, 
                                  file_path: str, 
                                  scan_id: str) -> List[Dict[str, Any]]:
        """Analyze a single file with AI"""
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            # Skip if file is too large
            if len(code) > 100000:  # 100KB limit
                logger.warning(f"Skipping large file: {file_path}")
                return []
            
            # Detect language
            language = self._detect_language(file_path)
            
            # Extract dependencies if applicable
            dependencies = self._extract_dependencies(code, language)
            
            # Prepare context for new AI components
            context = {
                'file_path': file_path,
                'language': language,
                'repository_path': os.path.dirname(file_path),
                'framework': self._detect_framework(code, language)
            }
            
            # Use Pure AI Detector for vulnerability detection
            ai_vulnerabilities = await self.pure_ai_detector.detect_vulnerabilities(code, context)
            
            # SQL Injection specific detection
            if language in ['python', 'java', 'javascript', 'php', 'ruby']:
                sql_detection = self.sql_injection_detector.detect(code, context)
                if sql_detection.is_vulnerable:
                    sql_vuln = self._convert_sql_to_vuln(sql_detection, file_path)
                    self._create_finding(scan_id, file_path, 'vulnerability', sql_vuln, {})
            
            # Comprehensive AI analysis
            analysis = self.ai_features.comprehensive_ai_analysis(
                code=code,
                file_path=file_path,
                dependencies=dependencies,
                language=language
            )
            
            # Add pure AI vulnerabilities to analysis
            if ai_vulnerabilities:
                analysis['ai_vulnerabilities'] = [vars(v) for v in ai_vulnerabilities]
            
            # Convert to findings format
            findings = []
            
            # Process vulnerabilities
            for vuln in analysis.get('vulnerabilities', []):
                finding = self._create_finding(
                    scan_id, file_path, 'vulnerability', vuln, analysis
                )
                findings.append(finding)
            
            # Process policy violations
            for violation in analysis.get('policy_violations', []):
                finding = self._create_finding(
                    scan_id, file_path, 'policy_violation', violation, analysis
                )
                findings.append(finding)
            
            # Process supply chain risks
            for package, risks in analysis.get('supply_chain_risks', {}).items():
                for risk in risks:
                    finding = self._create_finding(
                        scan_id, file_path, 'supply_chain', risk, analysis, package
                    )
                    findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Failed to analyze {file_path}: {e}")
            return []
    
    def _create_finding(self,
                       scan_id: str,
                       file_path: str,
                       finding_type: str,
                       finding_data: Any,
                       analysis: Dict[str, Any],
                       package_name: str = None) -> Dict[str, Any]:
        """Create a standardized finding object"""
        
        # Generate unique finding ID
        finding_id = hashlib.sha256(
            f"{scan_id}:{file_path}:{finding_type}:{str(finding_data)}".encode()
        ).hexdigest()[:16]
        
        # Extract severity and confidence
        if hasattr(finding_data, 'severity'):
            severity = finding_data.severity
        else:
            severity = finding_data.get('severity', 'MEDIUM')
        
        if hasattr(finding_data, 'ai_confidence'):
            confidence = finding_data.ai_confidence
        else:
            confidence = finding_data.get('confidence', 0.8)
        
        # Get business context
        business_score = self.business_context.calculate_business_risk_score(
            {
                'file': file_path,
                'severity': severity,
                'type': finding_type
            }
        )
        
        # Generate explanation
        explanation = self.explainability.generate_explanation(
            finding={
                'file': file_path,
                'type': finding_type,
                'severity': severity,
                'confidence': confidence,
                'message': str(finding_data)
            },
            ai_response=json.dumps(analysis),
            model_id=self.model_id,
            processing_time_ms=100,
            tokens_used=1000
        )
        
        return {
            'finding_id': finding_id,
            'scan_id': scan_id,
            'file_path': file_path,
            'finding_type': finding_type,
            'severity': severity,
            'confidence': confidence,
            'confidence_level': explanation.confidence_level.value,
            'business_risk_score': business_score,
            'description': self._get_finding_description(finding_data),
            'remediation': self._get_remediation_advice(finding_data),
            'evidence': [e.to_dynamodb_item() for e in explanation.evidence_list],
            'reasoning': explanation.reasoning_chain,
            'false_positive_indicators': explanation.false_positive_indicators,
            'package_name': package_name,
            'created_at': datetime.utcnow().isoformat()
        }
    
    async def _aggregate_results(self,
                               scan_result: AIScanResult,
                               findings: List[Dict[str, Any]]) -> AIScanResult:
        """Aggregate findings into scan result"""
        
        scan_result.total_findings = len(findings)
        
        # Count by severity
        for finding in findings:
            severity = finding['severity']
            if severity == 'CRITICAL':
                scan_result.critical_findings += 1
            elif severity == 'HIGH':
                scan_result.high_findings += 1
        
        # Calculate business risk score
        if findings:
            scan_result.business_risk_score = sum(
                f['business_risk_score'] for f in findings
            ) / len(findings)
        
        # Calculate AI confidence score
        if findings:
            scan_result.ai_confidence_score = sum(
                f['confidence'] for f in findings
            ) / len(findings)
        
        return scan_result
    
    async def _generate_ai_insights(self,
                                  findings: List[Dict[str, Any]],
                                  scan_result: AIScanResult) -> Dict[str, Any]:
        """Generate high-level AI insights from findings"""
        
        if not findings:
            return {
                'summary': 'No security issues detected',
                'recommendations': [],
                'risk_assessment': 'Low'
            }
        
        # Prepare findings summary for AI
        findings_summary = {
            'total': len(findings),
            'by_severity': {},
            'by_type': {},
            'top_risks': []
        }
        
        # Aggregate by severity and type
        for finding in findings:
            sev = finding['severity']
            ftype = finding['finding_type']
            
            findings_summary['by_severity'][sev] = findings_summary['by_severity'].get(sev, 0) + 1
            findings_summary['by_type'][ftype] = findings_summary['by_type'].get(ftype, 0) + 1
        
        # Get top 10 risks
        sorted_findings = sorted(findings, key=lambda x: x['business_risk_score'], reverse=True)
        findings_summary['top_risks'] = [
            {
                'file': f['file_path'],
                'type': f['finding_type'],
                'severity': f['severity'],
                'description': f['description'][:200]
            }
            for f in sorted_findings[:10]
        ]
        
        # Generate insights with AI
        prompt = f"""You are a security expert providing executive insights from a security scan.

Scan Results:
{json.dumps(findings_summary, indent=2)}

Business Risk Score: {scan_result.business_risk_score:.2f}
AI Confidence Score: {scan_result.ai_confidence_score:.2f}

Provide:
1. Executive summary (2-3 sentences)
2. Top 3 actionable recommendations
3. Risk assessment (Critical/High/Medium/Low)
4. Comparison to industry standards
5. Remediation priority order

Format as JSON:
{{
  "executive_summary": "...",
  "key_recommendations": ["rec1", "rec2", "rec3"],
  "risk_assessment": "Critical|High|Medium|Low",
  "industry_comparison": "...",
  "remediation_priorities": ["priority1", "priority2", "..."]
}}"""

        try:
            response = bedrock.invoke_model(
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
            insights = json.loads(response_body['content'][0]['text'])
            
            return insights
            
        except Exception as e:
            logger.error(f"Failed to generate AI insights: {e}")
            return {
                'executive_summary': f"Found {len(findings)} security issues requiring attention",
                'key_recommendations': ['Review critical findings', 'Update dependencies', 'Fix policy violations'],
                'risk_assessment': 'High' if scan_result.critical_findings > 0 else 'Medium',
                'industry_comparison': 'Unable to generate comparison',
                'remediation_priorities': ['Critical issues', 'High severity findings', 'Policy violations']
            }
    
    async def _store_scan_results(self,
                                scan_result: AIScanResult,
                                findings: List[Dict[str, Any]],
                                insights: Dict[str, Any]):
        """Store scan results in DynamoDB and S3"""
        
        # Store each finding
        for finding in findings:
            try:
                self.findings_table.put_item(Item=finding)
            except Exception as e:
                logger.error(f"Failed to store finding: {e}")
        
        # Store detailed report in S3
        report = {
            'scan_result': scan_result.__dict__,
            'findings': findings,
            'insights': insights,
            'generated_at': datetime.utcnow().isoformat()
        }
        
        try:
            s3.put_object(
                Bucket=self.scan_bucket,
                Key=f"reports/{scan_result.scan_id}.json",
                Body=json.dumps(report, default=str),
                ContentType='application/json'
            )
        except Exception as e:
            logger.error(f"Failed to store report in S3: {e}")
    
    def _generate_scan_id(self, repository: str, branch: str) -> str:
        """Generate unique scan ID"""
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        return f"{repository.replace('/', '-')}_{branch}_{timestamp}"
    
    def _get_current_commit(self, repository_path: str) -> str:
        """Get current Git commit SHA"""
        try:
            import subprocess
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=repository_path,
                capture_output=True,
                text=True
            )
            return result.stdout.strip()[:8]
        except:
            return 'unknown'
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext_to_lang = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.rs': 'rust',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c'
        }
        
        ext = Path(file_path).suffix.lower()
        return ext_to_lang.get(ext, 'unknown')
    
    def _extract_dependencies(self, code: str, language: str) -> Dict[str, str]:
        """Extract dependencies from code"""
        dependencies = {}
        
        if language == 'python':
            # Look for import statements
            import re
            imports = re.findall(r'^\s*(?:from|import)\s+(\S+)', code, re.MULTILINE)
            for imp in imports:
                pkg = imp.split('.')[0]
                if not pkg.startswith('_') and pkg not in ['os', 'sys', 'json']:
                    dependencies[pkg] = 'latest'
        
        elif language == 'javascript':
            # Look for require/import
            import re
            requires = re.findall(r'require\([\'"](.+?)[\'"]\)', code)
            imports = re.findall(r'import\s+.*?\s+from\s+[\'"](.+?)[\'"]', code)
            for dep in requires + imports:
                if not dep.startswith('.'):
                    dependencies[dep] = 'latest'
        
        # Add more language-specific extraction as needed
        
        return dependencies
    
    def _get_pr_changed_files(self, 
                            repository_path: str,
                            branch: str,
                            base_branch: str) -> List[str]:
        """Get files changed in a PR"""
        try:
            import subprocess
            result = subprocess.run(
                ['git', 'diff', '--name-only', f'{base_branch}...{branch}'],
                cwd=repository_path,
                capture_output=True,
                text=True
            )
            
            files = []
            for file in result.stdout.strip().split('\n'):
                if file and self._is_code_file(file):
                    full_path = os.path.join(repository_path, file)
                    if os.path.exists(full_path):
                        files.append(full_path)
            
            return files
        except Exception as e:
            logger.error(f"Failed to get PR files: {e}")
            return []
    
    def _get_all_code_files(self, repository_path: str) -> List[str]:
        """Get all code files in repository"""
        code_extensions = {
            '.py', '.js', '.ts', '.java', '.go', '.rs', '.rb', '.php',
            '.cs', '.cpp', '.c', '.h', '.hpp', '.jsx', '.tsx', '.vue'
        }
        
        files = []
        for root, _, filenames in os.walk(repository_path):
            # Skip hidden directories
            if '/.git' in root or '/node_modules' in root or '/__pycache__' in root:
                continue
            
            for filename in filenames:
                if Path(filename).suffix.lower() in code_extensions:
                    files.append(os.path.join(root, filename))
        
        return files
    
    def _is_code_file(self, file_path: str) -> bool:
        """Check if file is a code file"""
        code_extensions = {
            '.py', '.js', '.ts', '.java', '.go', '.rs', '.rb', '.php',
            '.cs', '.cpp', '.c', '.h', '.hpp', '.jsx', '.tsx', '.vue'
        }
        return Path(file_path).suffix.lower() in code_extensions
    
    def _get_finding_description(self, finding_data: Any) -> str:
        """Extract description from finding data"""
        if hasattr(finding_data, 'vulnerability_description'):
            return finding_data.vulnerability_description
        elif hasattr(finding_data, 'violation_details'):
            return finding_data.violation_details
        elif hasattr(finding_data, 'description'):
            return finding_data.description
        else:
            return str(finding_data)
    
    def _get_remediation_advice(self, finding_data: Any) -> str:
        """Extract remediation advice from finding data"""
        if hasattr(finding_data, 'remediation_advice'):
            return finding_data.remediation_advice
        elif hasattr(finding_data, 'suggested_fix'):
            return finding_data.suggested_fix
        elif hasattr(finding_data, 'remediation'):
            return finding_data.remediation
        else:
            return "Review and fix the identified security issue"
    
    def _store_scan_start(self, scan_result: AIScanResult):
        """Store scan start in DynamoDB"""
        try:
            self.scans_table.put_item(
                Item={
                    'scan_id': scan_result.scan_id,
                    'repository': scan_result.repository,
                    'branch': scan_result.branch,
                    'commit_sha': scan_result.commit_sha,
                    'scan_type': scan_result.scan_type,
                    'started_at': scan_result.started_at.isoformat(),
                    'scan_status': scan_result.scan_status
                }
            )
        except Exception as e:
            logger.error(f"Failed to store scan start: {e}")
    
    def _update_scan_status(self, scan_result: AIScanResult):
        """Update scan status in DynamoDB"""
        try:
            update_expr = "SET scan_status = :status, total_findings = :total, critical_findings = :critical, " \
                         "high_findings = :high, business_risk_score = :risk, ai_confidence_score = :conf"
            
            expr_values = {
                ':status': scan_result.scan_status,
                ':total': scan_result.total_findings,
                ':critical': scan_result.critical_findings,
                ':high': scan_result.high_findings,
                ':risk': scan_result.business_risk_score,
                ':conf': scan_result.ai_confidence_score
            }
            
            if scan_result.completed_at:
                update_expr += ", completed_at = :completed"
                expr_values[':completed'] = scan_result.completed_at.isoformat()
            
            if scan_result.error_message:
                update_expr += ", error_message = :error"
                expr_values[':error'] = scan_result.error_message
            
            self.scans_table.update_item(
                Key={'scan_id': scan_result.scan_id},
                UpdateExpression=update_expr,
                ExpressionAttributeValues=expr_values
            )
        except Exception as e:
            logger.error(f"Failed to update scan status: {e}")


# Async wrapper for CLI integration
def run_ai_scan(repository_path: str, scan_type: str = 'full') -> Dict[str, Any]:
    """Synchronous wrapper for AI scan orchestration"""
    orchestrator = AISecurityOrchestrator()
    
    # Run async scan
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        scan_result = loop.run_until_complete(
            orchestrator.orchestrate_security_scan(repository_path, scan_type)
        )
        
        return {
            'scan_id': scan_result.scan_id,
            'status': scan_result.scan_status,
            'total_findings': scan_result.total_findings,
            'critical_findings': scan_result.critical_findings,
            'high_findings': scan_result.high_findings,
            'business_risk_score': scan_result.business_risk_score,
            'ai_confidence_score': scan_result.ai_confidence_score,
            'error': scan_result.error_message
        }
    finally:
        loop.close()


# Extension methods for new AI components
class AISecurityOrchestratorExtensions:
    """Extensions to the AISecurityOrchestrator for new AI components"""
    
    def _convert_sql_to_vuln(self, sql_detection, file_path: str) -> Dict[str, Any]:
        """Convert SQL injection detection to vulnerability format"""
        return {
            'vuln_id': sql_detection.vuln_id if hasattr(sql_detection, 'vuln_id') else 'sql_' + hashlib.sha256(str(sql_detection).encode()).hexdigest()[:8],
            'vulnerability_type': 'sql_injection',
            'description': sql_detection.description,
            'severity': sql_detection.severity,
            'confidence': sql_detection.confidence,
            'file_path': file_path,
            'line_numbers': sql_detection.line_numbers,
            'code_snippet': sql_detection.code_snippet,
            'exploitation_scenario': sql_detection.exploitation_scenario,
            'fix_recommendation': sql_detection.remediation,
            'ai_reasoning': sql_detection.ai_reasoning,
            'detection_method': 'sql_injection_detector'
        }
    
    def _detect_framework(self, code: str, language: str) -> str:
        """Detect framework from code"""
        frameworks = {
            'python': ['django', 'flask', 'fastapi', 'pyramid'],
            'javascript': ['express', 'react', 'vue', 'angular'],
            'java': ['spring', 'struts', 'jersey'],
            'php': ['laravel', 'symfony', 'codeigniter'],
            'ruby': ['rails', 'sinatra']
        }
        
        detected = 'unknown'
        if language in frameworks:
            for framework in frameworks[language]:
                if framework in code.lower():
                    detected = framework
                    break
        
        return detected
    
    async def perform_threat_intelligence_analysis(self,
                                                  repository_path: str,
                                                  scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform threat intelligence analysis on scan results"""
        try:
            # Extract code patterns from findings
            code_patterns = []
            for finding in scan_results.get('findings', []):
                if 'code_snippet' in finding:
                    code_patterns.append(finding['code_snippet'])
            
            # Get technology stack
            tech_stack = self._extract_technology_stack(repository_path)
            
            # Analyze global threats
            threats = await self.threat_intelligence.analyze_global_threats(
                code_patterns[:20],  # Limit for performance
                tech_stack
            )
            
            # Predict future vulnerabilities
            historical_vulns = self._get_historical_vulnerabilities(repository_path)
            predictions = await self.threat_intelligence.predict_vulnerabilities(
                {'repository': repository_path, 'tech_stack': tech_stack},
                historical_vulns
            )
            
            return {
                'threats': [self._threat_to_dict(t) for t in threats],
                'predictions': [self._prediction_to_dict(p) for p in predictions],
                'risk_assessment': self._calculate_threat_risk(threats, predictions)
            }
            
        except Exception as e:
            logger.error(f"Threat intelligence analysis failed: {e}")
            return {'error': str(e)}
    
    async def analyze_incident(self,
                             incident_id: str,
                             incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform AI-driven root cause analysis for an incident"""
        try:
            # Get logs for the incident
            logs = self._get_incident_logs(incident_id)
            
            # Get related alerts
            related_alerts = self._get_related_alerts(incident_id)
            
            # Perform root cause analysis
            analysis = await self.root_cause_analyzer.analyze_incident(
                incident_data,
                logs,
                related_alerts
            )
            
            return {
                'incident_id': incident_id,
                'root_causes': analysis.root_causes,
                'contributing_factors': analysis.contributing_factors,
                'timeline': analysis.timeline,
                'impact_assessment': analysis.impact_assessment,
                'remediation_steps': analysis.remediation_steps,
                'prevention_measures': analysis.prevention_measures,
                'confidence_score': analysis.confidence_score,
                'analysis_reasoning': analysis.analysis_reasoning
            }
            
        except Exception as e:
            logger.error(f"Incident analysis failed: {e}")
            return {'error': str(e)}
    
    async def test_vulnerability_in_sandbox(self,
                                          vulnerability: Dict[str, Any],
                                          code_context: str,
                                          proposed_fix: Optional[str] = None) -> Dict[str, Any]:
        """Test a vulnerability in AI security sandbox"""
        try:
            # Run sandbox test
            report = await self.ai_sandbox.test_vulnerability(
                vulnerability,
                code_context,
                proposed_fix
            )
            
            return {
                'sandbox_id': report.sandbox_id,
                'vulnerability_confirmed': any(test.success for test in report.exploit_results),
                'exploit_tests': len(report.exploit_results),
                'successful_exploits': sum(1 for test in report.exploit_results if test.success),
                'fix_effective': all(fix.fix_effective for fix in report.fix_validations) if report.fix_validations else None,
                'risk_reduction': report.risk_reduction,
                'recommendations': report.recommendations,
                'duration_seconds': report.duration_seconds
            }
            
        except Exception as e:
            logger.error(f"Sandbox testing failed: {e}")
            return {'error': str(e)}
    
    def _extract_technology_stack(self, repository_path: str) -> List[str]:
        """Extract technology stack from repository"""
        tech_stack = []
        
        # Check package files
        package_files = {
            'package.json': 'nodejs',
            'requirements.txt': 'python',
            'pom.xml': 'java',
            'Gemfile': 'ruby',
            'composer.json': 'php',
            'go.mod': 'golang'
        }
        
        for file, tech in package_files.items():
            if os.path.exists(os.path.join(repository_path, file)):
                tech_stack.append(tech)
        
        return tech_stack
    
    def _get_historical_vulnerabilities(self, repository_path: str) -> List[Dict]:
        """Get historical vulnerabilities for repository"""
        # In production, would query from database
        return []
    
    def _threat_to_dict(self, threat) -> Dict[str, Any]:
        """Convert threat intelligence object to dict"""
        return {
            'threat_id': threat.threat_id,
            'threat_type': threat.threat_type,
            'threat_name': threat.threat_name,
            'description': threat.description,
            'severity': threat.severity,
            'likelihood': threat.likelihood,
            'attack_vectors': threat.attack_vectors,
            'mitigation_strategies': threat.mitigation_strategies
        }
    
    def _prediction_to_dict(self, prediction) -> Dict[str, Any]:
        """Convert vulnerability prediction to dict"""
        return {
            'prediction_id': prediction.prediction_id,
            'vulnerability_type': prediction.vulnerability_type,
            'affected_component': prediction.affected_component,
            'predicted_severity': prediction.predicted_severity,
            'likelihood_of_discovery': prediction.likelihood_of_discovery,
            'preventive_measures': prediction.preventive_measures
        }
    
    def _calculate_threat_risk(self, threats, predictions) -> Dict[str, Any]:
        """Calculate overall threat risk"""
        critical_threats = sum(1 for t in threats if t.severity == 'CRITICAL')
        high_likelihood_predictions = sum(1 for p in predictions if p.likelihood_of_discovery > 0.7)
        
        risk_score = (critical_threats * 10 + high_likelihood_predictions * 5) / max(len(threats) + len(predictions), 1)
        
        return {
            'risk_score': min(10, risk_score),
            'critical_threats': critical_threats,
            'high_risk_predictions': high_likelihood_predictions,
            'risk_level': 'CRITICAL' if risk_score > 7 else 'HIGH' if risk_score > 5 else 'MEDIUM'
        }
    
    def _get_incident_logs(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get logs related to incident"""
        # In production, would query CloudWatch logs
        return []
    
    def _get_related_alerts(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get alerts related to incident"""
        # In production, would query alert database
        return []
        loop.close()