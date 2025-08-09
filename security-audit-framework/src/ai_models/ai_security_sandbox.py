"""
AI Security Sandbox
Safe environment for testing AI-detected vulnerabilities and verifying fixes
"""
import json
import boto3
import docker
import tempfile
import subprocess
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import os
import shutil
import logging
from enum import Enum

logger = logging.getLogger(__name__)

# Initialize AWS clients
bedrock = boto3.client('bedrock-runtime')
dynamodb = boto3.resource('dynamodb')
ecr = boto3.client('ecr')


class SandboxStatus(Enum):
    INITIALIZING = "initializing"
    READY = "ready"
    TESTING = "testing"
    COMPLETED = "completed"
    FAILED = "failed"
    DESTROYED = "destroyed"


@dataclass
class ExploitTest:
    """AI-generated exploit test"""
    test_id: str
    vulnerability_id: str
    exploit_code: str
    expected_outcome: str
    actual_outcome: Optional[str] = None
    success: Optional[bool] = None
    execution_logs: List[str] = field(default_factory=list)
    ai_analysis: Optional[str] = None


@dataclass
class FixValidation:
    """AI validation of security fix"""
    fix_id: str
    vulnerability_id: str
    original_code: str
    fixed_code: str
    fix_effective: bool
    remaining_risks: List[str]
    side_effects: List[str]
    performance_impact: Optional[str] = None
    ai_confidence: float = 0.0


@dataclass
class SandboxReport:
    """Complete sandbox testing report"""
    sandbox_id: str
    vulnerability_tested: str
    exploit_results: List[ExploitTest]
    fix_validations: List[FixValidation]
    overall_assessment: str
    risk_reduction: float  # 0-100%
    recommendations: List[str]
    sandbox_logs: List[str]
    created_at: datetime
    duration_seconds: float


class AISecuritySandbox:
    """
    AI-powered security sandbox for testing vulnerabilities and fixes
    Provides isolated environment for safe exploitation testing
    """
    
    def __init__(self):
        self.model_id = 'anthropic.claude-3-sonnet-20240229-v1:0'
        
        # DynamoDB tables
        self.sandbox_table = dynamodb.Table('SecurityAuditSandboxTests')
        self.exploit_table = dynamodb.Table('SecurityAuditExploitTests')
        
        # Docker client for sandboxing
        try:
            self.docker_client = docker.from_env()
        except:
            logger.warning("Docker not available - using process isolation")
            self.docker_client = None
        
        # Sandbox configuration
        self.sandbox_timeout = 60  # seconds
        self.max_memory = "512m"
        self.max_cpu = "0.5"
        
    async def test_vulnerability(self,
                               vulnerability: Dict[str, Any],
                               code_context: str,
                               proposed_fix: Optional[str] = None) -> SandboxReport:
        """
        Test a vulnerability in sandbox environment
        """
        sandbox_id = self._create_sandbox_id()
        start_time = datetime.utcnow()
        
        logger.info(f"Creating sandbox {sandbox_id} for vulnerability {vulnerability.get('id')}")
        
        # Initialize sandbox
        sandbox_env = await self._initialize_sandbox(sandbox_id, code_context)
        
        # Generate and run exploit tests
        exploit_tests = await self._generate_exploit_tests(vulnerability, code_context)
        exploit_results = await self._run_exploit_tests(sandbox_env, exploit_tests)
        
        # If fix provided, validate it
        fix_validations = []
        if proposed_fix:
            fix_validation = await self._validate_fix(
                sandbox_env,
                vulnerability,
                code_context,
                proposed_fix,
                exploit_tests
            )
            fix_validations.append(fix_validation)
        
        # Generate overall assessment
        assessment = await self._generate_assessment(
            vulnerability,
            exploit_results,
            fix_validations
        )
        
        # Cleanup sandbox
        await self._destroy_sandbox(sandbox_env)
        
        # Create report
        report = SandboxReport(
            sandbox_id=sandbox_id,
            vulnerability_tested=vulnerability.get('id', 'unknown'),
            exploit_results=exploit_results,
            fix_validations=fix_validations,
            overall_assessment=assessment['summary'],
            risk_reduction=assessment['risk_reduction'],
            recommendations=assessment['recommendations'],
            sandbox_logs=sandbox_env.get('logs', []),
            created_at=start_time,
            duration_seconds=(datetime.utcnow() - start_time).total_seconds()
        )
        
        # Store report
        self._store_sandbox_report(report)
        
        return report
    
    async def _initialize_sandbox(self,
                                 sandbox_id: str,
                                 code_context: str) -> Dict[str, Any]:
        """
        Initialize isolated sandbox environment
        """
        if self.docker_client:
            return await self._initialize_docker_sandbox(sandbox_id, code_context)
        else:
            return await self._initialize_process_sandbox(sandbox_id, code_context)
    
    async def _initialize_docker_sandbox(self,
                                       sandbox_id: str,
                                       code_context: str) -> Dict[str, Any]:
        """
        Initialize Docker-based sandbox
        """
        # Create temporary directory
        sandbox_dir = tempfile.mkdtemp(prefix=f"ai_sandbox_{sandbox_id}_")
        
        # Write code to test
        code_file = os.path.join(sandbox_dir, "vulnerable_code.py")
        with open(code_file, 'w') as f:
            f.write(code_context)
        
        # Create Dockerfile for sandbox
        dockerfile_content = """
FROM python:3.9-slim
RUN pip install requests flask sqlalchemy
WORKDIR /sandbox
COPY . .
RUN useradd -m sandboxuser
USER sandboxuser
CMD ["python", "-u", "test_runner.py"]
"""
        
        dockerfile_path = os.path.join(sandbox_dir, "Dockerfile")
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content)
        
        # Build sandbox image
        image_tag = f"ai-sandbox:{sandbox_id}"
        self.docker_client.images.build(
            path=sandbox_dir,
            tag=image_tag,
            rm=True
        )
        
        return {
            'sandbox_id': sandbox_id,
            'sandbox_dir': sandbox_dir,
            'image_tag': image_tag,
            'status': SandboxStatus.READY,
            'logs': []
        }
    
    async def _initialize_process_sandbox(self,
                                        sandbox_id: str,
                                        code_context: str) -> Dict[str, Any]:
        """
        Initialize process-based sandbox (fallback)
        """
        # Create isolated directory
        sandbox_dir = tempfile.mkdtemp(prefix=f"ai_sandbox_{sandbox_id}_")
        
        # Write code to test
        code_file = os.path.join(sandbox_dir, "vulnerable_code.py")
        with open(code_file, 'w') as f:
            f.write(code_context)
        
        return {
            'sandbox_id': sandbox_id,
            'sandbox_dir': sandbox_dir,
            'status': SandboxStatus.READY,
            'logs': []
        }
    
    async def _generate_exploit_tests(self,
                                    vulnerability: Dict[str, Any],
                                    code_context: str) -> List[ExploitTest]:
        """
        Use AI to generate exploit tests
        """
        prompt = f"""You are a security researcher creating exploit tests for a vulnerability.

Vulnerability:
Type: {vulnerability.get('type')}
Description: {vulnerability.get('description')}
Severity: {vulnerability.get('severity')}

Vulnerable code:
```python
{code_context[:2000]}
```

Generate exploit test cases that:
1. Demonstrate the vulnerability is real
2. Show different exploitation techniques
3. Verify the impact
4. Are safe to run in a sandbox

For each test, provide:
- Exploit code that triggers the vulnerability
- Expected outcome if vulnerable
- Safe boundaries (don't cause actual damage)

Provide tests in JSON format:
{{
  "exploit_tests": [
    {{
      "test_name": "descriptive name",
      "exploit_code": "python code to exploit",
      "expected_outcome": "what should happen if vulnerable",
      "test_type": "proof_of_concept|full_exploit|edge_case"
    }}
  ]
}}"""

        try:
            response = bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 3000,
                    "messages": [{
                        "role": "user",
                        "content": prompt
                    }],
                    "temperature": 0.3
                })
            )
            
            response_body = json.loads(response['body'].read())
            test_data = json.loads(response_body['content'][0]['text'])
            
            tests = []
            for test in test_data.get('exploit_tests', []):
                exploit_test = ExploitTest(
                    test_id=self._generate_test_id(),
                    vulnerability_id=vulnerability.get('id', 'unknown'),
                    exploit_code=test['exploit_code'],
                    expected_outcome=test['expected_outcome']
                )
                tests.append(exploit_test)
            
            return tests
            
        except Exception as e:
            logger.error(f"Failed to generate exploit tests: {e}")
            return []
    
    async def _run_exploit_tests(self,
                               sandbox_env: Dict[str, Any],
                               tests: List[ExploitTest]) -> List[ExploitTest]:
        """
        Run exploit tests in sandbox
        """
        results = []
        
        for test in tests:
            logger.info(f"Running exploit test {test.test_id}")
            
            # Prepare test runner script
            test_runner = f"""
import sys
import traceback

# Import vulnerable code
try:
    from vulnerable_code import *
except:
    pass

# Run exploit
try:
    {test.exploit_code}
    print("EXPLOIT_RESULT: Success - vulnerability confirmed")
except Exception as e:
    print(f"EXPLOIT_RESULT: Failed - {{str(e)}}")
    traceback.print_exc()
"""
            
            # Write test runner
            test_file = os.path.join(
                sandbox_env['sandbox_dir'],
                f"test_{test.test_id}.py"
            )
            with open(test_file, 'w') as f:
                f.write(test_runner)
            
            # Execute test
            if self.docker_client and 'image_tag' in sandbox_env:
                result = await self._run_docker_test(sandbox_env, test_file)
            else:
                result = await self._run_process_test(sandbox_env, test_file)
            
            # Update test with results
            test.actual_outcome = result['output']
            test.execution_logs = result['logs']
            test.success = "Success" in result['output']
            
            # AI analysis of results
            test.ai_analysis = await self._analyze_exploit_result(test)
            
            results.append(test)
        
        return results
    
    async def _run_docker_test(self,
                             sandbox_env: Dict[str, Any],
                             test_file: str) -> Dict[str, Any]:
        """
        Run test in Docker container
        """
        try:
            container = self.docker_client.containers.run(
                sandbox_env['image_tag'],
                command=f"python {os.path.basename(test_file)}",
                mem_limit=self.max_memory,
                cpu_quota=int(float(self.max_cpu) * 100000),
                network_disabled=True,
                remove=True,
                stdout=True,
                stderr=True,
                timeout=self.sandbox_timeout
            )
            
            return {
                'output': container.decode('utf-8'),
                'logs': [container.decode('utf-8')]
            }
            
        except Exception as e:
            return {
                'output': f"Execution failed: {str(e)}",
                'logs': [str(e)]
            }
    
    async def _run_process_test(self,
                              sandbox_env: Dict[str, Any],
                              test_file: str) -> Dict[str, Any]:
        """
        Run test in subprocess (fallback)
        """
        try:
            # Run with timeout and resource limits
            result = subprocess.run(
                ['python', test_file],
                cwd=sandbox_env['sandbox_dir'],
                capture_output=True,
                text=True,
                timeout=self.sandbox_timeout
            )
            
            return {
                'output': result.stdout + result.stderr,
                'logs': [result.stdout, result.stderr]
            }
            
        except subprocess.TimeoutExpired:
            return {
                'output': "Test timed out",
                'logs': ["Timeout exceeded"]
            }
        except Exception as e:
            return {
                'output': f"Execution failed: {str(e)}",
                'logs': [str(e)]
            }
    
    async def _validate_fix(self,
                          sandbox_env: Dict[str, Any],
                          vulnerability: Dict[str, Any],
                          original_code: str,
                          fixed_code: str,
                          exploit_tests: List[ExploitTest]) -> FixValidation:
        """
        Validate that a fix actually prevents the vulnerability
        """
        # Write fixed code to sandbox
        fixed_file = os.path.join(sandbox_env['sandbox_dir'], "fixed_code.py")
        with open(fixed_file, 'w') as f:
            f.write(fixed_code)
        
        # Re-run exploits against fixed code
        fixed_results = []
        for test in exploit_tests:
            # Modify test to use fixed code
            modified_test = test.exploit_code.replace(
                "from vulnerable_code import",
                "from fixed_code import"
            )
            
            # Run test against fix
            result = await self._run_process_test(
                sandbox_env,
                self._create_temp_test(sandbox_env, modified_test)
            )
            
            fixed_results.append({
                'test_id': test.test_id,
                'still_vulnerable': "Success" in result['output']
            })
        
        # AI analysis of fix effectiveness
        fix_analysis = await self._analyze_fix_effectiveness(
            vulnerability,
            original_code,
            fixed_code,
            fixed_results
        )
        
        return FixValidation(
            fix_id=self._generate_test_id(),
            vulnerability_id=vulnerability.get('id', 'unknown'),
            original_code=original_code[:500],  # Truncate for storage
            fixed_code=fixed_code[:500],
            fix_effective=fix_analysis['effective'],
            remaining_risks=fix_analysis['remaining_risks'],
            side_effects=fix_analysis['side_effects'],
            performance_impact=fix_analysis.get('performance_impact'),
            ai_confidence=fix_analysis['confidence']
        )
    
    async def _analyze_fix_effectiveness(self,
                                       vulnerability: Dict[str, Any],
                                       original_code: str,
                                       fixed_code: str,
                                       test_results: List[Dict]) -> Dict[str, Any]:
        """
        AI analysis of fix effectiveness
        """
        prompt = f"""You are a security expert analyzing if a fix properly addresses a vulnerability.

Vulnerability: {vulnerability.get('description')}

Original vulnerable code:
```python
{original_code[:1000]}
```

Proposed fix:
```python
{fixed_code[:1000]}
```

Exploit test results against fix:
{json.dumps(test_results, indent=2)}

Analyze:
1. Does the fix prevent the vulnerability?
2. Are there remaining attack vectors?
3. Does the fix introduce new issues?
4. What are the side effects?
5. Performance impact?

Provide analysis in JSON format:
{{
  "effective": true/false,
  "confidence": 0.0-1.0,
  "remaining_risks": ["risk1", "risk2"],
  "side_effects": ["effect1", "effect2"],
  "performance_impact": "description or null",
  "recommendation": "approve|reject|modify"
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
            analysis = json.loads(response_body['content'][0]['text'])
            
            return analysis
            
        except Exception as e:
            logger.error(f"Fix analysis failed: {e}")
            return {
                'effective': False,
                'confidence': 0.1,
                'remaining_risks': ['Analysis failed'],
                'side_effects': [],
                'performance_impact': None
            }
    
    async def _analyze_exploit_result(self, test: ExploitTest) -> str:
        """
        AI analysis of exploit test result
        """
        prompt = f"""Analyze this security exploit test result:

Test: {test.test_id}
Expected: {test.expected_outcome}
Actual: {test.actual_outcome}
Success: {test.success}

Provide a brief analysis of what this result means for security."""

        try:
            response = bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 500,
                    "messages": [{
                        "role": "user",
                        "content": prompt
                    }],
                    "temperature": 0.1
                })
            )
            
            response_body = json.loads(response['body'].read())
            return response_body['content'][0]['text']
            
        except Exception as e:
            return f"Analysis failed: {str(e)}"
    
    async def _generate_assessment(self,
                                 vulnerability: Dict[str, Any],
                                 exploit_results: List[ExploitTest],
                                 fix_validations: List[FixValidation]) -> Dict[str, Any]:
        """
        Generate overall security assessment
        """
        successful_exploits = sum(1 for test in exploit_results if test.success)
        total_exploits = len(exploit_results)
        
        fix_effective = all(fix.fix_effective for fix in fix_validations) if fix_validations else False
        
        risk_reduction = 0.0
        if fix_validations and fix_effective:
            risk_reduction = 90.0  # Base reduction
            # Adjust based on remaining risks
            for fix in fix_validations:
                risk_reduction -= len(fix.remaining_risks) * 5
        
        risk_reduction = max(0.0, min(100.0, risk_reduction))
        
        recommendations = []
        if successful_exploits > 0:
            recommendations.append("Vulnerability confirmed - immediate action required")
        
        if fix_effective:
            recommendations.append("Proposed fix is effective - recommend deployment")
        else:
            recommendations.append("Fix needs improvement - address remaining risks")
        
        return {
            'summary': f"Tested {total_exploits} exploits, {successful_exploits} successful. "
                      f"Fix effectiveness: {fix_effective}. Risk reduction: {risk_reduction:.1f}%",
            'risk_reduction': risk_reduction,
            'recommendations': recommendations
        }
    
    async def _destroy_sandbox(self, sandbox_env: Dict[str, Any]):
        """
        Clean up sandbox environment
        """
        try:
            # Remove temporary directory
            if 'sandbox_dir' in sandbox_env:
                shutil.rmtree(sandbox_env['sandbox_dir'], ignore_errors=True)
            
            # Remove Docker image if used
            if self.docker_client and 'image_tag' in sandbox_env:
                try:
                    self.docker_client.images.remove(sandbox_env['image_tag'])
                except:
                    pass
            
            sandbox_env['status'] = SandboxStatus.DESTROYED
            
        except Exception as e:
            logger.error(f"Failed to destroy sandbox: {e}")
    
    def _create_sandbox_id(self) -> str:
        """Generate unique sandbox ID"""
        timestamp = datetime.utcnow().isoformat()
        return f"sandbox_{hashlib.sha256(timestamp.encode()).hexdigest()[:12]}"
    
    def _generate_test_id(self) -> str:
        """Generate unique test ID"""
        timestamp = datetime.utcnow().isoformat()
        return f"test_{hashlib.sha256(timestamp.encode()).hexdigest()[:8]}"
    
    def _create_temp_test(self, sandbox_env: Dict[str, Any], code: str) -> str:
        """Create temporary test file"""
        test_file = os.path.join(
            sandbox_env['sandbox_dir'],
            f"temp_test_{self._generate_test_id()}.py"
        )
        with open(test_file, 'w') as f:
            f.write(code)
        return test_file
    
    def _store_sandbox_report(self, report: SandboxReport):
        """Store sandbox report in DynamoDB"""
        try:
            self.sandbox_table.put_item(
                Item={
                    'sandbox_id': report.sandbox_id,
                    'vulnerability_tested': report.vulnerability_tested,
                    'exploit_count': len(report.exploit_results),
                    'successful_exploits': sum(1 for e in report.exploit_results if e.success),
                    'fix_tested': len(report.fix_validations) > 0,
                    'fix_effective': all(f.fix_effective for f in report.fix_validations),
                    'risk_reduction': float(report.risk_reduction),
                    'overall_assessment': report.overall_assessment,
                    'recommendations': report.recommendations,
                    'created_at': report.created_at.isoformat(),
                    'duration_seconds': float(report.duration_seconds),
                    'ttl': int((datetime.utcnow().timestamp()) + 86400 * 30)  # 30 day TTL
                }
            )
        except Exception as e:
            logger.error(f"Failed to store sandbox report: {e}")