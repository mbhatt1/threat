"""
AI Security Test Generator
Generates security test cases and penetration testing scenarios using AWS Bedrock
"""
import json
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging
import hashlib
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass
class SecurityTestCase:
    """Represents a generated security test case"""
    test_id: str
    test_name: str
    test_type: str  # unit, integration, penetration, fuzzing
    vulnerability_type: str
    test_description: str
    test_code: str
    expected_result: str
    severity: str
    confidence: float
    prerequisites: List[str] = field(default_factory=list)
    cleanup_steps: List[str] = field(default_factory=list)
    
    
@dataclass
class PenetrationScenario:
    """Represents a penetration testing scenario"""
    scenario_id: str
    scenario_name: str
    attack_vector: str
    target_vulnerability: str
    attack_steps: List[Dict[str, Any]]
    success_indicators: List[str]
    detection_evasion: List[str]
    impact_assessment: Dict[str, Any]
    mitigation_validation: Dict[str, Any]
    risk_score: float


@dataclass
class TestGenerationResult:
    """Complete test generation result"""
    test_cases: List[SecurityTestCase]
    penetration_scenarios: List[PenetrationScenario]
    test_suite_metadata: Dict[str, Any]
    coverage_analysis: Dict[str, Any]
    generation_timestamp: str
    ai_confidence: float


class AISecurityTestGenerator:
    """
    AI-powered security test generator using AWS Bedrock
    """
    
    def __init__(self, bedrock_client=None):
        self.bedrock = bedrock_client or boto3.client('bedrock-runtime')
        self.model_id = 'anthropic.claude-3-sonnet-20240229-v1:0'
        
    async def generate_tests(self,
                           vulnerabilities: List[Dict[str, Any]],
                           code_context: Dict[str, Any],
                           test_types: List[str] = None) -> TestGenerationResult:
        """
        Generate comprehensive security tests for identified vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability findings
            code_context: Context about the codebase
            test_types: Types of tests to generate (unit, integration, penetration, fuzzing)
            
        Returns:
            TestGenerationResult with all generated tests
        """
        if not test_types:
            test_types = ['unit', 'integration', 'penetration', 'fuzzing']
            
        # Generate different types of tests in parallel
        tasks = []
        
        if 'unit' in test_types or 'integration' in test_types:
            tasks.append(self._generate_test_cases(vulnerabilities, code_context))
            
        if 'penetration' in test_types:
            tasks.append(self._generate_penetration_scenarios(vulnerabilities, code_context))
            
        if 'fuzzing' in test_types:
            tasks.append(self._generate_fuzzing_tests(vulnerabilities, code_context))
            
        results = await asyncio.gather(*tasks)
        
        # Combine results
        test_cases = []
        penetration_scenarios = []
        
        for result in results:
            if isinstance(result, list) and result and isinstance(result[0], SecurityTestCase):
                test_cases.extend(result)
            elif isinstance(result, list) and result and isinstance(result[0], PenetrationScenario):
                penetration_scenarios.extend(result)
            elif isinstance(result, dict) and 'fuzzing_tests' in result:
                # Convert fuzzing tests to SecurityTestCase format
                test_cases.extend(result['fuzzing_tests'])
                
        # Generate test suite metadata
        test_suite_metadata = self._generate_suite_metadata(
            test_cases, penetration_scenarios, code_context
        )
        
        # Analyze test coverage
        coverage_analysis = await self._analyze_test_coverage(
            vulnerabilities, test_cases, penetration_scenarios
        )
        
        return TestGenerationResult(
            test_cases=test_cases,
            penetration_scenarios=penetration_scenarios,
            test_suite_metadata=test_suite_metadata,
            coverage_analysis=coverage_analysis,
            generation_timestamp=datetime.utcnow().isoformat(),
            ai_confidence=self._calculate_confidence(test_cases, penetration_scenarios)
        )
        
    async def _generate_test_cases(self,
                                 vulnerabilities: List[Dict[str, Any]],
                                 code_context: Dict[str, Any]) -> List[SecurityTestCase]:
        """Generate unit and integration test cases"""
        
        prompt = f"""You are an expert security test engineer. Generate comprehensive security test cases for the following vulnerabilities.

Code Context:
- Language: {code_context.get('language', 'unknown')}
- Framework: {code_context.get('framework', 'unknown')}
- File: {code_context.get('file_path', 'unknown')}

Vulnerabilities to test:
{json.dumps(vulnerabilities, indent=2)}

For each vulnerability, generate detailed test cases that:
1. Verify the vulnerability exists (negative test)
2. Verify the fix works (positive test)
3. Test edge cases and boundary conditions
4. Include regression tests

Return a JSON array with this structure:
[
  {{
    "test_name": "descriptive test name",
    "test_type": "unit|integration",
    "vulnerability_type": "type of vulnerability",
    "test_description": "what the test validates",
    "test_code": "actual test code in the target language",
    "expected_result": "what should happen",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": 0.0-1.0,
    "prerequisites": ["setup steps"],
    "cleanup_steps": ["teardown steps"]
  }}
]
"""

        try:
            response = self.bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4000,
                    "messages": [{
                        "role": "user",
                        "content": prompt
                    }]
                })
            )
            
            result = json.loads(response['body'].read())
            ai_tests = json.loads(result['content'][0]['text'])
            
            # Convert to SecurityTestCase objects
            test_cases = []
            for test in ai_tests:
                test_cases.append(SecurityTestCase(
                    test_id=self._generate_test_id(test['test_name']),
                    test_name=test['test_name'],
                    test_type=test['test_type'],
                    vulnerability_type=test['vulnerability_type'],
                    test_description=test['test_description'],
                    test_code=test['test_code'],
                    expected_result=test['expected_result'],
                    severity=test['severity'],
                    confidence=test['confidence'],
                    prerequisites=test.get('prerequisites', []),
                    cleanup_steps=test.get('cleanup_steps', [])
                ))
                
            return test_cases
            
        except Exception as e:
            logger.error(f"Failed to generate test cases: {e}")
            return []
            
    async def _generate_penetration_scenarios(self,
                                            vulnerabilities: List[Dict[str, Any]],
                                            code_context: Dict[str, Any]) -> List[PenetrationScenario]:
        """Generate penetration testing scenarios"""
        
        prompt = f"""You are an expert penetration tester. Create realistic penetration testing scenarios for the following vulnerabilities.

Target Context:
- Application Type: {code_context.get('app_type', 'web application')}
- Technology Stack: {code_context.get('tech_stack', [])}
- Deployment: {code_context.get('deployment', 'cloud')}

Vulnerabilities:
{json.dumps(vulnerabilities, indent=2)}

For each major vulnerability, create a penetration testing scenario that includes:
1. Attack vector and entry points
2. Step-by-step exploitation process
3. Techniques to evade detection
4. Success indicators
5. Impact if successful
6. How to validate mitigation

Return a JSON array with this structure:
[
  {{
    "scenario_name": "descriptive scenario name",
    "attack_vector": "how the attack is delivered",
    "target_vulnerability": "which vulnerability is exploited",
    "attack_steps": [
      {{
        "step": 1,
        "action": "what to do",
        "tool": "tool or technique",
        "expected_response": "what should happen",
        "detection_risk": "low|medium|high"
      }}
    ],
    "success_indicators": ["signs of successful exploitation"],
    "detection_evasion": ["techniques to avoid detection"],
    "impact_assessment": {{
      "confidentiality": "impact description",
      "integrity": "impact description",
      "availability": "impact description",
      "business_impact": "potential business consequences"
    }},
    "mitigation_validation": {{
      "test_after_fix": "how to verify the fix",
      "expected_result": "what should happen after mitigation"
    }},
    "risk_score": 0.0-10.0
  }}
]
"""

        try:
            response = self.bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4000,
                    "messages": [{
                        "role": "user",
                        "content": prompt
                    }]
                })
            )
            
            result = json.loads(response['body'].read())
            ai_scenarios = json.loads(result['content'][0]['text'])
            
            # Convert to PenetrationScenario objects
            scenarios = []
            for scenario in ai_scenarios:
                scenarios.append(PenetrationScenario(
                    scenario_id=self._generate_test_id(scenario['scenario_name']),
                    scenario_name=scenario['scenario_name'],
                    attack_vector=scenario['attack_vector'],
                    target_vulnerability=scenario['target_vulnerability'],
                    attack_steps=scenario['attack_steps'],
                    success_indicators=scenario['success_indicators'],
                    detection_evasion=scenario['detection_evasion'],
                    impact_assessment=scenario['impact_assessment'],
                    mitigation_validation=scenario['mitigation_validation'],
                    risk_score=scenario['risk_score']
                ))
                
            return scenarios
            
        except Exception as e:
            logger.error(f"Failed to generate penetration scenarios: {e}")
            return []
            
    async def _generate_fuzzing_tests(self,
                                    vulnerabilities: List[Dict[str, Any]],
                                    code_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fuzzing test cases"""
        
        prompt = f"""You are a security fuzzing expert. Generate fuzzing test cases for input validation vulnerabilities.

Code Context:
{json.dumps(code_context, indent=2)}

Focus on these vulnerability types:
{json.dumps([v.get('type', '') for v in vulnerabilities], indent=2)}

Generate fuzzing test cases that include:
1. Malformed input patterns
2. Boundary value tests
3. Format string attacks
4. Injection payloads
5. Buffer overflow attempts

Return a JSON object with fuzzing test cases:
{{
  "fuzzing_tests": [
    {{
      "test_name": "descriptive name",
      "target_input": "which input field/parameter",
      "fuzzing_patterns": ["pattern1", "pattern2", ...],
      "expected_behavior": "how the app should handle it",
      "vulnerability_indicator": "what indicates a vulnerability"
    }}
  ]
}}
"""

        try:
            response = self.bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 3000,
                    "messages": [{
                        "role": "user",
                        "content": prompt
                    }]
                })
            )
            
            result = json.loads(response['body'].read())
            fuzzing_data = json.loads(result['content'][0]['text'])
            
            # Convert fuzzing tests to SecurityTestCase format
            test_cases = []
            for fuzz_test in fuzzing_data.get('fuzzing_tests', []):
                for i, pattern in enumerate(fuzz_test['fuzzing_patterns'][:5]):  # Limit patterns
                    test_cases.append(SecurityTestCase(
                        test_id=self._generate_test_id(f"{fuzz_test['test_name']}_{i}"),
                        test_name=f"{fuzz_test['test_name']} - Pattern {i+1}",
                        test_type='fuzzing',
                        vulnerability_type='input_validation',
                        test_description=f"Fuzzing {fuzz_test['target_input']} with: {pattern}",
                        test_code=self._generate_fuzzing_code(
                            fuzz_test['target_input'], pattern, code_context
                        ),
                        expected_result=fuzz_test['expected_behavior'],
                        severity='MEDIUM',
                        confidence=0.8,
                        prerequisites=[],
                        cleanup_steps=[]
                    ))
                    
            return {'fuzzing_tests': test_cases}
            
        except Exception as e:
            logger.error(f"Failed to generate fuzzing tests: {e}")
            return {'fuzzing_tests': []}
            
    async def _analyze_test_coverage(self,
                                   vulnerabilities: List[Dict[str, Any]],
                                   test_cases: List[SecurityTestCase],
                                   penetration_scenarios: List[PenetrationScenario]) -> Dict[str, Any]:
        """Analyze test coverage for vulnerabilities"""
        
        # Count coverage by vulnerability type
        vuln_types = set(v.get('type', 'unknown') for v in vulnerabilities)
        tested_types = set(t.vulnerability_type for t in test_cases)
        pen_tested_types = set(s.target_vulnerability for s in penetration_scenarios)
        
        all_tested = tested_types.union(pen_tested_types)
        
        coverage = {
            'total_vulnerabilities': len(vulnerabilities),
            'total_test_cases': len(test_cases),
            'total_penetration_scenarios': len(penetration_scenarios),
            'vulnerability_coverage': {
                'covered': list(all_tested),
                'uncovered': list(vuln_types - all_tested),
                'coverage_percentage': (len(all_tested) / len(vuln_types) * 100) if vuln_types else 0
            },
            'test_distribution': {
                'unit_tests': len([t for t in test_cases if t.test_type == 'unit']),
                'integration_tests': len([t for t in test_cases if t.test_type == 'integration']),
                'fuzzing_tests': len([t for t in test_cases if t.test_type == 'fuzzing']),
                'penetration_tests': len(penetration_scenarios)
            },
            'severity_coverage': self._analyze_severity_coverage(vulnerabilities, test_cases),
            'recommendations': self._generate_coverage_recommendations(vuln_types - all_tested)
        }
        
        return coverage
        
    def _analyze_severity_coverage(self,
                                 vulnerabilities: List[Dict[str, Any]],
                                 test_cases: List[SecurityTestCase]) -> Dict[str, Any]:
        """Analyze test coverage by severity"""
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        tested_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'MEDIUM')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
        for test in test_cases:
            tested_severity[test.severity] = tested_severity.get(test.severity, 0) + 1
            
        return {
            'vulnerability_severity': severity_counts,
            'test_severity': tested_severity,
            'critical_coverage': (tested_severity['CRITICAL'] >= severity_counts['CRITICAL'])
        }
        
    def _generate_coverage_recommendations(self, uncovered_types: set) -> List[str]:
        """Generate recommendations for improving test coverage"""
        
        recommendations = []
        
        if uncovered_types:
            recommendations.append(
                f"Add tests for uncovered vulnerability types: {', '.join(uncovered_types)}"
            )
            
        recommendations.extend([
            "Consider adding performance security tests",
            "Include authentication and authorization test scenarios",
            "Add tests for security misconfigurations",
            "Create tests for business logic vulnerabilities"
        ])
        
        return recommendations
        
    def _generate_suite_metadata(self,
                               test_cases: List[SecurityTestCase],
                               penetration_scenarios: List[PenetrationScenario],
                               code_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate metadata for the test suite"""
        
        return {
            'suite_id': self._generate_test_id('test_suite'),
            'generation_date': datetime.utcnow().isoformat(),
            'target_application': code_context.get('repository', 'unknown'),
            'programming_language': code_context.get('language', 'unknown'),
            'framework': code_context.get('framework', 'unknown'),
            'total_tests': len(test_cases) + len(penetration_scenarios),
            'estimated_execution_time': self._estimate_execution_time(test_cases, penetration_scenarios),
            'required_tools': self._identify_required_tools(test_cases, penetration_scenarios),
            'test_categories': {
                'security_tests': len(test_cases),
                'penetration_tests': len(penetration_scenarios)
            }
        }
        
    def _generate_fuzzing_code(self, target: str, pattern: str, context: Dict[str, Any]) -> str:
        """Generate language-specific fuzzing test code"""
        
        language = context.get('language', 'python').lower()
        
        if language == 'python':
            return f"""
def test_fuzzing_{target.replace('.', '_')}():
    payload = "{pattern}"
    response = make_request(target_input='{target}', value=payload)
    
    # Verify proper input validation
    assert response.status_code != 500, "Server error indicates poor input handling"
    assert 'error' not in response.text.lower(), "Unexpected error in response"
    assert len(response.text) < 10000, "Possible information disclosure"
"""
        elif language == 'javascript':
            return f"""
test('Fuzzing {target}', async () => {{
    const payload = "{pattern}";
    const response = await makeRequest('{target}', payload);
    
    expect(response.status).not.toBe(500);
    expect(response.data).not.toMatch(/error/i);
    expect(response.data.length).toBeLessThan(10000);
}});
"""
        else:
            return f"// Fuzzing test for {target} with payload: {pattern}"
            
    def _generate_test_id(self, name: str) -> str:
        """Generate unique test ID"""
        return hashlib.sha256(f"{name}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12]
        
    def _calculate_confidence(self,
                            test_cases: List[SecurityTestCase],
                            scenarios: List[PenetrationScenario]) -> float:
        """Calculate overall confidence in generated tests"""
        
        if not test_cases and not scenarios:
            return 0.0
            
        # Average confidence from test cases
        test_confidence = sum(t.confidence for t in test_cases) / len(test_cases) if test_cases else 0
        
        # Scenario confidence based on risk scores
        scenario_confidence = sum(1.0 if s.risk_score > 5 else 0.8 for s in scenarios) / len(scenarios) if scenarios else 0
        
        # Weight test cases and scenarios equally
        return (test_confidence + scenario_confidence) / 2 if test_cases or scenarios else 0.0
        
    def _estimate_execution_time(self,
                               test_cases: List[SecurityTestCase],
                               scenarios: List[PenetrationScenario]) -> str:
        """Estimate total execution time for all tests"""
        
        # Rough estimates
        unit_time = 0.5  # minutes per unit test
        integration_time = 2  # minutes per integration test
        fuzzing_time = 1  # minutes per fuzzing test
        penetration_time = 30  # minutes per penetration scenario
        
        total_minutes = 0
        
        for test in test_cases:
            if test.test_type == 'unit':
                total_minutes += unit_time
            elif test.test_type == 'integration':
                total_minutes += integration_time
            elif test.test_type == 'fuzzing':
                total_minutes += fuzzing_time
                
        total_minutes += len(scenarios) * penetration_time
        
        if total_minutes < 60:
            return f"{int(total_minutes)} minutes"
        else:
            hours = total_minutes / 60
            return f"{hours:.1f} hours"
            
    def _identify_required_tools(self,
                               test_cases: List[SecurityTestCase],
                               scenarios: List[PenetrationScenario]) -> List[str]:
        """Identify tools required for test execution"""
        
        tools = set(['pytest', 'unittest'])  # Basic testing frameworks
        
        # Check penetration scenarios for specific tools
        for scenario in scenarios:
            for step in scenario.attack_steps:
                tool = step.get('tool', '').lower()
                if tool and tool not in ['manual', 'custom']:
                    tools.add(tool)
                    
        # Add common security testing tools
        if any(t.test_type == 'fuzzing' for t in test_cases):
            tools.add('AFL++')
            tools.add('libFuzzer')
            
        if scenarios:
            tools.add('Burp Suite')
            tools.add('OWASP ZAP')
            
        return sorted(list(tools))