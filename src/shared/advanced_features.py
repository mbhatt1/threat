"""
AI-Powered Advanced Security Features
Supply chain intelligence, custom policies, and code flow analysis using Claude
"""
import json
import re
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import boto3
from pathlib import Path
import logging
from decimal import Decimal
import os
import yaml
import base64

logger = logging.getLogger(__name__)

# AWS clients
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')
bedrock = boto3.client('bedrock-runtime')

@dataclass
class AIVulnerabilityIntel:
    """AI-discovered supply chain vulnerability"""
    package_name: str
    current_version: str
    vulnerability_description: str
    ai_confidence: float
    severity: str
    risk_analysis: str
    remediation_advice: str
    ai_reasoning: List[str]
    similar_vulnerabilities: List[str] = field(default_factory=list)
    
@dataclass
class AIPolicyViolation:
    """AI-detected policy violation"""
    violation_id: str
    policy_description: str
    violation_details: str
    severity: str
    ai_confidence: float
    suggested_fix: str
    code_context: str
    business_impact: str

class AISupplyChainIntelligence:
    """
    AI-powered supply chain vulnerability intelligence using Claude
    """
    
    def __init__(self):
        # DynamoDB tables
        self.ai_vuln_analysis_table = dynamodb.Table(
            os.environ.get('AI_VULN_ANALYSIS_TABLE', 'SecurityAuditAIVulnAnalysis')
        )
        self.package_risk_table = dynamodb.Table(
            os.environ.get('PACKAGE_RISK_TABLE', 'SecurityAuditPackageRisk')
        )
        
        # Claude model configuration
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
    
    def analyze_dependencies_with_ai(self, 
                                   dependencies: Dict[str, str],
                                   language: str,
                                   project_context: str = "") -> Dict[str, List[AIVulnerabilityIntel]]:
        """
        Use AI to analyze dependencies for potential vulnerabilities
        """
        vulnerabilities = {}
        
        # Batch analyze dependencies for efficiency
        dep_batch = []
        for package, version in dependencies.items():
            dep_batch.append(f"{package}@{version}")
            
            # Process in batches of 10
            if len(dep_batch) >= 10:
                batch_vulns = self._analyze_dependency_batch(dep_batch, language, project_context)
                vulnerabilities.update(batch_vulns)
                dep_batch = []
        
        # Process remaining
        if dep_batch:
            batch_vulns = self._analyze_dependency_batch(dep_batch, language, project_context)
            vulnerabilities.update(batch_vulns)
        
        return vulnerabilities
    
    def _analyze_dependency_batch(self, 
                                dependencies: List[str],
                                language: str,
                                project_context: str) -> Dict[str, List[AIVulnerabilityIntel]]:
        """Analyze a batch of dependencies with AI"""
        
        prompt = f"""You are an expert security researcher analyzing {language} dependencies for vulnerabilities.

Analyze these dependencies for security risks:
{json.dumps(dependencies, indent=2)}

Project context: {project_context or 'General application'}

For each dependency, identify:
1. Known vulnerabilities (even if not in CVE databases)
2. Supply chain risks (maintenance, typosquatting, etc.)
3. Security anti-patterns in the package
4. Potential attack vectors
5. Version-specific issues

Consider:
- Recent security incidents
- Package maintenance status
- Dependency confusion attacks
- Prototype pollution (JavaScript)
- Deserialization issues (Python/Java)
- Memory safety (C/C++ dependencies)
- Transitive dependency risks

Provide analysis in this exact JSON format:
{{
  "package_name@version": {{
    "vulnerabilities": [
      {{
        "description": "detailed vulnerability description",
        "severity": "CRITICAL|HIGH|MEDIUM|LOW",
        "confidence": 0.0-1.0,
        "risk_analysis": "detailed risk explanation",
        "remediation": "specific fix advice",
        "reasoning": ["step1", "step2", "..."]
      }}
    ],
    "supply_chain_risks": {{
      "maintenance_score": 0-100,
      "typosquatting_risk": true/false,
      "suspicious_patterns": ["pattern1", "..."]
    }}
  }}
}}"""

        try:
            response = bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4000,
                    "messages": [{
                        "role": "user",
                        "content": prompt
                    }],
                    "temperature": 0.1
                })
            )
            
            response_body = json.loads(response['body'].read())
            ai_analysis = json.loads(response_body['content'][0]['text'])
            
            # Convert AI response to vulnerability objects
            vulnerabilities = {}
            for dep_key, dep_analysis in ai_analysis.items():
                package_name, version = dep_key.split('@', 1)
                vulns = []
                
                for vuln in dep_analysis.get('vulnerabilities', []):
                    vulns.append(AIVulnerabilityIntel(
                        package_name=package_name,
                        current_version=version,
                        vulnerability_description=vuln['description'],
                        ai_confidence=vuln['confidence'],
                        severity=vuln['severity'],
                        risk_analysis=vuln['risk_analysis'],
                        remediation_advice=vuln['remediation'],
                        ai_reasoning=vuln['reasoning']
                    ))
                
                if vulns:
                    vulnerabilities[package_name] = vulns
            
            # Store AI analysis
            self._store_ai_analysis(vulnerabilities)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"AI dependency analysis failed: {e}")
            return {}
    
    def analyze_package_behavior_with_ai(self, 
                                       package_name: str,
                                       package_code: Optional[str] = None) -> Dict[str, Any]:
        """
        Use AI to analyze package behavior for malicious patterns
        """
        prompt = f"""You are a security expert analyzing the {package_name} package for malicious behavior.

{f"Package code snippet: {package_code[:5000]}" if package_code else "Analyze based on package name and common patterns."}

Analyze for:
1. Data exfiltration attempts
2. Backdoor functionality
3. Cryptocurrency mining
4. Environment variable theft
4. Suspicious network connections
5. File system tampering
6. Process manipulation
7. Obfuscation techniques

Provide detailed analysis including:
- Confidence level (0-1)
- Specific code patterns found
- Potential impact
- Indicators of compromise

Format as JSON with structure:
{{
  "malicious_probability": 0.0-1.0,
  "suspicious_behaviors": [
    {{
      "behavior": "description",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "evidence": "specific code or pattern",
      "ioc": ["indicator1", "..."]
    }}
  ],
  "obfuscation_detected": true/false,
  "recommendation": "block|warn|allow"
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
            
            # Store analysis
            self._store_package_behavior_analysis(package_name, analysis)
            
            return analysis
            
        except Exception as e:
            logger.error(f"AI behavior analysis failed: {e}")
            return {"error": str(e)}
    
    def predict_zero_day_vulnerabilities(self, 
                                       code_context: str,
                                       technology_stack: List[str]) -> List[Dict[str, Any]]:
        """
        Use AI to predict potential zero-day vulnerabilities
        """
        prompt = f"""You are an elite security researcher predicting zero-day vulnerabilities.

Technology stack: {', '.join(technology_stack)}
Code context:
{code_context[:3000]}

Based on:
1. Common vulnerability patterns
2. Recent attack trends
3. Technology-specific weaknesses
4. Emerging threat patterns
5. Supply chain attack vectors

Predict potential zero-day vulnerabilities that could affect this codebase.

Provide predictions in JSON format:
{{
  "predictions": [
    {{
      "vulnerability_type": "specific vulnerability class",
      "description": "detailed description",
      "attack_vector": "how it could be exploited",
      "likelihood": 0.0-1.0,
      "impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "mitigation": "preventive measures",
      "reasoning": ["why this is likely", "..."]
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
                    "temperature": 0.3  # Slightly higher for creative prediction
                })
            )
            
            response_body = json.loads(response['body'].read())
            predictions = json.loads(response_body['content'][0]['text'])
            
            return predictions.get('predictions', [])
            
        except Exception as e:
            logger.error(f"Zero-day prediction failed: {e}")
            return []
    
    def _store_ai_analysis(self, vulnerabilities: Dict[str, List[AIVulnerabilityIntel]]):
        """Store AI vulnerability analysis in DynamoDB"""
        for package, vulns in vulnerabilities.items():
            for vuln in vulns:
                try:
                    self.ai_vuln_analysis_table.put_item(
                        Item={
                            'package_version': f"{vuln.package_name}@{vuln.current_version}",
                            'analysis_timestamp': datetime.utcnow().isoformat(),
                            'vulnerability_description': vuln.vulnerability_description,
                            'ai_confidence': Decimal(str(vuln.ai_confidence)),
                            'severity': vuln.severity,
                            'risk_analysis': vuln.risk_analysis,
                            'remediation_advice': vuln.remediation_advice,
                            'ai_reasoning': vuln.ai_reasoning,
                            'ttl': int((datetime.utcnow() + timedelta(days=30)).timestamp())
                        }
                    )
                except Exception as e:
                    logger.error(f"Failed to store AI analysis: {e}")
    
    def _store_package_behavior_analysis(self, package_name: str, analysis: Dict[str, Any]):
        """Store package behavior analysis"""
        try:
            self.package_risk_table.put_item(
                Item={
                    'package_name': package_name,
                    'analysis_timestamp': datetime.utcnow().isoformat(),
                    'malicious_probability': Decimal(str(analysis.get('malicious_probability', 0))),
                    'suspicious_behaviors': json.dumps(analysis.get('suspicious_behaviors', [])),
                    'recommendation': analysis.get('recommendation', 'review'),
                    'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())
                }
            )
        except Exception as e:
            logger.error(f"Failed to store behavior analysis: {e}")


class AICustomPolicyEngine:
    """
    AI-powered custom security policy engine
    """
    
    def __init__(self):
        # DynamoDB tables
        self.ai_policies_table = dynamodb.Table(
            os.environ.get('AI_POLICIES_TABLE', 'SecurityAuditAIPolicies')
        )
        self.policy_violations_table = dynamodb.Table(
            os.environ.get('POLICY_VIOLATIONS_TABLE', 'SecurityAuditPolicyViolations')
        )
        
        # S3 for policy definitions
        self.policy_bucket = os.environ.get('POLICY_BUCKET', 'security-audit-policies')
        
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
    
    def create_policy_from_natural_language(self, 
                                          policy_description: str,
                                          examples: List[str] = None) -> Dict[str, Any]:
        """
        Create security policy from natural language description
        """
        prompt = f"""You are a security policy expert. Create a detailed security policy from this description:

Policy Description: {policy_description}

{f"Examples of violations: {examples}" if examples else ""}

Create a comprehensive policy that includes:
1. Clear violation criteria
2. Severity classification rules
3. Exception patterns
4. Detection logic
5. Remediation guidance

Format as JSON:
{{
  "policy_name": "descriptive name",
  "policy_id": "unique-id",
  "description": "detailed description",
  "violation_patterns": [
    {{
      "pattern": "what to look for",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "detection_logic": "how to detect"
    }}
  ],
  "exceptions": ["exception patterns"],
  "remediation_template": "how to fix violations",
  "business_justification": "why this matters"
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
            policy = json.loads(response_body['content'][0]['text'])
            
            # Store policy
            self._store_ai_policy(policy)
            
            return policy
            
        except Exception as e:
            logger.error(f"Policy creation failed: {e}")
            return {"error": str(e)}
    
    def evaluate_code_against_policies(self, 
                                     code: str,
                                     file_path: str,
                                     policies: List[str] = None) -> List[AIPolicyViolation]:
        """
        Use AI to evaluate code against security policies
        """
        # Get active policies
        active_policies = policies or self._get_active_policies()
        
        prompt = f"""You are a security auditor evaluating code against security policies.

File: {file_path}
Code to evaluate:
```
{code[:5000]}
```

Security Policies to check:
{json.dumps(active_policies, indent=2)}

For each policy:
1. Check if the code violates the policy
2. Identify specific violations with line numbers
3. Assess severity based on context
4. Suggest specific fixes
5. Evaluate business impact

Provide violations in JSON format:
{{
  "violations": [
    {{
      "policy_id": "policy identifier",
      "violation_description": "what was violated and how",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0.0-1.0,
      "line_numbers": [1, 2, ...],
      "code_snippet": "violating code",
      "suggested_fix": "specific fix code",
      "business_impact": "potential impact description"
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
                    "temperature": 0.1
                })
            )
            
            response_body = json.loads(response['body'].read())
            violations_data = json.loads(response_body['content'][0]['text'])
            
            # Convert to violation objects
            violations = []
            for v in violations_data.get('violations', []):
                violation = AIPolicyViolation(
                    violation_id=hashlib.sha256(
                        f"{file_path}:{v['policy_id']}:{v['line_numbers']}".encode()
                    ).hexdigest()[:16],
                    policy_description=v['policy_id'],
                    violation_details=v['violation_description'],
                    severity=v['severity'],
                    ai_confidence=v['confidence'],
                    suggested_fix=v['suggested_fix'],
                    code_context=v['code_snippet'],
                    business_impact=v['business_impact']
                )
                violations.append(violation)
            
            # Store violations
            self._store_violations(file_path, violations)
            
            return violations
            
        except Exception as e:
            logger.error(f"Policy evaluation failed: {e}")
            return []
    
    def learn_policies_from_codebase(self, 
                                    secure_code_examples: List[str],
                                    vulnerable_code_examples: List[str]) -> List[Dict[str, Any]]:
        """
        Use AI to learn security policies from code examples
        """
        prompt = f"""You are a security expert learning patterns from code examples.

Secure code examples:
{chr(10).join(f"Example {i+1}:{chr(10)}{code[:1000]}" for i, code in enumerate(secure_code_examples[:3]))}

Vulnerable code examples:
{chr(10).join(f"Example {i+1}:{chr(10)}{code[:1000]}" for i, code in enumerate(vulnerable_code_examples[:3]))}

Based on these examples:
1. Identify security patterns that distinguish secure from vulnerable code
2. Extract security policies that could prevent the vulnerabilities
3. Create detection rules for each pattern
4. Prioritize by impact

Generate policies in JSON format:
{{
  "learned_policies": [
    {{
      "pattern_name": "descriptive name",
      "security_principle": "what principle is violated",
      "detection_rule": "how to detect violations",
      "secure_pattern": "what secure code looks like",
      "vulnerable_pattern": "what vulnerable code looks like",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "auto_fix_possible": true/false
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
                    "temperature": 0.2
                })
            )
            
            response_body = json.loads(response['body'].read())
            learned = json.loads(response_body['content'][0]['text'])
            
            return learned.get('learned_policies', [])
            
        except Exception as e:
            logger.error(f"Policy learning failed: {e}")
            return []
    
    def _get_active_policies(self) -> List[str]:
        """Get active security policies"""
        # This would fetch from DynamoDB/S3
        return [
            "No hardcoded secrets or credentials",
            "No SQL injection vulnerabilities",
            "Proper input validation on all user inputs",
            "No use of dangerous functions (eval, exec, etc.)",
            "Secure cryptographic practices",
            "No path traversal vulnerabilities",
            "Proper authentication and authorization",
            "Secure session management",
            "No sensitive data in logs",
            "HTTPS/TLS for all communications"
        ]
    
    def _store_ai_policy(self, policy: Dict[str, Any]):
        """Store AI-generated policy"""
        try:
            self.ai_policies_table.put_item(
                Item={
                    'policy_id': policy['policy_id'],
                    'policy_name': policy['policy_name'],
                    'description': policy['description'],
                    'policy_json': json.dumps(policy),
                    'created_at': datetime.utcnow().isoformat(),
                    'active': True
                }
            )
        except Exception as e:
            logger.error(f"Failed to store policy: {e}")
    
    def _store_violations(self, file_path: str, violations: List[AIPolicyViolation]):
        """Store policy violations"""
        for violation in violations:
            try:
                self.policy_violations_table.put_item(
                    Item={
                        'violation_id': violation.violation_id,
                        'file_path': file_path,
                        'policy_description': violation.policy_description,
                        'violation_details': violation.violation_details,
                        'severity': violation.severity,
                        'ai_confidence': Decimal(str(violation.ai_confidence)),
                        'suggested_fix': violation.suggested_fix,
                        'business_impact': violation.business_impact,
                        'detected_at': datetime.utcnow().isoformat(),
                        'resolved': False,
                        'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())
                    }
                )
            except Exception as e:
                logger.error(f"Failed to store violation: {e}")


class AICodeFlowAnalyzer:
    """
    AI-powered code flow and data flow analysis
    """
    
    def __init__(self):
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
        
        # DynamoDB for storing analysis results
        self.flow_analysis_table = dynamodb.Table(
            os.environ.get('FLOW_ANALYSIS_TABLE', 'SecurityAuditFlowAnalysis')
        )
    
    def analyze_data_flow(self, 
                         code: str,
                         entry_points: List[str],
                         sensitive_sinks: List[str]) -> Dict[str, Any]:
        """
        Use AI to trace data flow from sources to sinks
        """
        prompt = f"""You are a security expert analyzing data flow for security vulnerabilities.

Code to analyze:
```
{code[:8000]}
```

Entry points (sources): {entry_points}
Sensitive sinks: {sensitive_sinks}

Trace data flow from each entry point to sensitive sinks and identify:
1. Taint propagation paths
2. Missing sanitization
3. Injection vulnerabilities
4. Data leakage risks
5. Unsafe transformations

Provide analysis in JSON format:
{{
  "data_flows": [
    {{
      "source": "entry point",
      "sink": "sensitive operation",
      "path": ["function1", "variable1", "function2", "..."],
      "tainted": true/false,
      "sanitization_present": true/false,
      "vulnerability_type": "injection type or none",
      "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
      "proof_of_concept": "example exploit if vulnerable"
    }}
  ],
  "summary": {{
    "total_flows": N,
    "vulnerable_flows": N,
    "critical_findings": ["finding1", "..."]
  }}
}}"""

        try:
            response = bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4000,
                    "messages": [{
                        "role": "user",
                        "content": prompt
                    }],
                    "temperature": 0.1
                })
            )
            
            response_body = json.loads(response['body'].read())
            analysis = json.loads(response_body['content'][0]['text'])
            
            # Store analysis
            self._store_flow_analysis('data_flow', analysis)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Data flow analysis failed: {e}")
            return {"error": str(e)}
    
    def analyze_control_flow_security(self, code: str) -> Dict[str, Any]:
        """
        Analyze control flow for security issues
        """
        prompt = f"""You are a security expert analyzing control flow for vulnerabilities.

Code to analyze:
```
{code[:8000]}
```

Identify control flow security issues:
1. Race conditions
2. Time-of-check-time-of-use (TOCTOU)
3. Improper error handling
4. Authentication/authorization bypasses
5. Infinite loops or DoS conditions
6. Unsafe state transitions

Provide analysis in JSON format:
{{
  "control_flow_issues": [
    {{
      "issue_type": "specific vulnerability type",
      "description": "detailed description",
      "location": "function/line reference",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "exploitation_scenario": "how it could be exploited",
      "fix_recommendation": "specific fix"
    }}
  ],
  "security_gates": [
    {{
      "gate_type": "authentication|authorization|validation",
      "location": "where the check occurs",
      "effectiveness": "strong|moderate|weak",
      "bypass_possible": true/false
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
                    "temperature": 0.1
                })
            )
            
            response_body = json.loads(response['body'].read())
            analysis = json.loads(response_body['content'][0]['text'])
            
            # Store analysis
            self._store_flow_analysis('control_flow', analysis)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Control flow analysis failed: {e}")
            return {"error": str(e)}
    
    def predict_attack_paths(self, 
                           application_context: str,
                           code_snippets: List[str]) -> List[Dict[str, Any]]:
        """
        Use AI to predict potential attack paths
        """
        prompt = f"""You are an elite security researcher predicting attack paths.

Application context: {application_context}

Code snippets from the application:
{chr(10).join(f"Snippet {i+1}:{chr(10)}{code[:500]}" for i, code in enumerate(code_snippets[:5]))}

Based on the code patterns and context, predict:
1. Most likely attack vectors
2. Attack chains (multi-step attacks)
3. Privilege escalation paths
4. Data exfiltration routes
5. Service disruption methods

For each attack path provide:
- Step-by-step exploitation
- Required preconditions
- Likelihood of success
- Potential impact
- Detection difficulty

Format as JSON:
{{
  "attack_paths": [
    {{
      "attack_name": "descriptive name",
      "attack_type": "category",
      "steps": [
        {{
          "step": 1,
          "action": "what attacker does",
          "target": "what is targeted",
          "technique": "how it's done",
          "detection_difficulty": "high|medium|low"
        }}
      ],
      "preconditions": ["required conditions"],
      "success_likelihood": 0.0-1.0,
      "impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "mitigation": "how to prevent this attack"
    }}
  ]
}}"""

        try:
            response = bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4000,
                    "messages": [{
                        "role": "user",
                        "content": prompt
                    }],
                    "temperature": 0.3  # Slightly higher for creative attack prediction
                })
            )
            
            response_body = json.loads(response['body'].read())
            predictions = json.loads(response_body['content'][0]['text'])
            
            return predictions.get('attack_paths', [])
            
        except Exception as e:
            logger.error(f"Attack path prediction failed: {e}")
            return []
    
    def _store_flow_analysis(self, analysis_type: str, analysis: Dict[str, Any]):
        """Store flow analysis results"""
        try:
            self.flow_analysis_table.put_item(
                Item={
                    'analysis_id': hashlib.sha256(
                        f"{analysis_type}:{datetime.utcnow().isoformat()}".encode()
                    ).hexdigest()[:16],
                    'analysis_type': analysis_type,
                    'timestamp': datetime.utcnow().isoformat(),
                    'analysis_json': json.dumps(analysis),
                    'ttl': int((datetime.utcnow() + timedelta(days=30)).timestamp())
                }
            )
        except Exception as e:
            logger.error(f"Failed to store flow analysis: {e}")


# Facade class for easy access to all AI features
class AISecurityFeatures:
    """
    Unified interface for all AI-powered security features
    """
    
    def __init__(self):
        self.supply_chain = AISupplyChainIntelligence()
        self.policy_engine = AICustomPolicyEngine()
        self.flow_analyzer = AICodeFlowAnalyzer()
    
    def comprehensive_ai_analysis(self, 
                                code: str,
                                file_path: str,
                                dependencies: Dict[str, str] = None,
                                language: str = None) -> Dict[str, Any]:
        """
        Perform comprehensive AI security analysis
        """
        results = {
            'file_path': file_path,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'vulnerabilities': [],
            'policy_violations': [],
            'supply_chain_risks': {},
            'attack_paths': [],
            'risk_score': 0.0
        }
        
        # Supply chain analysis
        if dependencies:
            results['supply_chain_risks'] = self.supply_chain.analyze_dependencies_with_ai(
                dependencies, language or 'unknown'
            )
        
        # Policy evaluation
        results['policy_violations'] = self.policy_engine.evaluate_code_against_policies(
            code, file_path
        )
        
        # Flow analysis
        flow_results = self.flow_analyzer.analyze_control_flow_security(code)
        if 'control_flow_issues' in flow_results:
            results['vulnerabilities'].extend(flow_results['control_flow_issues'])
        
        # Attack path prediction
        results['attack_paths'] = self.flow_analyzer.predict_attack_paths(
            f"File: {file_path}", [code]
        )
        
        # Calculate overall risk score
        results['risk_score'] = self._calculate_risk_score(results)
        
        return results
    
    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score from analysis results"""
        score = 0.0
        
        # Supply chain risks
        for package, vulns in results['supply_chain_risks'].items():
            for vuln in vulns:
                severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2}
                score += severity_scores.get(vuln.severity, 0) * vuln.ai_confidence
        
        # Policy violations
        for violation in results['policy_violations']:
            severity_scores = {'CRITICAL': 8, 'HIGH': 6, 'MEDIUM': 3, 'LOW': 1}
            score += severity_scores.get(violation.severity, 0) * violation.ai_confidence
        
        # Vulnerabilities
        for vuln in results['vulnerabilities']:
            severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2}
            score += severity_scores.get(vuln.get('severity', 'MEDIUM'), 0)
        
        # Attack paths
        for path in results['attack_paths']:
            impact_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2}
            score += impact_scores.get(path.get('impact', 'MEDIUM'), 0) * path.get('success_likelihood', 0.5)
        
        # Normalize to 0-100
        return min(100.0, score)