"""
Pure AI Vulnerability Detection
No traditional tool dependencies - 100% AI-based security analysis
"""
import json
import boto3
import asyncio
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import re
import logging

logger = logging.getLogger(__name__)

# Initialize AWS clients
bedrock = boto3.client('bedrock-runtime')
dynamodb = boto3.resource('dynamodb')


@dataclass
class AIVulnerability:
    """Pure AI-detected vulnerability"""
    vuln_id: str
    vulnerability_type: str
    description: str
    severity: str
    confidence: float
    file_path: str
    line_numbers: List[int]
    code_snippet: str
    exploitation_scenario: str
    fix_recommendation: str
    ai_reasoning: List[str]
    detection_method: str = "pure_ai"
    traditional_tool_equivalent: Optional[str] = None


@dataclass
class AISecurityFinding:
    """Comprehensive AI security finding"""
    finding_id: str
    finding_type: str  # vulnerability, misconfiguration, bad_practice, security_debt
    title: str
    description: str
    risk_score: float  # 0-10
    exploitability: float  # 0-1
    business_impact: str
    technical_details: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    remediation: Dict[str, Any]
    ai_confidence: float
    detection_timestamp: datetime


class PureAIVulnerabilityDetector:
    """
    100% AI-based vulnerability detection without any traditional security tools
    Direct code understanding and vulnerability reasoning
    """
    
    def __init__(self):
        self.model_id = 'anthropic.claude-3-sonnet-20240229-v1:0'
        
        # DynamoDB tables for pure AI findings
        self.ai_findings_table = dynamodb.Table('SecurityAuditPureAIFindings')
        self.ai_patterns_table = dynamodb.Table('SecurityAuditAIPatterns')
        
        # AI-learned vulnerability patterns (no tool formats)
        self.vulnerability_signatures = self._initialize_ai_signatures()
        
    async def detect_vulnerabilities(self,
                                   code: str,
                                   context: Dict[str, Any]) -> List[AIVulnerability]:
        """
        Pure AI vulnerability detection without any traditional tools
        """
        vulnerabilities = []
        
        # Multi-pass AI analysis
        # Pass 1: General vulnerability scan
        general_vulns = await self._ai_general_scan(code, context)
        vulnerabilities.extend(general_vulns)
        
        # Pass 2: Deep semantic analysis
        semantic_vulns = await self._ai_semantic_analysis(code, context)
        vulnerabilities.extend(semantic_vulns)
        
        # Pass 3: Behavioral analysis
        behavioral_vulns = await self._ai_behavioral_analysis(code, context)
        vulnerabilities.extend(behavioral_vulns)
        
        # Pass 4: Cross-reference analysis
        cross_ref_vulns = await self._ai_cross_reference_analysis(code, context, vulnerabilities)
        vulnerabilities.extend(cross_ref_vulns)
        
        # Deduplicate and rank
        unique_vulns = self._deduplicate_findings(vulnerabilities)
        ranked_vulns = self._rank_by_severity(unique_vulns)
        
        # Store findings
        for vuln in ranked_vulns:
            self._store_ai_finding(vuln)
        
        return ranked_vulns
    
    async def _ai_general_scan(self,
                              code: str,
                              context: Dict[str, Any]) -> List[AIVulnerability]:
        """
        General AI vulnerability scan - no traditional patterns
        """
        prompt = f"""You are an advanced AI security analyzer examining code for vulnerabilities.
DO NOT reference or use patterns from traditional tools like Semgrep, Bandit, or others.
Use pure reasoning and understanding of security principles.

Code to analyze:
```{context.get('language', 'unknown')}
{code[:5000]}
```

File: {context.get('file_path', 'unknown')}
Framework: {context.get('framework', 'unknown')}

Perform deep security analysis:
1. Understand the code's purpose and data flow
2. Identify security vulnerabilities through reasoning
3. Consider the specific technology context
4. Think about how an attacker might exploit this code
5. Do NOT mention traditional security tools

For each vulnerability found, provide:
- Clear explanation of the vulnerability
- Why it's dangerous in this specific context
- How it could be exploited
- Specific fix for this code

Provide findings in JSON format:
{{
  "vulnerabilities": [
    {{
      "type": "vulnerability category",
      "description": "detailed explanation",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0.0-1.0,
      "line_numbers": [line1, line2],
      "vulnerable_code": "exact code snippet",
      "exploitation_scenario": "how an attacker would exploit this",
      "fix_recommendation": "specific fix code",
      "reasoning": ["step1", "step2", "step3"]
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
                    "temperature": 0.2
                })
            )
            
            response_body = json.loads(response['body'].read())
            findings = json.loads(response_body['content'][0]['text'])
            
            vulnerabilities = []
            for vuln in findings.get('vulnerabilities', []):
                vulnerability = AIVulnerability(
                    vuln_id=self._generate_vuln_id(),
                    vulnerability_type=vuln['type'],
                    description=vuln['description'],
                    severity=vuln['severity'],
                    confidence=vuln['confidence'],
                    file_path=context.get('file_path', 'unknown'),
                    line_numbers=vuln['line_numbers'],
                    code_snippet=vuln['vulnerable_code'],
                    exploitation_scenario=vuln['exploitation_scenario'],
                    fix_recommendation=vuln['fix_recommendation'],
                    ai_reasoning=vuln['reasoning'],
                    detection_method="ai_general_scan"
                )
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"AI general scan failed: {e}")
            return []
    
    async def _ai_semantic_analysis(self,
                                  code: str,
                                  context: Dict[str, Any]) -> List[AIVulnerability]:
        """
        Deep semantic understanding of code for vulnerabilities
        """
        prompt = f"""You are an AI performing deep semantic security analysis.
Focus on understanding the MEANING and INTENT of the code, not pattern matching.

Code to analyze:
```{context.get('language', 'unknown')}
{code[:4000]}
```

Perform semantic security analysis:
1. What is this code trying to accomplish?
2. What assumptions does it make about inputs?
3. What trust boundaries does it cross?
4. What security guarantees should it provide?
5. Where does it fail to provide those guarantees?

Look for semantic vulnerabilities:
- Logic flaws that break security assumptions
- Missing security controls for the use case
- Incorrect implementations of security concepts
- Business logic vulnerabilities
- State management issues
- Race conditions in the logic

Provide findings in JSON format:
{{
  "semantic_vulnerabilities": [
    {{
      "vulnerability_type": "semantic vulnerability type",
      "semantic_issue": "what security assumption is broken",
      "description": "detailed explanation",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0.0-1.0,
      "affected_lines": [line1, line2],
      "problematic_logic": "the flawed logic",
      "security_impact": "what security guarantee is violated",
      "proper_implementation": "how it should be done",
      "reasoning": ["semantic analysis step 1", "step 2"]
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
            findings = json.loads(response_body['content'][0]['text'])
            
            vulnerabilities = []
            for vuln in findings.get('semantic_vulnerabilities', []):
                vulnerability = AIVulnerability(
                    vuln_id=self._generate_vuln_id(),
                    vulnerability_type=f"semantic_{vuln['vulnerability_type']}",
                    description=vuln['description'],
                    severity=vuln['severity'],
                    confidence=vuln['confidence'],
                    file_path=context.get('file_path', 'unknown'),
                    line_numbers=vuln['affected_lines'],
                    code_snippet=vuln['problematic_logic'],
                    exploitation_scenario=vuln['security_impact'],
                    fix_recommendation=vuln['proper_implementation'],
                    ai_reasoning=vuln['reasoning'],
                    detection_method="ai_semantic_analysis"
                )
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"AI semantic analysis failed: {e}")
            return []
    
    async def _ai_behavioral_analysis(self,
                                    code: str,
                                    context: Dict[str, Any]) -> List[AIVulnerability]:
        """
        Analyze code behavior for security issues
        """
        prompt = f"""You are an AI analyzing code BEHAVIOR for security vulnerabilities.
Focus on what the code DOES, not what it looks like.

Code to analyze:
```{context.get('language', 'unknown')}
{code[:4000]}
```

Analyze the code's behavior:
1. What external resources does it access?
2. How does it handle user input?
3. What side effects does it have?
4. How does it manage state?
5. What happens in edge cases?

Look for behavioral vulnerabilities:
- Unsafe resource access patterns
- Missing bounds checks in loops/recursion
- Improper error handling that leaks information
- Side effects that violate security principles
- State mutations that break invariants
- Timing-based vulnerabilities

Provide findings in JSON format:
{{
  "behavioral_vulnerabilities": [
    {{
      "behavior_type": "unsafe behavior category",
      "description": "what the code does wrong",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0.0-1.0,
      "code_lines": [line1, line2],
      "unsafe_behavior": "specific behavior description",
      "attack_scenario": "how to exploit this behavior",
      "safe_behavior": "how it should behave",
      "fix_code": "corrected implementation",
      "analysis_reasoning": ["behavior analysis step 1", "step 2"]
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
            findings = json.loads(response_body['content'][0]['text'])
            
            vulnerabilities = []
            for vuln in findings.get('behavioral_vulnerabilities', []):
                vulnerability = AIVulnerability(
                    vuln_id=self._generate_vuln_id(),
                    vulnerability_type=f"behavioral_{vuln['behavior_type']}",
                    description=vuln['description'],
                    severity=vuln['severity'],
                    confidence=vuln['confidence'],
                    file_path=context.get('file_path', 'unknown'),
                    line_numbers=vuln['code_lines'],
                    code_snippet=vuln['unsafe_behavior'],
                    exploitation_scenario=vuln['attack_scenario'],
                    fix_recommendation=vuln['fix_code'],
                    ai_reasoning=vuln['analysis_reasoning'],
                    detection_method="ai_behavioral_analysis"
                )
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"AI behavioral analysis failed: {e}")
            return []
    
    async def _ai_cross_reference_analysis(self,
                                         code: str,
                                         context: Dict[str, Any],
                                         found_vulns: List[AIVulnerability]) -> List[AIVulnerability]:
        """
        Cross-reference analysis to find vulnerability chains
        """
        if not found_vulns:
            return []
        
        # Prepare summary of found vulnerabilities
        vuln_summary = [
            {
                'type': v.vulnerability_type,
                'location': f"lines {v.line_numbers}",
                'description': v.description[:100]
            }
            for v in found_vulns[:10]
        ]
        
        prompt = f"""You are an AI finding vulnerability CHAINS and COMBINATIONS.

Already found vulnerabilities:
{json.dumps(vuln_summary, indent=2)}

Code context:
```{context.get('language', 'unknown')}
{code[:3000]}
```

Analyze for:
1. How vulnerabilities could be chained together
2. Combined exploits using multiple vulnerabilities
3. Vulnerabilities that amplify each other
4. New vulnerabilities exposed by fixing others
5. Hidden vulnerabilities revealed by the found ones

Provide findings in JSON format:
{{
  "vulnerability_chains": [
    {{
      "chain_type": "type of vulnerability chain",
      "description": "how vulnerabilities combine",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": 0.0-1.0,
      "vulnerabilities_involved": ["vuln type 1", "vuln type 2"],
      "combined_impact": "impact when chained",
      "exploitation_path": "step-by-step exploitation",
      "mitigation_strategy": "how to break the chain",
      "reasoning": ["analysis step 1", "step 2"]
    }}
  ]
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
                    "temperature": 0.3
                })
            )
            
            response_body = json.loads(response['body'].read())
            findings = json.loads(response_body['content'][0]['text'])
            
            vulnerabilities = []
            for chain in findings.get('vulnerability_chains', []):
                # Create a composite vulnerability for the chain
                vulnerability = AIVulnerability(
                    vuln_id=self._generate_vuln_id(),
                    vulnerability_type=f"chain_{chain['chain_type']}",
                    description=chain['description'],
                    severity=chain['severity'],
                    confidence=chain['confidence'],
                    file_path=context.get('file_path', 'unknown'),
                    line_numbers=[],  # Chains may span multiple locations
                    code_snippet=chain['combined_impact'],
                    exploitation_scenario=chain['exploitation_path'],
                    fix_recommendation=chain['mitigation_strategy'],
                    ai_reasoning=chain['reasoning'],
                    detection_method="ai_cross_reference"
                )
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"AI cross-reference analysis failed: {e}")
            return []
    
    def detect_without_patterns(self,
                              code: str,
                              language: str) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities without any pattern matching
        Pure AI understanding only
        """
        prompt = f"""You are an AI that understands security deeply.
Analyze this {language} code for vulnerabilities using ONLY your understanding.
Do NOT use any regex patterns or traditional tool approaches.

Code:
```{language}
{code}
```

Think about:
- What could go wrong?
- How could an attacker misuse this?
- What security properties are missing?
- What assumptions might be violated?

Respond with vulnerabilities found through pure understanding."""

        # This method demonstrates pure AI detection
        # No patterns, no traditional approaches
        # Just AI reasoning about security
        
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
                    "temperature": 0.2
                })
            )
            
            # Process pure AI understanding
            return self._process_pure_ai_response(response)
            
        except Exception as e:
            logger.error(f"Pure AI detection failed: {e}")
            return []
    
    def _initialize_ai_signatures(self) -> Dict[str, Any]:
        """
        Initialize AI-learned signatures (not traditional patterns)
        These are semantic signatures, not regex
        """
        return {
            'trust_boundary_violation': {
                'description': 'Code that trusts external input without validation',
                'ai_indicators': ['user_input', 'external_data', 'no_validation']
            },
            'state_confusion': {
                'description': 'Code with unclear or mutable security state',
                'ai_indicators': ['global_state', 'race_conditions', 'unclear_ownership']
            },
            'crypto_misuse': {
                'description': 'Cryptography used incorrectly for the context',
                'ai_indicators': ['weak_algorithms', 'bad_randomness', 'key_management']
            }
        }
    
    def _deduplicate_findings(self, vulnerabilities: List[AIVulnerability]) -> List[AIVulnerability]:
        """Deduplicate findings based on similarity"""
        unique = {}
        
        for vuln in vulnerabilities:
            # Create a signature for deduplication
            sig = f"{vuln.vulnerability_type}:{vuln.file_path}:{sorted(vuln.line_numbers)}"
            
            if sig not in unique:
                unique[sig] = vuln
            else:
                # Keep the one with higher confidence
                if vuln.confidence > unique[sig].confidence:
                    unique[sig] = vuln
        
        return list(unique.values())
    
    def _rank_by_severity(self, vulnerabilities: List[AIVulnerability]) -> List[AIVulnerability]:
        """Rank vulnerabilities by severity and confidence"""
        severity_scores = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }
        
        return sorted(
            vulnerabilities,
            key=lambda v: (severity_scores.get(v.severity, 0) * v.confidence),
            reverse=True
        )
    
    def _generate_vuln_id(self) -> str:
        """Generate unique vulnerability ID"""
        timestamp = datetime.utcnow().isoformat()
        random_component = hashlib.sha256(timestamp.encode()).hexdigest()[:8]
        return f"AI-VULN-{random_component}"
    
    def _store_ai_finding(self, vulnerability: AIVulnerability):
        """Store pure AI finding in DynamoDB"""
        try:
            self.ai_findings_table.put_item(
                Item={
                    'vuln_id': vulnerability.vuln_id,
                    'vulnerability_type': vulnerability.vulnerability_type,
                    'description': vulnerability.description,
                    'severity': vulnerability.severity,
                    'confidence': float(vulnerability.confidence),
                    'file_path': vulnerability.file_path,
                    'line_numbers': vulnerability.line_numbers,
                    'code_snippet': vulnerability.code_snippet[:500],  # Truncate for storage
                    'exploitation_scenario': vulnerability.exploitation_scenario,
                    'fix_recommendation': vulnerability.fix_recommendation,
                    'ai_reasoning': vulnerability.ai_reasoning,
                    'detection_method': vulnerability.detection_method,
                    'detected_at': datetime.utcnow().isoformat(),
                    'pure_ai': True,  # Flag for pure AI detection
                    'ttl': int((datetime.utcnow().timestamp()) + 86400 * 90)  # 90 day TTL
                }
            )
        except Exception as e:
            logger.error(f"Failed to store AI finding: {e}")
    
    def _process_pure_ai_response(self, response: Any) -> List[Dict[str, Any]]:
        """Process response from pure AI analysis"""
        try:
            response_body = json.loads(response['body'].read())
            # Extract findings from AI's natural language response
            # This demonstrates processing unstructured AI output
            return []  # Simplified for brevity
        except Exception as e:
            logger.error(f"Failed to process AI response: {e}")
            return []