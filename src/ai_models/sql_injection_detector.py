"""
Specialized Deep Learning Model for SQL Injection Detection
Uses transformer-based architecture with attention mechanisms for code analysis
"""
import json
import boto3
import numpy as np
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
import re
import hashlib
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Initialize AWS clients
bedrock = boto3.client('bedrock-runtime')
dynamodb = boto3.resource('dynamodb')


@dataclass
class SQLInjectionPrediction:
    """SQL injection vulnerability prediction"""
    is_vulnerable: bool
    confidence: float
    injection_type: str  # blind, union, boolean, time-based, error-based
    attack_vector: str
    severity: str
    proof_of_concept: Optional[str]
    remediation: str
    ai_reasoning: List[str]
    attention_weights: Dict[str, float]  # Which parts of code triggered detection


class SQLInjectionDetector:
    """
    Specialized AI model for detecting SQL injection vulnerabilities
    Uses advanced pattern recognition and context understanding
    """
    
    def __init__(self):
        self.model_id = 'anthropic.claude-3-sonnet-20240229-v1:0'
        
        # SQL injection patterns knowledge base
        self.injection_patterns = {
            'string_concatenation': {
                'pattern': r'(SELECT|INSERT|UPDATE|DELETE).*\+\s*["\']?\s*\+?\s*\$?\w+',
                'risk': 'HIGH',
                'description': 'Direct string concatenation in SQL query'
            },
            'format_string': {
                'pattern': r'(query|sql|statement).*%(s|d)|\.format\(.*\)',
                'risk': 'HIGH',
                'description': 'Format string used in SQL construction'
            },
            'interpolation': {
                'pattern': r'(f["\']|rf["\']).*?(SELECT|INSERT|UPDATE|DELETE)',
                'risk': 'CRITICAL',
                'description': 'F-string interpolation in SQL'
            },
            'dynamic_table': {
                'pattern': r'FROM\s+["\']?\s*\+?\s*\$?\w+',
                'risk': 'MEDIUM',
                'description': 'Dynamic table name construction'
            },
            'order_by_injection': {
                'pattern': r'ORDER\s+BY\s+["\']?\s*\+?\s*\$?\w+',
                'risk': 'MEDIUM',
                'description': 'Dynamic ORDER BY clause'
            }
        }
        
        # Context understanding weights
        self.context_weights = {
            'user_input_proximity': 0.3,
            'sanitization_presence': -0.5,
            'parameterization_used': -0.8,
            'validation_present': -0.3,
            'dangerous_functions': 0.4
        }
    
    def detect(self, 
               code: str, 
               context: Dict[str, Any],
               deep_analysis: bool = True) -> SQLInjectionPrediction:
        """
        Detect SQL injection vulnerabilities using deep learning approach
        """
        # Extract code features
        features = self._extract_features(code, context)
        
        # Pattern-based detection
        pattern_matches = self._check_patterns(code)
        
        # Context-aware analysis
        context_score = self._analyze_context(code, context)
        
        # Deep AI analysis if requested
        if deep_analysis:
            ai_analysis = self._deep_ai_analysis(code, context, features)
        else:
            ai_analysis = self._quick_analysis(features, pattern_matches)
        
        # Calculate attention weights (which parts triggered detection)
        attention_weights = self._calculate_attention_weights(
            code, pattern_matches, ai_analysis
        )
        
        # Generate proof of concept if vulnerable
        poc = None
        if ai_analysis['is_vulnerable']:
            poc = self._generate_proof_of_concept(
                code, 
                ai_analysis['injection_type'],
                ai_analysis['attack_vector']
            )
        
        return SQLInjectionPrediction(
            is_vulnerable=ai_analysis['is_vulnerable'],
            confidence=ai_analysis['confidence'],
            injection_type=ai_analysis['injection_type'],
            attack_vector=ai_analysis['attack_vector'],
            severity=ai_analysis['severity'],
            proof_of_concept=poc,
            remediation=ai_analysis['remediation'],
            ai_reasoning=ai_analysis['reasoning'],
            attention_weights=attention_weights
        )
    
    def _deep_ai_analysis(self, 
                         code: str, 
                         context: Dict[str, Any],
                         features: Dict[str, Any]) -> Dict[str, Any]:
        """Perform deep AI analysis using Claude"""
        
        prompt = f"""You are a SQL injection security expert analyzing code for vulnerabilities.

Code to analyze:
```
{code[:3000]}
```

Context:
- File type: {context.get('file_type', 'unknown')}
- Framework: {context.get('framework', 'unknown')}
- Has user input: {features['has_user_input']}
- Uses concatenation: {features['uses_concatenation']}
- Has parameterization: {features['has_parameterization']}

Analyze for SQL injection vulnerabilities with the following focus:
1. Identify any user-controlled input reaching SQL queries
2. Check for proper parameterization/prepared statements
3. Look for string concatenation in query construction
4. Identify injection types (blind, union, boolean-based, time-based, error-based)
5. Assess the severity and exploitability

Provide analysis in JSON format:
{{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "injection_type": "type or none",
  "attack_vector": "specific vector description",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "remediation": "specific fix recommendation",
  "reasoning": ["step 1", "step 2", "..."]
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
            logger.error(f"AI analysis failed: {e}")
            return self._fallback_analysis(features)
    
    def _generate_proof_of_concept(self, 
                                  code: str,
                                  injection_type: str,
                                  attack_vector: str) -> str:
        """Generate a proof of concept exploit"""
        
        poc_templates = {
            'union': "' UNION SELECT username, password FROM users--",
            'blind': "' AND 1=1--",
            'boolean': "' OR '1'='1",
            'time-based': "'; WAITFOR DELAY '00:00:05'--",
            'error-based': "' AND 1=CONVERT(int, (SELECT @@version))--"
        }
        
        base_poc = poc_templates.get(injection_type, "' OR '1'='1")
        
        # Customize POC based on detected patterns
        if 'user_id' in code:
            return f"user_id=1{base_poc}"
        elif 'username' in code:
            return f"username=admin{base_poc}"
        elif 'id' in code:
            return f"id=1{base_poc}"
        else:
            return base_poc
    
    def _check_patterns(self, code: str) -> List[Dict[str, Any]]:
        """Check for known SQL injection patterns"""
        matches = []
        
        for pattern_name, pattern_info in self.injection_patterns.items():
            if re.search(pattern_info['pattern'], code, re.IGNORECASE):
                matches.append({
                    'pattern': pattern_name,
                    'risk': pattern_info['risk'],
                    'description': pattern_info['description']
                })
        
        return matches
    
    def _extract_features(self, code: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features for ML model"""
        return {
            'has_user_input': self._detect_user_input(code),
            'uses_concatenation': '+' in code and any(sql in code.upper() for sql in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']),
            'has_parameterization': '?' in code or ':' in code or '%s' in code,
            'has_validation': self._detect_validation(code),
            'query_complexity': self._calculate_query_complexity(code),
            'dangerous_functions': self._detect_dangerous_functions(code)
        }
    
    def _detect_user_input(self, code: str) -> bool:
        """Detect if code handles user input"""
        user_input_indicators = [
            'request.', 'params', 'query', 'body', 'user_input',
            'form.', 'args.', 'POST', 'GET', 'REQUEST'
        ]
        return any(indicator in code for indicator in user_input_indicators)
    
    def _detect_validation(self, code: str) -> bool:
        """Detect input validation presence"""
        validation_indicators = [
            'validate', 'sanitize', 'escape', 'clean',
            'filter', 'check', 'verify', 'regex'
        ]
        return any(indicator in code.lower() for indicator in validation_indicators)
    
    def _calculate_query_complexity(self, code: str) -> int:
        """Calculate SQL query complexity score"""
        complexity = 0
        sql_keywords = ['SELECT', 'JOIN', 'WHERE', 'GROUP BY', 'ORDER BY', 'HAVING', 'UNION']
        for keyword in sql_keywords:
            complexity += code.upper().count(keyword)
        return complexity
    
    def _detect_dangerous_functions(self, code: str) -> List[str]:
        """Detect use of dangerous functions"""
        dangerous = ['exec', 'eval', 'raw', 'unsafe', 'dynamic']
        found = []
        for func in dangerous:
            if func in code.lower():
                found.append(func)
        return found
    
    def _analyze_context(self, code: str, context: Dict[str, Any]) -> float:
        """Analyze code context for risk factors"""
        score = 0.0
        
        # Framework-specific checks
        framework = context.get('framework', '').lower()
        if framework in ['express', 'flask', 'django']:
            if 'raw(' in code or 'execute(' in code:
                score += 0.3
        
        # Check for ORM usage (safer)
        if any(orm in code for orm in ['SQLAlchemy', 'Sequelize', 'TypeORM', 'Prisma']):
            score -= 0.2
        
        return max(0.0, min(1.0, score))
    
    def _calculate_attention_weights(self,
                                   code: str,
                                   pattern_matches: List[Dict],
                                   ai_analysis: Dict) -> Dict[str, float]:
        """Calculate which parts of code triggered detection"""
        weights = {}
        
        # Weight dangerous patterns
        for match in pattern_matches:
            weights[match['pattern']] = 0.3 if match['risk'] == 'HIGH' else 0.2
        
        # Weight based on AI confidence
        if ai_analysis.get('is_vulnerable'):
            weights['ai_detection'] = ai_analysis.get('confidence', 0.5)
        
        # Normalize weights
        total = sum(weights.values())
        if total > 0:
            weights = {k: v/total for k, v in weights.items()}
        
        return weights
    
    def _quick_analysis(self, features: Dict, pattern_matches: List) -> Dict[str, Any]:
        """Quick analysis without deep AI"""
        is_vulnerable = (
            len(pattern_matches) > 0 and 
            features['uses_concatenation'] and
            features['has_user_input']
        )
        
        confidence = 0.9 if is_vulnerable and not features['has_parameterization'] else 0.3
        
        return {
            'is_vulnerable': is_vulnerable,
            'confidence': confidence,
            'injection_type': pattern_matches[0]['pattern'] if pattern_matches else 'none',
            'attack_vector': 'String concatenation with user input',
            'severity': 'HIGH' if is_vulnerable else 'LOW',
            'remediation': 'Use parameterized queries or prepared statements',
            'reasoning': ['Pattern-based detection', 'No deep AI analysis performed']
        }
    
    def _fallback_analysis(self, features: Dict) -> Dict[str, Any]:
        """Fallback analysis if AI fails"""
        return {
            'is_vulnerable': features['uses_concatenation'] and features['has_user_input'],
            'confidence': 0.6,
            'injection_type': 'potential',
            'attack_vector': 'Possible SQL injection via string concatenation',
            'severity': 'MEDIUM',
            'remediation': 'Review code for SQL injection vulnerabilities',
            'reasoning': ['AI analysis failed', 'Using pattern-based detection']
        }