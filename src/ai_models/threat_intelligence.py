"""
AI Security Intelligence
Threat intelligence AI that learns from global attacks and provides predictive vulnerability discovery
"""
import json
import boto3
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np
import logging

logger = logging.getLogger(__name__)

# Initialize AWS clients
bedrock = boto3.client('bedrock-runtime')
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')


@dataclass
class ThreatIntelligence:
    """AI-generated threat intelligence"""
    threat_id: str
    threat_type: str  # zero-day, emerging, known, variant
    threat_name: str
    description: str
    severity: str
    likelihood: float  # 0-1 probability of exploitation
    attack_vectors: List[str]
    affected_technologies: List[str]
    indicators_of_compromise: List[str]
    mitigation_strategies: List[str]
    ai_confidence: float
    discovered_at: datetime
    related_cves: List[str] = field(default_factory=list)
    predicted_evolution: Optional[str] = None


@dataclass
class VulnerabilityPrediction:
    """Predictive vulnerability discovery"""
    prediction_id: str
    vulnerability_type: str
    affected_component: str
    description: str
    predicted_severity: str
    likelihood_of_discovery: float
    time_to_exploit: str  # "immediate", "days", "weeks", "months"
    reasoning: List[str]
    preventive_measures: List[str]
    code_patterns: List[str]
    ai_confidence: float


class AISecurityIntelligence:
    """
    AI-powered threat intelligence that learns from global attacks
    and provides predictive vulnerability discovery
    """
    
    def __init__(self):
        self.model_id = 'anthropic.claude-3-sonnet-20240229-v1:0'
        
        # DynamoDB tables
        self.threat_intel_table = dynamodb.Table('SecurityAuditThreatIntel')
        self.predictions_table = dynamodb.Table('SecurityAuditVulnPredictions')
        self.attack_patterns_table = dynamodb.Table('SecurityAuditAttackPatterns')
        
        # S3 buckets
        self.intel_bucket = 'security-audit-threat-intel'
        
        # Knowledge base
        self.attack_patterns = self._load_attack_patterns()
        self.vulnerability_trends = self._load_vulnerability_trends()
        
    def analyze_global_threats(self, 
                             code_patterns: List[str],
                             technology_stack: List[str],
                             time_window: int = 30) -> List[ThreatIntelligence]:
        """
        Analyze global threat landscape and identify relevant threats
        """
        # Get recent attack patterns
        recent_attacks = self._get_recent_attacks(time_window)
        
        # AI analysis of threat landscape
        threats = self._ai_threat_analysis(
            code_patterns,
            technology_stack,
            recent_attacks
        )
        
        # Correlate with known vulnerabilities
        correlated_threats = self._correlate_threats(threats)
        
        # Store intelligence
        for threat in correlated_threats:
            self._store_threat_intelligence(threat)
        
        return correlated_threats
    
    def predict_vulnerabilities(self,
                              codebase_analysis: Dict[str, Any],
                              historical_vulnerabilities: List[Dict]) -> List[VulnerabilityPrediction]:
        """
        Predict future vulnerabilities before they're discovered
        """
        predictions = []
        
        # Analyze code patterns for vulnerability indicators
        pattern_risks = self._analyze_vulnerability_patterns(codebase_analysis)
        
        # Use AI to predict vulnerabilities
        ai_predictions = self._ai_predictive_analysis(
            codebase_analysis,
            historical_vulnerabilities,
            pattern_risks
        )
        
        # Generate actionable predictions
        for pred in ai_predictions:
            prediction = VulnerabilityPrediction(
                prediction_id=self._generate_id('pred'),
                vulnerability_type=pred['type'],
                affected_component=pred['component'],
                description=pred['description'],
                predicted_severity=pred['severity'],
                likelihood_of_discovery=pred['likelihood'],
                time_to_exploit=pred['time_to_exploit'],
                reasoning=pred['reasoning'],
                preventive_measures=pred['preventive_measures'],
                code_patterns=pred['code_patterns'],
                ai_confidence=pred['confidence']
            )
            predictions.append(prediction)
            self._store_prediction(prediction)
        
        return predictions
    
    def correlate_security_events(self,
                                events: List[Dict[str, Any]],
                                context: Dict[str, Any]) -> Dict[str, Any]:
        """
        AI correlation of disparate security events
        """
        prompt = f"""You are a security intelligence analyst correlating security events.

Events to analyze:
{json.dumps(events[:20], indent=2)}

Context:
- Repository: {context.get('repository', 'unknown')}
- Time range: {context.get('time_range', 'last 7 days')}
- Technology stack: {context.get('tech_stack', [])}

Perform deep correlation analysis:
1. Identify patterns across events
2. Detect potential attack campaigns
3. Find hidden relationships
4. Assess combined risk
5. Predict next steps in attack chain

Provide analysis in JSON format:
{{
  "correlation_findings": [
    {{
      "pattern": "identified pattern",
      "related_events": ["event_ids"],
      "attack_campaign": "campaign name or none",
      "confidence": 0.0-1.0,
      "risk_level": "CRITICAL|HIGH|MEDIUM|LOW"
    }}
  ],
  "attack_chains": [
    {{
      "chain_name": "attack chain description",
      "steps": ["step1", "step2"],
      "current_stage": "stage",
      "predicted_next": "next likely action"
    }}
  ],
  "recommendations": ["action1", "action2"]
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
            correlation = json.loads(response_body['content'][0]['text'])
            
            return correlation
            
        except Exception as e:
            logger.error(f"Event correlation failed: {e}")
            return {"error": str(e)}
    
    def threat_hunting(self,
                      code_repository: str,
                      hunt_parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        AI-powered proactive threat hunting
        """
        # Define hunting queries based on parameters
        hunt_type = hunt_parameters.get('type', 'comprehensive')
        
        # Prepare threat hunting prompt
        prompt = f"""You are an advanced threat hunter analyzing code for hidden vulnerabilities.

Repository: {code_repository}
Hunt type: {hunt_type}
Focus areas: {hunt_parameters.get('focus_areas', ['all'])}

Perform advanced threat hunting:
1. Look for subtle vulnerability indicators
2. Identify attack surface expansion
3. Find logic bombs or backdoors
4. Detect supply chain risks
5. Uncover time-bomb vulnerabilities

Use these advanced techniques:
- Behavioral analysis
- Pattern anomaly detection  
- Statistical outlier identification
- Cross-reference with threat intelligence

Provide findings in JSON format:
{{
  "hidden_threats": [
    {{
      "threat_type": "type",
      "description": "detailed description",
      "indicators": ["indicator1", "indicator2"],
      "confidence": 0.0-1.0,
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "hunt_technique": "technique used"
    }}
  ],
  "suspicious_patterns": [
    {{
      "pattern": "pattern description",
      "locations": ["file:line"],
      "risk_assessment": "assessment"
    }}
  ],
  "recommendations": ["recommendation1", "recommendation2"]
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
                    "temperature": 0.3
                })
            )
            
            response_body = json.loads(response['body'].read())
            hunt_results = json.loads(response_body['content'][0]['text'])
            
            # Process and enrich results
            findings = []
            for threat in hunt_results.get('hidden_threats', []):
                finding = {
                    'finding_id': self._generate_id('hunt'),
                    'timestamp': datetime.utcnow().isoformat(),
                    'repository': code_repository,
                    **threat
                }
                findings.append(finding)
                
            return findings
            
        except Exception as e:
            logger.error(f"Threat hunting failed: {e}")
            return []
    
    def _ai_threat_analysis(self,
                          code_patterns: List[str],
                          technology_stack: List[str],
                          recent_attacks: List[Dict]) -> List[Dict]:
        """
        AI analysis of threats based on code and attack patterns
        """
        prompt = f"""You are a threat intelligence expert analyzing potential security threats.

Code patterns observed:
{json.dumps(code_patterns[:10], indent=2)}

Technology stack:
{json.dumps(technology_stack, indent=2)}

Recent global attacks:
{json.dumps(recent_attacks[:5], indent=2)}

Analyze and identify:
1. Relevant threats to this codebase
2. Zero-day vulnerability potential
3. Emerging attack vectors
4. Supply chain risks
5. Technology-specific threats

Provide threat intelligence in JSON format:
{{
  "threats": [
    {{
      "threat_type": "zero-day|emerging|known|variant",
      "threat_name": "descriptive name",
      "description": "detailed description",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "likelihood": 0.0-1.0,
      "attack_vectors": ["vector1", "vector2"],
      "affected_technologies": ["tech1", "tech2"],
      "indicators_of_compromise": ["ioc1", "ioc2"],
      "mitigation_strategies": ["strategy1", "strategy2"],
      "confidence": 0.0-1.0
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
            threats = json.loads(response_body['content'][0]['text'])
            
            return threats.get('threats', [])
            
        except Exception as e:
            logger.error(f"AI threat analysis failed: {e}")
            return []
    
    def _ai_predictive_analysis(self,
                               codebase_analysis: Dict,
                               historical_vulns: List[Dict],
                               pattern_risks: Dict) -> List[Dict]:
        """
        AI-powered predictive vulnerability analysis
        """
        prompt = f"""You are a security researcher predicting future vulnerabilities.

Codebase analysis:
- Languages: {codebase_analysis.get('languages', [])}
- Frameworks: {codebase_analysis.get('frameworks', [])}
- Dependencies: {len(codebase_analysis.get('dependencies', []))} packages
- Code complexity: {codebase_analysis.get('complexity', 'unknown')}

Historical vulnerabilities in similar projects:
{json.dumps(historical_vulns[:5], indent=2)}

Identified risk patterns:
{json.dumps(pattern_risks, indent=2)}

Predict potential vulnerabilities that could be discovered in the future:
1. Analyze attack surface
2. Identify weak points
3. Predict exploitation methods
4. Estimate discovery timeline
5. Suggest preventive measures

Provide predictions in JSON format:
{{
  "predictions": [
    {{
      "type": "vulnerability type",
      "component": "affected component",
      "description": "detailed prediction",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "likelihood": 0.0-1.0,
      "time_to_exploit": "immediate|days|weeks|months",
      "reasoning": ["reason1", "reason2"],
      "preventive_measures": ["measure1", "measure2"],
      "code_patterns": ["pattern1", "pattern2"],
      "confidence": 0.0-1.0
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
            predictions = json.loads(response_body['content'][0]['text'])
            
            return predictions.get('predictions', [])
            
        except Exception as e:
            logger.error(f"Predictive analysis failed: {e}")
            return []
    
    def _analyze_vulnerability_patterns(self, codebase_analysis: Dict) -> Dict[str, float]:
        """Analyze code patterns for vulnerability risk indicators"""
        pattern_risks = {}
        
        # Check for risky patterns
        risky_patterns = {
            'unsafe_deserialization': 0.8,
            'dynamic_code_execution': 0.9,
            'weak_crypto': 0.7,
            'sql_concatenation': 0.8,
            'path_traversal': 0.7,
            'xxe_processing': 0.8,
            'command_injection': 0.9,
            'template_injection': 0.8
        }
        
        # Analyze codebase for patterns
        code_patterns = codebase_analysis.get('patterns', {})
        for pattern, risk_score in risky_patterns.items():
            if pattern in code_patterns:
                pattern_risks[pattern] = risk_score
        
        return pattern_risks
    
    def _correlate_threats(self, threats: List[Dict]) -> List[ThreatIntelligence]:
        """Correlate threats with known vulnerabilities"""
        correlated = []
        
        for threat in threats:
            threat_intel = ThreatIntelligence(
                threat_id=self._generate_id('threat'),
                threat_type=threat['threat_type'],
                threat_name=threat['threat_name'],
                description=threat['description'],
                severity=threat['severity'],
                likelihood=threat['likelihood'],
                attack_vectors=threat['attack_vectors'],
                affected_technologies=threat['affected_technologies'],
                indicators_of_compromise=threat['indicators_of_compromise'],
                mitigation_strategies=threat['mitigation_strategies'],
                ai_confidence=threat['confidence'],
                discovered_at=datetime.utcnow()
            )
            
            # Try to correlate with CVEs
            related_cves = self._find_related_cves(threat)
            if related_cves:
                threat_intel.related_cves = related_cves
            
            correlated.append(threat_intel)
        
        return correlated
    
    def _get_recent_attacks(self, days: int) -> List[Dict]:
        """Get recent attack patterns from threat feeds"""
        # In production, this would connect to threat intelligence feeds
        # For now, return simulated data
        return [
            {
                'attack_type': 'supply_chain',
                'target': 'npm_packages',
                'technique': 'dependency_confusion',
                'severity': 'HIGH'
            },
            {
                'attack_type': 'zero_day',
                'target': 'web_frameworks',
                'technique': 'prototype_pollution',
                'severity': 'CRITICAL'
            }
        ]
    
    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load known attack patterns"""
        # In production, load from S3 or database
        return {
            'sql_injection': {
                'indicators': ['concatenation', 'dynamic_query'],
                'severity': 'HIGH'
            },
            'xss': {
                'indicators': ['innerHTML', 'document.write'],
                'severity': 'MEDIUM'
            }
        }
    
    def _load_vulnerability_trends(self) -> Dict[str, Any]:
        """Load vulnerability trend data"""
        # In production, load from threat intelligence database
        return {
            'increasing': ['supply_chain', 'api_security'],
            'decreasing': ['buffer_overflow'],
            'stable': ['sql_injection', 'xss']
        }
    
    def _find_related_cves(self, threat: Dict) -> List[str]:
        """Find CVEs related to threat"""
        # In production, query CVE database
        # Simulated CVE correlation
        cve_mapping = {
            'prototype_pollution': ['CVE-2022-21824', 'CVE-2021-23555'],
            'dependency_confusion': ['CVE-2021-23406'],
            'sql_injection': ['CVE-2021-42013', 'CVE-2020-15168']
        }
        
        related = []
        for vector in threat.get('attack_vectors', []):
            if vector.lower() in cve_mapping:
                related.extend(cve_mapping[vector.lower()])
        
        return related
    
    def _generate_id(self, prefix: str) -> str:
        """Generate unique ID"""
        timestamp = datetime.utcnow().isoformat()
        hash_input = f"{prefix}:{timestamp}:{np.random.rand()}"
        return f"{prefix}_{hashlib.sha256(hash_input.encode()).hexdigest()[:12]}"
    
    def _store_threat_intelligence(self, threat: ThreatIntelligence):
        """Store threat intelligence in DynamoDB"""
        try:
            self.threat_intel_table.put_item(
                Item={
                    'threat_id': threat.threat_id,
                    'threat_type': threat.threat_type,
                    'threat_name': threat.threat_name,
                    'description': threat.description,
                    'severity': threat.severity,
                    'likelihood': float(threat.likelihood),
                    'attack_vectors': threat.attack_vectors,
                    'affected_technologies': threat.affected_technologies,
                    'indicators_of_compromise': threat.indicators_of_compromise,
                    'mitigation_strategies': threat.mitigation_strategies,
                    'ai_confidence': float(threat.ai_confidence),
                    'discovered_at': threat.discovered_at.isoformat(),
                    'related_cves': threat.related_cves,
                    'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())
                }
            )
        except Exception as e:
            logger.error(f"Failed to store threat intelligence: {e}")
    
    def _store_prediction(self, prediction: VulnerabilityPrediction):
        """Store vulnerability prediction"""
        try:
            self.predictions_table.put_item(
                Item={
                    'prediction_id': prediction.prediction_id,
                    'vulnerability_type': prediction.vulnerability_type,
                    'affected_component': prediction.affected_component,
                    'description': prediction.description,
                    'predicted_severity': prediction.predicted_severity,
                    'likelihood_of_discovery': float(prediction.likelihood_of_discovery),
                    'time_to_exploit': prediction.time_to_exploit,
                    'reasoning': prediction.reasoning,
                    'preventive_measures': prediction.preventive_measures,
                    'code_patterns': prediction.code_patterns,
                    'ai_confidence': float(prediction.ai_confidence),
                    'created_at': datetime.utcnow().isoformat(),
                    'ttl': int((datetime.utcnow() + timedelta(days=180)).timestamp())
                }
            )
        except Exception as e:
            logger.error(f"Failed to store prediction: {e}")