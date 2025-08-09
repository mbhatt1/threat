"""
AI-Driven Root Cause Analysis
Intelligent incident response with automated root cause identification
"""
import json
import boto3
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from enum import Enum

logger = logging.getLogger(__name__)

# Initialize AWS clients
bedrock = boto3.client('bedrock-runtime')
dynamodb = boto3.resource('dynamodb')
cloudwatch = boto3.client('logs')


class IncidentSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class RootCauseAnalysis:
    """AI-generated root cause analysis"""
    incident_id: str
    root_causes: List[Dict[str, Any]]
    contributing_factors: List[str]
    timeline: List[Dict[str, str]]
    impact_assessment: Dict[str, Any]
    remediation_steps: List[Dict[str, Any]]
    prevention_measures: List[str]
    confidence_score: float
    analysis_reasoning: List[str]
    related_incidents: List[str] = field(default_factory=list)


@dataclass
class IncidentClassification:
    """AI incident classification"""
    incident_type: str
    severity: IncidentSeverity
    attack_category: str  # MITRE ATT&CK category
    threat_actor_profile: Optional[str]
    kill_chain_stage: str
    business_impact: str
    urgency_score: float


class AIRootCauseAnalyzer:
    """
    AI-powered incident response with automated root cause analysis
    """
    
    def __init__(self):
        self.model_id = 'anthropic.claude-3-sonnet-20240229-v1:0'
        
        # DynamoDB tables
        self.incidents_table = dynamodb.Table('SecurityAuditIncidents')
        self.root_cause_table = dynamodb.Table('SecurityAuditRootCause')
        
        # Knowledge base
        self.attack_patterns = self._load_attack_patterns()
        self.incident_templates = self._load_incident_templates()
    
    def analyze_incident(self,
                        incident_data: Dict[str, Any],
                        logs: List[Dict[str, Any]],
                        related_alerts: List[Dict[str, Any]]) -> RootCauseAnalysis:
        """
        Perform AI-driven root cause analysis on security incident
        """
        # Classify the incident first
        classification = self._classify_incident(incident_data, logs)
        
        # Perform deep root cause analysis
        root_cause = self._deep_root_cause_analysis(
            incident_data,
            logs,
            related_alerts,
            classification
        )
        
        # Generate remediation playbook
        remediation = self._generate_remediation_playbook(
            root_cause,
            classification
        )
        
        # Find related incidents
        related = self._find_related_incidents(incident_data, root_cause)
        
        analysis = RootCauseAnalysis(
            incident_id=incident_data.get('incident_id', 'unknown'),
            root_causes=root_cause['root_causes'],
            contributing_factors=root_cause['contributing_factors'],
            timeline=root_cause['timeline'],
            impact_assessment=root_cause['impact_assessment'],
            remediation_steps=remediation['steps'],
            prevention_measures=remediation['prevention'],
            confidence_score=root_cause['confidence'],
            analysis_reasoning=root_cause['reasoning'],
            related_incidents=related
        )
        
        # Store analysis
        self._store_analysis(analysis)
        
        return analysis
    
    def _classify_incident(self,
                         incident_data: Dict[str, Any],
                         logs: List[Dict[str, Any]]) -> IncidentClassification:
        """
        AI-powered incident classification
        """
        prompt = f"""You are a security incident response expert classifying a security incident.

Incident data:
{json.dumps(incident_data, indent=2)}

Recent logs (last 10):
{json.dumps(logs[-10:], indent=2)}

Classify this incident:
1. Determine incident type (data breach, malware, DDoS, insider threat, etc.)
2. Assess severity (CRITICAL, HIGH, MEDIUM, LOW)
3. Map to MITRE ATT&CK framework
4. Profile potential threat actor
5. Identify kill chain stage
6. Assess business impact

Provide classification in JSON format:
{{
  "incident_type": "specific type",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "attack_category": "MITRE ATT&CK category",
  "threat_actor_profile": "profile or null",
  "kill_chain_stage": "reconnaissance|weaponization|delivery|exploitation|installation|command_control|actions_on_objectives",
  "business_impact": "impact description",
  "urgency_score": 0.0-1.0
}}"""

        try:
            response = bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1500,
                    "messages": [{
                        "role": "user",
                        "content": prompt
                    }],
                    "temperature": 0.1
                })
            )
            
            response_body = json.loads(response['body'].read())
            classification_data = json.loads(response_body['content'][0]['text'])
            
            return IncidentClassification(
                incident_type=classification_data['incident_type'],
                severity=IncidentSeverity(classification_data['severity']),
                attack_category=classification_data['attack_category'],
                threat_actor_profile=classification_data.get('threat_actor_profile'),
                kill_chain_stage=classification_data['kill_chain_stage'],
                business_impact=classification_data['business_impact'],
                urgency_score=classification_data['urgency_score']
            )
            
        except Exception as e:
            logger.error(f"Incident classification failed: {e}")
            return self._fallback_classification(incident_data)
    
    def _deep_root_cause_analysis(self,
                                incident_data: Dict[str, Any],
                                logs: List[Dict[str, Any]],
                                related_alerts: List[Dict[str, Any]],
                                classification: IncidentClassification) -> Dict[str, Any]:
        """
        Perform deep AI analysis to find root cause
        """
        prompt = f"""You are a security forensics expert performing root cause analysis.

Incident Classification:
- Type: {classification.incident_type}
- Severity: {classification.severity.value}
- Attack Category: {classification.attack_category}
- Kill Chain Stage: {classification.kill_chain_stage}

Incident Data:
{json.dumps(incident_data, indent=2)}

System Logs (last 50 entries):
{json.dumps(logs[-50:], indent=2)}

Related Security Alerts:
{json.dumps(related_alerts[:10], indent=2)}

Perform deep root cause analysis:
1. Identify the PRIMARY root cause(s)
2. List all contributing factors
3. Reconstruct the attack timeline
4. Assess the full impact
5. Explain your reasoning step by step

Focus on:
- Initial compromise vector
- Privilege escalation methods
- Lateral movement patterns
- Data exfiltration indicators
- Persistence mechanisms

Provide analysis in JSON format:
{{
  "root_causes": [
    {{
      "cause": "specific root cause",
      "evidence": ["evidence1", "evidence2"],
      "confidence": 0.0-1.0,
      "category": "misconfiguration|vulnerability|human_error|malicious_insider|external_attack"
    }}
  ],
  "contributing_factors": ["factor1", "factor2"],
  "timeline": [
    {{
      "timestamp": "ISO timestamp",
      "event": "what happened",
      "significance": "why this matters"
    }}
  ],
  "impact_assessment": {{
    "data_compromised": "description",
    "systems_affected": ["system1", "system2"],
    "business_functions_impacted": ["function1"],
    "estimated_downtime": "duration",
    "regulatory_implications": ["implication1"]
  }},
  "confidence": 0.0-1.0,
  "reasoning": ["step1", "step2", "step3"]
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
            
            return analysis
            
        except Exception as e:
            logger.error(f"Root cause analysis failed: {e}")
            return self._fallback_analysis()
    
    def _generate_remediation_playbook(self,
                                     root_cause: Dict[str, Any],
                                     classification: IncidentClassification) -> Dict[str, Any]:
        """
        Generate AI-powered remediation playbook
        """
        prompt = f"""You are a security incident response expert creating a remediation playbook.

Incident Type: {classification.incident_type}
Severity: {classification.severity.value}

Root Causes Identified:
{json.dumps(root_cause['root_causes'], indent=2)}

Contributing Factors:
{root_cause['contributing_factors']}

Impact Assessment:
{json.dumps(root_cause['impact_assessment'], indent=2)}

Create a detailed remediation playbook:
1. Immediate containment actions
2. Eradication steps
3. Recovery procedures
4. Validation checks
5. Long-term prevention measures

For each step, provide:
- Clear action items
- Required tools/commands
- Success criteria
- Estimated time
- Risk considerations

Provide playbook in JSON format:
{{
  "steps": [
    {{
      "phase": "containment|eradication|recovery|validation",
      "action": "specific action",
      "details": "detailed instructions",
      "tools_required": ["tool1", "tool2"],
      "commands": ["command1", "command2"],
      "success_criteria": "how to verify success",
      "estimated_time": "duration",
      "risks": ["risk1", "risk2"],
      "priority": 1-5
    }}
  ],
  "prevention": [
    "long-term prevention measure 1",
    "long-term prevention measure 2"
  ],
  "monitoring": [
    "what to monitor going forward"
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
            playbook = json.loads(response_body['content'][0]['text'])
            
            # Sort steps by priority
            playbook['steps'] = sorted(
                playbook['steps'],
                key=lambda x: x.get('priority', 5)
            )
            
            return playbook
            
        except Exception as e:
            logger.error(f"Playbook generation failed: {e}")
            return self._fallback_playbook()
    
    def alert_prioritization(self,
                           alerts: List[Dict[str, Any]],
                           context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        AI-powered intelligent alert prioritization
        """
        prompt = f"""You are a SOC analyst prioritizing security alerts using AI.

Current alerts (showing first 20):
{json.dumps(alerts[:20], indent=2)}

Context:
- Current threat landscape: {context.get('threat_level', 'medium')}
- Business criticality: {context.get('business_context', {})}
- Recent incidents: {context.get('recent_incidents', 0)}

Prioritize these alerts based on:
1. True positive likelihood
2. Potential impact
3. Attack chain progression
4. Business criticality
5. Correlation with other alerts

For each alert, assess:
- Is this likely a true positive?
- What's the potential impact?
- Is this part of a larger attack?
- How urgent is the response?

Provide prioritization in JSON format:
{{
  "prioritized_alerts": [
    {{
      "alert_id": "original alert id",
      "priority_score": 0.0-1.0,
      "true_positive_likelihood": 0.0-1.0,
      "potential_impact": "CRITICAL|HIGH|MEDIUM|LOW",
      "attack_chain_indicator": true/false,
      "correlated_alerts": ["alert_id1", "alert_id2"],
      "recommended_action": "investigate|respond|monitor|dismiss",
      "reasoning": "why this priority"
    }}
  ],
  "alert_clusters": [
    {{
      "cluster_name": "related alerts group",
      "alert_ids": ["id1", "id2"],
      "combined_severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "attack_hypothesis": "what might be happening"
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
            prioritization = json.loads(response_body['content'][0]['text'])
            
            # Sort by priority score
            prioritization['prioritized_alerts'] = sorted(
                prioritization['prioritized_alerts'],
                key=lambda x: x['priority_score'],
                reverse=True
            )
            
            return prioritization['prioritized_alerts']
            
        except Exception as e:
            logger.error(f"Alert prioritization failed: {e}")
            return alerts  # Return unprioritized
    
    def _find_related_incidents(self,
                              incident_data: Dict[str, Any],
                              root_cause: Dict[str, Any]) -> List[str]:
        """
        Find historically related incidents using AI
        """
        # In production, would query incident database
        # and use AI to find patterns
        related = []
        
        # Simulate finding related incidents
        for cause in root_cause['root_causes']:
            if cause['category'] == 'vulnerability':
                related.append(f"INC-2023-{hash(cause['cause']) % 1000}")
        
        return related
    
    def _store_analysis(self, analysis: RootCauseAnalysis):
        """Store root cause analysis in DynamoDB"""
        try:
            self.root_cause_table.put_item(
                Item={
                    'incident_id': analysis.incident_id,
                    'root_causes': analysis.root_causes,
                    'contributing_factors': analysis.contributing_factors,
                    'timeline': analysis.timeline,
                    'impact_assessment': analysis.impact_assessment,
                    'remediation_steps': analysis.remediation_steps,
                    'prevention_measures': analysis.prevention_measures,
                    'confidence_score': float(analysis.confidence_score),
                    'analysis_reasoning': analysis.analysis_reasoning,
                    'related_incidents': analysis.related_incidents,
                    'analyzed_at': datetime.utcnow().isoformat(),
                    'ttl': int((datetime.utcnow() + timedelta(days=365)).timestamp())
                }
            )
        except Exception as e:
            logger.error(f"Failed to store analysis: {e}")
    
    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load known attack patterns for analysis"""
        return {
            'lateral_movement': {
                'indicators': ['multiple_auth_failures', 'unusual_access_patterns'],
                'typical_tools': ['mimikatz', 'psexec', 'wmi']
            },
            'data_exfiltration': {
                'indicators': ['large_data_transfers', 'unusual_destinations'],
                'typical_methods': ['dns_tunneling', 'https_post', 'cloud_storage']
            }
        }
    
    def _load_incident_templates(self) -> Dict[str, Any]:
        """Load incident response templates"""
        return {
            'ransomware': {
                'immediate_actions': ['isolate_systems', 'preserve_evidence'],
                'recovery_steps': ['restore_from_backup', 'decrypt_if_possible']
            },
            'data_breach': {
                'immediate_actions': ['contain_breach', 'assess_scope'],
                'recovery_steps': ['patch_vulnerability', 'notify_affected']
            }
        }
    
    def _fallback_classification(self, incident_data: Dict) -> IncidentClassification:
        """Fallback classification if AI fails"""
        return IncidentClassification(
            incident_type='unknown',
            severity=IncidentSeverity.HIGH,
            attack_category='unknown',
            threat_actor_profile=None,
            kill_chain_stage='unknown',
            business_impact='potential security incident',
            urgency_score=0.7
        )
    
    def _fallback_analysis(self) -> Dict[str, Any]:
        """Fallback analysis if AI fails"""
        return {
            'root_causes': [{
                'cause': 'Unable to determine - manual analysis required',
                'evidence': [],
                'confidence': 0.1,
                'category': 'unknown'
            }],
            'contributing_factors': ['AI analysis failed'],
            'timeline': [],
            'impact_assessment': {
                'data_compromised': 'unknown',
                'systems_affected': [],
                'business_functions_impacted': [],
                'estimated_downtime': 'unknown',
                'regulatory_implications': []
            },
            'confidence': 0.1,
            'reasoning': ['AI analysis failed - manual investigation required']
        }
    
    def _fallback_playbook(self) -> Dict[str, Any]:
        """Fallback playbook if AI fails"""
        return {
            'steps': [{
                'phase': 'containment',
                'action': 'Isolate affected systems',
                'details': 'Disconnect from network',
                'tools_required': [],
                'commands': [],
                'success_criteria': 'System isolated',
                'estimated_time': '15 minutes',
                'risks': [],
                'priority': 1
            }],
            'prevention': ['Review security controls'],
            'monitoring': ['Monitor for recurrence']
        }