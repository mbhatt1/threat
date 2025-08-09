"""
Business Context and Risk Scoring Engine
"""
import json
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import yaml
import re

class AssetCriticality(Enum):
    """Business criticality levels"""
    CRITICAL = "critical"      # Core business functionality
    HIGH = "high"             # Important features
    MEDIUM = "medium"         # Standard features
    LOW = "low"              # Non-critical features
    
    @property
    def weight(self) -> float:
        """Get numerical weight for criticality"""
        weights = {
            AssetCriticality.CRITICAL: 10.0,
            AssetCriticality.HIGH: 5.0,
            AssetCriticality.MEDIUM: 2.0,
            AssetCriticality.LOW: 1.0
        }
        return weights[self]

@dataclass
class BusinessAsset:
    """Represents a business asset/component"""
    name: str
    type: str  # api, database, auth, payment, etc.
    criticality: AssetCriticality
    data_classification: str  # public, internal, confidential, restricted
    compliance_requirements: List[str] = field(default_factory=list)  # PCI, HIPAA, etc.
    file_patterns: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    threat_model_id: Optional[str] = None

@dataclass
class ThreatScenario:
    """Threat modeling scenario"""
    id: str
    name: str
    description: str
    impact: str  # data_breach, service_disruption, financial_loss
    likelihood: str  # very_likely, likely, possible, unlikely
    mitigations: List[str] = field(default_factory=list)
    assets_affected: List[str] = field(default_factory=list)

@dataclass
class SecurityPolicy:
    """Custom security policy"""
    id: str
    name: str
    description: str
    rules: List[Dict[str, Any]]
    severity_override: Optional[str] = None
    applies_to: List[str] = field(default_factory=list)  # asset names or patterns
    exceptions: List[str] = field(default_factory=list)

class BusinessContextEngine:
    """
    Manages business context, threat modeling, and risk scoring
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        self.assets: Dict[str, BusinessAsset] = {}
        self.threat_scenarios: Dict[str, ThreatScenario] = {}
        self.policies: Dict[str, SecurityPolicy] = {}
        self.asset_map: Dict[str, str] = {}  # file_path -> asset_name mapping
        
        if config_path:
            self.load_configuration(config_path)
    
    def load_configuration(self, config_path: Path):
        """Load business context configuration"""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Load assets
        for asset_config in config.get('assets', []):
            asset = BusinessAsset(
                name=asset_config['name'],
                type=asset_config['type'],
                criticality=AssetCriticality(asset_config['criticality']),
                data_classification=asset_config.get('data_classification', 'internal'),
                compliance_requirements=asset_config.get('compliance', []),
                file_patterns=asset_config.get('file_patterns', []),
                dependencies=asset_config.get('dependencies', []),
                threat_model_id=asset_config.get('threat_model_id')
            )
            self.register_asset(asset)
        
        # Load threat scenarios
        for threat_config in config.get('threat_scenarios', []):
            threat = ThreatScenario(
                id=threat_config['id'],
                name=threat_config['name'],
                description=threat_config['description'],
                impact=threat_config['impact'],
                likelihood=threat_config['likelihood'],
                mitigations=threat_config.get('mitigations', []),
                assets_affected=threat_config.get('assets_affected', [])
            )
            self.register_threat_scenario(threat)
        
        # Load policies
        for policy_config in config.get('policies', []):
            policy = SecurityPolicy(
                id=policy_config['id'],
                name=policy_config['name'],
                description=policy_config['description'],
                rules=policy_config['rules'],
                severity_override=policy_config.get('severity_override'),
                applies_to=policy_config.get('applies_to', []),
                exceptions=policy_config.get('exceptions', [])
            )
            self.register_policy(policy)
    
    def register_asset(self, asset: BusinessAsset):
        """Register a business asset"""
        self.assets[asset.name] = asset
        
        # Update file pattern mapping
        for pattern in asset.file_patterns:
            self.asset_map[pattern] = asset.name
    
    def register_threat_scenario(self, threat: ThreatScenario):
        """Register a threat scenario"""
        self.threat_scenarios[threat.id] = threat
    
    def register_policy(self, policy: SecurityPolicy):
        """Register a security policy"""
        self.policies[policy.id] = policy
    
    def get_asset_for_file(self, file_path: str) -> Optional[BusinessAsset]:
        """Get business asset associated with a file"""
        # Check direct mapping
        for pattern, asset_name in self.asset_map.items():
            if re.match(pattern, file_path):
                return self.assets.get(asset_name)
        
        # Fallback to checking each asset's patterns
        for asset in self.assets.values():
            for pattern in asset.file_patterns:
                if re.match(pattern, file_path):
                    return asset
        
        return None
    
    def calculate_business_risk_score(self, finding: Dict[str, Any]) -> float:
        """
        Calculate risk score with business context
        
        Returns score from 0-100
        """
        base_score = self._get_base_severity_score(finding.get('severity', 'MEDIUM'))
        
        # Get asset context
        asset = self.get_asset_for_file(finding.get('file', ''))
        if not asset:
            return base_score
        
        # Apply criticality multiplier
        criticality_multiplier = asset.criticality.weight / 2.0  # Normalize to reasonable range
        
        # Apply data classification multiplier
        data_multiplier = self._get_data_classification_multiplier(asset.data_classification)
        
        # Apply compliance multiplier
        compliance_multiplier = 1.0
        if asset.compliance_requirements:
            compliance_multiplier = 1.5  # 50% increase for compliance-regulated assets
        
        # Calculate final score
        final_score = base_score * criticality_multiplier * data_multiplier * compliance_multiplier
        
        # Check if finding relates to active threats
        threat_multiplier = self._get_threat_multiplier(finding, asset)
        final_score *= threat_multiplier
        
        # Apply policy overrides
        final_score = self._apply_policy_overrides(finding, asset, final_score)
        
        return min(100.0, final_score)
    
    def _get_base_severity_score(self, severity: str) -> float:
        """Get base score for severity"""
        scores = {
            'CRITICAL': 40.0,
            'HIGH': 30.0,
            'MEDIUM': 20.0,
            'LOW': 10.0,
            'INFO': 5.0
        }
        return scores.get(severity.upper(), 20.0)
    
    def _get_data_classification_multiplier(self, classification: str) -> float:
        """Get multiplier based on data classification"""
        multipliers = {
            'restricted': 2.0,    # Highly sensitive
            'confidential': 1.5,  # Sensitive
            'internal': 1.0,      # Standard
            'public': 0.5         # Low sensitivity
        }
        return multipliers.get(classification.lower(), 1.0)
    
    def _get_threat_multiplier(self, finding: Dict[str, Any], 
                              asset: BusinessAsset) -> float:
        """Get multiplier based on active threats"""
        multiplier = 1.0
        
        for threat_id, threat in self.threat_scenarios.items():
            if asset.name in threat.assets_affected:
                # Check if finding type relates to threat
                if self._finding_relates_to_threat(finding, threat):
                    # Apply likelihood multiplier
                    likelihood_multipliers = {
                        'very_likely': 2.0,
                        'likely': 1.5,
                        'possible': 1.2,
                        'unlikely': 1.0
                    }
                    multiplier = max(multiplier, 
                                   likelihood_multipliers.get(threat.likelihood, 1.0))
        
        return multiplier
    
    def _finding_relates_to_threat(self, finding: Dict[str, Any], 
                                  threat: ThreatScenario) -> bool:
        """Check if finding relates to threat scenario"""
        finding_type = finding.get('type', '').lower()
        threat_desc = threat.description.lower()
        
        # Simple keyword matching - could be enhanced with ML
        threat_keywords = {
            'injection': ['sql', 'command', 'ldap', 'xpath'],
            'authentication': ['auth', 'login', 'session', 'password'],
            'data_exposure': ['secret', 'credential', 'api_key', 'token'],
            'access_control': ['authorization', 'permission', 'rbac']
        }
        
        for category, keywords in threat_keywords.items():
            if any(kw in finding_type for kw in keywords) and category in threat_desc:
                return True
        
        return False
    
    def _apply_policy_overrides(self, finding: Dict[str, Any], 
                               asset: BusinessAsset, 
                               current_score: float) -> float:
        """Apply custom policy overrides to score"""
        for policy in self.policies.values():
            # Check if policy applies to this asset
            if not self._policy_applies_to_asset(policy, asset):
                continue
            
            # Check if finding matches policy rules
            if self._finding_matches_policy(finding, policy):
                # Apply severity override if specified
                if policy.severity_override:
                    override_score = self._get_base_severity_score(policy.severity_override)
                    # Use the higher of current score or override
                    current_score = max(current_score, override_score)
        
        return current_score
    
    def _policy_applies_to_asset(self, policy: SecurityPolicy, 
                                asset: BusinessAsset) -> bool:
        """Check if policy applies to asset"""
        if not policy.applies_to:
            return True  # Applies to all if not specified
        
        for pattern in policy.applies_to:
            if pattern == asset.name or re.match(pattern, asset.name):
                # Check exceptions
                for exception in policy.exceptions:
                    if exception == asset.name or re.match(exception, asset.name):
                        return False
                return True
        
        return False
    
    def _finding_matches_policy(self, finding: Dict[str, Any], 
                               policy: SecurityPolicy) -> bool:
        """Check if finding matches policy rules"""
        for rule in policy.rules:
            matches = True
            for field, pattern in rule.items():
                finding_value = finding.get(field, '')
                if not re.match(pattern, str(finding_value)):
                    matches = False
                    break
            
            if matches:
                return True
        
        return False
    
    def generate_risk_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate risk report with business context"""
        report = {
            'total_findings': len(findings),
            'risk_by_asset': {},
            'risk_by_compliance': {},
            'high_risk_assets': [],
            'compliance_violations': [],
            'threat_exposure': {}
        }
        
        # Group findings by asset
        asset_findings = {}
        for finding in findings:
            asset = self.get_asset_for_file(finding.get('file', ''))
            if asset:
                if asset.name not in asset_findings:
                    asset_findings[asset.name] = []
                asset_findings[asset.name].append(finding)
        
        # Calculate risk by asset
        for asset_name, asset_findings_list in asset_findings.items():
            asset = self.assets[asset_name]
            
            # Calculate aggregate risk
            risk_scores = [
                self.calculate_business_risk_score(f) 
                for f in asset_findings_list
            ]
            
            avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
            max_risk = max(risk_scores) if risk_scores else 0
            
            report['risk_by_asset'][asset_name] = {
                'criticality': asset.criticality.value,
                'findings_count': len(asset_findings_list),
                'average_risk': round(avg_risk, 2),
                'max_risk': round(max_risk, 2),
                'data_classification': asset.data_classification,
                'compliance': asset.compliance_requirements
            }
            
            # Identify high-risk assets
            if max_risk > 70 or (avg_risk > 50 and asset.criticality in 
                                [AssetCriticality.CRITICAL, AssetCriticality.HIGH]):
                report['high_risk_assets'].append({
                    'asset': asset_name,
                    'reason': 'High risk score with critical business function'
                })
            
            # Check compliance violations
            if asset.compliance_requirements:
                for req in asset.compliance_requirements:
                    violations = self._check_compliance_violations(
                        asset_findings_list, req
                    )
                    if violations:
                        report['compliance_violations'].extend(violations)
                        if req not in report['risk_by_compliance']:
                            report['risk_by_compliance'][req] = 0
                        report['risk_by_compliance'][req] += len(violations)
        
        # Analyze threat exposure
        for threat_id, threat in self.threat_scenarios.items():
            exposed_assets = []
            for asset_name in threat.assets_affected:
                if asset_name in asset_findings and asset_findings[asset_name]:
                    exposed_assets.append(asset_name)
            
            if exposed_assets:
                report['threat_exposure'][threat.name] = {
                    'likelihood': threat.likelihood,
                    'impact': threat.impact,
                    'exposed_assets': exposed_assets,
                    'mitigations_needed': threat.mitigations
                }
        
        return report
    
    def _check_compliance_violations(self, findings: List[Dict[str, Any]], 
                                   compliance_req: str) -> List[Dict[str, Any]]:
        """Check for compliance violations"""
        violations = []
        
        # Define compliance rules (simplified)
        compliance_rules = {
            'PCI': {
                'forbidden_types': ['plaintext_card_number', 'weak_encryption'],
                'required_controls': ['encryption', 'access_logging']
            },
            'HIPAA': {
                'forbidden_types': ['unencrypted_phi', 'missing_audit_log'],
                'required_controls': ['encryption', 'access_control', 'audit_trail']
            },
            'GDPR': {
                'forbidden_types': ['personal_data_exposure', 'missing_consent'],
                'required_controls': ['data_minimization', 'right_to_deletion']
            }
        }
        
        rules = compliance_rules.get(compliance_req, {})
        forbidden = rules.get('forbidden_types', [])
        
        for finding in findings:
            finding_type = finding.get('type', '')
            if any(forbidden_type in finding_type for forbidden_type in forbidden):
                violations.append({
                    'compliance': compliance_req,
                    'violation_type': finding_type,
                    'finding': finding,
                    'severity': 'CRITICAL'  # Compliance violations are always critical
                })
        
        return violations