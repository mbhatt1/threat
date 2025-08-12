"""
Business Context Engine - Maps technical vulnerabilities to business impact
"""
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import boto3


class BusinessContextEngine:
    """
    Maps technical security findings to business risk and impact
    Provides context-aware risk scoring
    """
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.context_table = 'security-business-context'
        
        # Default business context mappings
        self.asset_criticality = {
            'payment': 'critical',
            'auth': 'critical',
            'user_data': 'high',
            'admin': 'critical',
            'public': 'low',
            'internal': 'medium'
        }
        
        self.data_sensitivity = {
            'pii': 'high',
            'financial': 'critical',
            'healthcare': 'critical',
            'public': 'low',
            'internal': 'medium'
        }
    
    def calculate_business_risk(self, findings: List[Dict[str, Any]], 
                               repository_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate business risk score based on findings and context
        
        Args:
            findings: List of security findings
            repository_metadata: Metadata about the repository
            
        Returns:
            Business risk assessment
        """
        risk_assessment = {
            'overall_risk_score': 0.0,
            'risk_level': 'low',
            'business_impact': [],
            'compliance_risks': [],
            'financial_impact_estimate': 0.0,
            'recommendations': []
        }
        
        if not findings:
            return risk_assessment
        
        # Calculate weighted risk score
        total_score = 0.0
        weights = {
            'critical': 10.0,
            'high': 5.0,
            'medium': 2.0,
            'low': 0.5
        }
        
        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            base_score = weights.get(severity, 0.5)
            
            # Apply business context multipliers
            multiplier = self._get_context_multiplier(finding, repository_metadata)
            total_score += base_score * multiplier
        
        # Normalize score to 0-100
        risk_assessment['overall_risk_score'] = min(total_score, 100.0)
        
        # Determine risk level
        if risk_assessment['overall_risk_score'] >= 80:
            risk_assessment['risk_level'] = 'critical'
        elif risk_assessment['overall_risk_score'] >= 60:
            risk_assessment['risk_level'] = 'high'
        elif risk_assessment['overall_risk_score'] >= 40:
            risk_assessment['risk_level'] = 'medium'
        else:
            risk_assessment['risk_level'] = 'low'
        
        # Generate business impact statements
        risk_assessment['business_impact'] = self._generate_impact_statements(
            findings, repository_metadata
        )
        
        # Check compliance risks
        risk_assessment['compliance_risks'] = self._check_compliance_risks(findings)
        
        # Estimate financial impact
        risk_assessment['financial_impact_estimate'] = self._estimate_financial_impact(
            findings, risk_assessment['compliance_risks']
        )
        
        # Generate recommendations
        risk_assessment['recommendations'] = self._generate_recommendations(
            findings, risk_assessment
        )
        
        return risk_assessment
    
    def _get_context_multiplier(self, finding: Dict[str, Any], 
                               metadata: Dict[str, Any]) -> float:
        """Calculate context-based risk multiplier"""
        multiplier = 1.0
        
        # Check if affects critical assets
        file_path = finding.get('file_path', '').lower()
        for asset_type, criticality in self.asset_criticality.items():
            if asset_type in file_path:
                if criticality == 'critical':
                    multiplier *= 2.0
                elif criticality == 'high':
                    multiplier *= 1.5
                break
        
        # Check data sensitivity
        if finding.get('type') == 'data_exposure':
            for data_type, sensitivity in self.data_sensitivity.items():
                if data_type in str(finding.get('details', '')).lower():
                    if sensitivity == 'critical':
                        multiplier *= 2.5
                    elif sensitivity == 'high':
                        multiplier *= 1.8
                    break
        
        # Production environment multiplier
        if metadata.get('environment') == 'production':
            multiplier *= 1.5
        
        return multiplier
    
    def _generate_impact_statements(self, findings: List[Dict[str, Any]], 
                                   metadata: Dict[str, Any]) -> List[str]:
        """Generate business-readable impact statements"""
        impacts = []
        
        # Group findings by type
        finding_types = {}
        for finding in findings:
            ftype = finding.get('type', 'unknown')
            if ftype not in finding_types:
                finding_types[ftype] = 0
            finding_types[ftype] += 1
        
        # Generate impact statements
        if 'sql_injection' in finding_types:
            impacts.append(
                f"Database compromise risk: {finding_types['sql_injection']} SQL injection "
                f"vulnerabilities could lead to data theft or manipulation"
            )
        
        if 'authentication_bypass' in finding_types:
            impacts.append(
                "Authentication vulnerabilities could allow unauthorized access to user accounts"
            )
        
        if 'data_exposure' in finding_types:
            impacts.append(
                "Sensitive data exposure could result in regulatory fines and reputation damage"
            )
        
        if 'dependency_vulnerability' in finding_types:
            count = finding_types['dependency_vulnerability']
            impacts.append(
                f"{count} vulnerable dependencies increase supply chain attack risk"
            )
        
        return impacts
    
    def _check_compliance_risks(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Check for compliance-related risks"""
        compliance_risks = []
        
        # Check for PII exposure (GDPR, CCPA)
        pii_findings = [f for f in findings if 'pii' in str(f).lower()]
        if pii_findings:
            compliance_risks.append("GDPR/CCPA: Personal data exposure risk")
        
        # Check for payment data (PCI DSS)
        payment_findings = [f for f in findings if 'payment' in str(f).lower() 
                           or 'credit' in str(f).lower()]
        if payment_findings:
            compliance_risks.append("PCI DSS: Payment card data at risk")
        
        # Check for healthcare data (HIPAA)
        health_findings = [f for f in findings if 'health' in str(f).lower() 
                          or 'medical' in str(f).lower()]
        if health_findings:
            compliance_risks.append("HIPAA: Protected health information exposure")
        
        return compliance_risks
    
    def _estimate_financial_impact(self, findings: List[Dict[str, Any]], 
                                  compliance_risks: List[str]) -> float:
        """Estimate potential financial impact"""
        impact = 0.0
        
        # Base impact per finding severity
        severity_costs = {
            'critical': 50000,
            'high': 20000,
            'medium': 5000,
            'low': 1000
        }
        
        for finding in findings:
            severity = finding.get('severity', 'low').lower()
            impact += severity_costs.get(severity, 1000)
        
        # Add compliance penalties
        if 'GDPR' in str(compliance_risks):
            impact += 100000  # Potential GDPR fine
        if 'PCI DSS' in str(compliance_risks):
            impact += 50000   # PCI compliance violation
        if 'HIPAA' in str(compliance_risks):
            impact += 75000   # HIPAA violation
        
        return impact
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]], 
                                 risk_assessment: Dict[str, Any]) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        if risk_assessment['risk_level'] in ['critical', 'high']:
            recommendations.append(
                "IMMEDIATE ACTION REQUIRED: Address critical vulnerabilities within 24-48 hours"
            )
        
        # Count critical findings
        critical_count = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
        if critical_count > 0:
            recommendations.append(
                f"Fix {critical_count} critical vulnerabilities before next deployment"
            )
        
        # Supply chain recommendations
        dep_findings = [f for f in findings if f.get('type') == 'dependency_vulnerability']
        if dep_findings:
            recommendations.append(
                "Update vulnerable dependencies and implement dependency scanning in CI/CD"
            )
        
        # Compliance recommendations
        if risk_assessment['compliance_risks']:
            recommendations.append(
                "Conduct compliance review and implement data protection controls"
            )
        
        return recommendations