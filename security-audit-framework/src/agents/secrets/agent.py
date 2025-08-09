#!/usr/bin/env python3
"""
Secrets Detection Agent
Integrated with AI Orchestrator for detecting exposed secrets and credentials
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List

# Add parent directories to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import AI orchestrator and shared components
from shared.ai_orchestrator import AISecurityOrchestrator
from shared.ai_explainability import AIExplainabilityEngine
from shared.business_context import BusinessContextEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecretsAgent:
    """Secrets detection agent using AI orchestrator"""
    
    def __init__(self):
        # Initialize AI components
        self.ai_orchestrator = AISecurityOrchestrator()
        self.explainability = AIExplainabilityEngine()
        self.business_context = BusinessContextEngine()
        
    async def scan(self, repository_path: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform secrets scan using AI orchestrator"""
        scan_id = scan_config.get('scan_id', 'unknown')
        scan_type = scan_config.get('scan_type', 'secrets')
        branch = scan_config.get('branch', 'main')
        
        logger.info(f"Starting secrets scan {scan_id} with AI orchestrator")
        
        try:
            # Configure scan to focus on secrets detection
            scan_config['focus_areas'] = ['secrets', 'credentials', 'api_keys']
            
            # Use AI orchestrator for comprehensive scanning
            scan_result = await self.ai_orchestrator.orchestrate_security_scan(
                repository_path=repository_path,
                scan_type=scan_type,
                branch=branch,
                base_branch=scan_config.get('base_branch')
            )
            
            # Extract secrets-specific findings
            secrets_findings = self._extract_secrets_findings(scan_result)
            
            # Return results
            return {
                'scan_id': scan_id,
                'ai_scan_id': scan_result.scan_id,
                'agent': 'secrets',
                'status': scan_result.scan_status,
                'total_findings': len(secrets_findings),
                'critical_findings': scan_result.critical_findings,
                'high_findings': scan_result.high_findings,
                'business_risk_score': scan_result.business_risk_score,
                'ai_confidence_score': scan_result.ai_confidence_score,
                'secrets_findings': secrets_findings,
                'scan_type': 'SECRETS_AI'
            }
            
        except Exception as e:
            logger.error(f"Secrets scan failed: {e}")
            return {
                'scan_id': scan_id,
                'agent': 'secrets',
                'status': 'failed',
                'error': str(e)
            }
    
    def _extract_secrets_findings(self, scan_result) -> List[Dict[str, Any]]:
        """Extract secrets-specific findings from scan result"""
        secrets_findings = []
        
        # Common secret patterns to look for
        secret_patterns = {
            'api_key': ['api_key', 'apikey', 'api-key', 'access_key', 'accesskey'],
            'private_key': ['private_key', 'privatekey', 'private-key', 'rsa_key', 'ssh_key'],
            'password': ['password', 'passwd', 'pwd', 'pass', 'secret'],
            'token': ['token', 'auth_token', 'access_token', 'bearer_token', 'oauth'],
            'credentials': ['credential', 'creds', 'username', 'user_name'],
            'database': ['db_password', 'database_url', 'connection_string', 'mongodb_uri'],
            'aws': ['aws_access_key', 'aws_secret_key', 'aws_session_token'],
            'github': ['github_token', 'gh_token', 'github_pat'],
            'slack': ['slack_token', 'slack_webhook'],
            'stripe': ['stripe_key', 'stripe_secret'],
            'sendgrid': ['sendgrid_key', 'sendgrid_api'],
            'twilio': ['twilio_sid', 'twilio_auth'],
            'firebase': ['firebase_key', 'firebase_config'],
            'google': ['google_api_key', 'gcp_key', 'service_account']
        }
        
        # Extract findings from scan result
        if hasattr(scan_result, '__dict__'):
            # If it's an AIScanResult object
            scan_dict = scan_result.__dict__
        else:
            # If it's already a dict
            scan_dict = scan_result
        
        # Look for secrets in the findings
        all_findings = scan_dict.get('findings', [])
        
        for finding in all_findings:
            finding_type = finding.get('finding_type', '').lower()
            description = finding.get('description', '').lower()
            file_path = finding.get('file_path', '').lower()
            
            # Check if this finding is related to secrets
            is_secret = False
            detected_secret_type = 'unknown'
            
            # Check finding type
            if any(term in finding_type for term in ['secret', 'credential', 'password', 'token', 'key']):
                is_secret = True
            
            # Check description for secret patterns
            for secret_type, patterns in secret_patterns.items():
                if any(pattern in description for pattern in patterns):
                    is_secret = True
                    detected_secret_type = secret_type
                    break
            
            # Check if file is likely to contain secrets
            secret_file_patterns = ['.env', 'config', 'settings', 'credentials', 'secrets']
            if any(pattern in file_path for pattern in secret_file_patterns):
                is_secret = True
            
            if is_secret:
                secrets_finding = {
                    'finding_id': finding.get('finding_id', ''),
                    'type': 'exposed_secret',
                    'secret_type': detected_secret_type,
                    'severity': finding.get('severity', 'HIGH'),
                    'confidence': finding.get('confidence', 0.8),
                    'file_path': finding.get('file_path', ''),
                    'line_numbers': finding.get('line_numbers', []),
                    'description': finding.get('description', ''),
                    'remediation': finding.get('remediation', 'Remove hardcoded secrets and use secure secret management'),
                    'evidence': finding.get('evidence', []),
                    'business_risk_score': finding.get('business_risk_score', 0.9)
                }
                
                # Enhance remediation based on secret type
                if detected_secret_type == 'api_key':
                    secrets_finding['remediation'] = 'Remove API key from code. Use environment variables or AWS Secrets Manager.'
                elif detected_secret_type == 'password':
                    secrets_finding['remediation'] = 'Remove hardcoded password. Use secure credential storage like AWS SSM Parameter Store.'
                elif detected_secret_type == 'private_key':
                    secrets_finding['remediation'] = 'Remove private key from repository. Use AWS KMS or secure key management service.'
                elif detected_secret_type == 'database':
                    secrets_finding['remediation'] = 'Remove database credentials. Use AWS RDS IAM authentication or Secrets Manager.'
                elif detected_secret_type == 'aws':
                    secrets_finding['remediation'] = 'Remove AWS credentials. Use IAM roles instead of hardcoded keys.'
                
                secrets_findings.append(secrets_finding)
        
        # If no secrets found in regular findings, check for secrets-specific detections
        if not secrets_findings and hasattr(scan_result, 'ai_vulnerabilities'):
            for vuln in scan_result.ai_vulnerabilities:
                if any(term in str(vuln).lower() for term in ['secret', 'credential', 'password', 'token', 'key']):
                    secrets_findings.append({
                        'type': 'exposed_secret',
                        'secret_type': 'detected_by_ai',
                        'severity': 'HIGH',
                        'confidence': 0.85,
                        'description': str(vuln),
                        'remediation': 'Review and remove any hardcoded secrets'
                    })
        
        return secrets_findings


def lambda_handler(event, context):
    """Lambda handler for secrets agent"""
    import asyncio
    
    agent = SecretsAgent()
    
    repository_path = event.get('repository_path', '/mnt/efs/repos/current')
    scan_config = event.get('scan_config', {})
    
    # Run async scan
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        result = loop.run_until_complete(agent.scan(repository_path, scan_config))
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }
    finally:
        loop.close()


if __name__ == "__main__":
    # For testing
    test_event = {
        'repository_path': '/tmp/test-repo',
        'scan_config': {
            'scan_id': 'test-secrets-123',
            'scan_type': 'secrets'
        }
    }
    
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))