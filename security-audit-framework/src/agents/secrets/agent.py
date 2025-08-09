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
        # In a real implementation, this would filter findings
        # For now, return a simplified structure
        return [
            {
                'type': 'exposed_secret',
                'secret_type': 'api_key',
                'severity': 'CRITICAL',
                'description': 'Exposed API key detected'
            }
        ]


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