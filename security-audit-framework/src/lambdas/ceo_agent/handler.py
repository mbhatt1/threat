"""
AI-Powered CEO Agent - Orchestrates AI Security Scanning
"""
import os
import sys
import json
import boto3
from datetime import datetime
from typing import Dict, List, Any
import uuid
from pathlib import Path

# Add parent directories to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import AI orchestrator and shared modules
from shared.ai_orchestrator import AISecurityOrchestrator
from shared.strands import StrandsMessage, MessageType
from shared.hashiru import HashiruOptimizer
from shared.business_context import BusinessContextEngine

# AWS clients
stepfunctions = boto3.client('stepfunctions')
dynamodb = boto3.resource('dynamodb')
bedrock_runtime = boto3.client('bedrock-runtime')
s3_client = boto3.client('s3')


class AICEOAgent:
    """AI-powered orchestrator using centralized AI orchestrator for security analysis"""
    
    def __init__(self):
        # Initialize AI components
        self.ai_orchestrator = AISecurityOrchestrator()
        self.business_context = BusinessContextEngine()
        self.hashiru = HashiruOptimizer()
        
        # DynamoDB tables
        self.scan_table = dynamodb.Table(os.environ.get('SCAN_TABLE', 'SecurityScans'))
        self.ai_scans_table = dynamodb.Table(os.environ.get('AI_SCANS_TABLE', 'SecurityAuditAIScans'))
        
        # Configuration
        self.state_machine_arn = os.environ.get('STATE_MACHINE_ARN')
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
        
    async def process_scan_request(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process scan request and orchestrate AI-based security scanning"""
        
        # Extract scan configuration
        repository_url = event.get('repository_url')
        branch = event.get('branch', 'main')
        scan_options = event.get('scan_options', {})
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan record in legacy table for compatibility
        scan_record = {
            'scan_id': scan_id,
            'repository_url': repository_url,
            'branch': branch,
            'status': 'INITIATED',
            'created_at': datetime.utcnow().isoformat(),
            'scan_type': 'BEDROCK_AI_UNIFIED',
            'scan_options': scan_options
        }
        
        # Store in DynamoDB
        self.scan_table.put_item(Item=scan_record)
        
        # Use AI to determine optimal scanning strategy
        scan_strategy = await self._determine_scan_strategy(repository_url, scan_options)
        
        # Determine scan type
        scan_type = 'full'
        if scan_options.get('incremental'):
            scan_type = 'incremental'
        elif scan_options.get('pr_scan'):
            scan_type = 'pr'
        
        # Check if we should use Step Functions or direct orchestration
        if scan_strategy.get('execution_environment') == 'ecs' or scan_strategy.get('large_repository'):
            # Use Step Functions for large scans
            return await self._execute_with_step_functions(
                scan_id, repository_url, branch, scan_strategy, scan_options
            )
        else:
            # Direct orchestration for smaller scans
            return await self._execute_direct_orchestration(
                scan_id, repository_url, branch, scan_type, scan_options
            )
    
    async def _execute_direct_orchestration(self, 
                                          scan_id: str,
                                          repository_url: str,
                                          branch: str,
                                          scan_type: str,
                                          scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scan directly using AI orchestrator"""
        
        # Clone repository to temp directory
        repo_path = f"/tmp/{scan_id}"
        await self._clone_repository(repository_url, branch, repo_path)
        
        try:
            # Use AI orchestrator for scanning
            scan_result = await self.ai_orchestrator.orchestrate_security_scan(
                repository_path=repo_path,
                scan_type=scan_type,
                branch=branch,
                base_branch=scan_options.get('base_branch')
            )
            
            # Update legacy scan table with results
            self.scan_table.update_item(
                Key={'scan_id': scan_id},
                UpdateExpression='SET #st = :status, ai_scan_id = :ai_scan, '
                               'total_findings = :total, critical_findings = :critical, '
                               'business_risk_score = :risk, completed_at = :completed',
                ExpressionAttributeNames={'#st': 'status'},
                ExpressionAttributeValues={
                    ':status': 'COMPLETED',
                    ':ai_scan': scan_result.scan_id,
                    ':total': scan_result.total_findings,
                    ':critical': scan_result.critical_findings,
                    ':risk': scan_result.business_risk_score,
                    ':completed': datetime.utcnow().isoformat()
                }
            )
            
            return {
                'scan_id': scan_id,
                'ai_scan_id': scan_result.scan_id,
                'status': scan_result.scan_status,
                'total_findings': scan_result.total_findings,
                'critical_findings': scan_result.critical_findings,
                'business_risk_score': scan_result.business_risk_score,
                'ai_confidence_score': scan_result.ai_confidence_score,
                'execution_type': 'direct'
            }
            
        except Exception as e:
            # Update scan status on failure
            self.scan_table.update_item(
                Key={'scan_id': scan_id},
                UpdateExpression='SET #st = :status, error_message = :error',
                ExpressionAttributeNames={'#st': 'status'},
                ExpressionAttributeValues={
                    ':status': 'FAILED',
                    ':error': str(e)
                }
            )
            raise
        finally:
            # Cleanup
            import shutil
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
    
    async def _execute_with_step_functions(self,
                                         scan_id: str,
                                         repository_url: str,
                                         branch: str,
                                         scan_strategy: Dict[str, Any],
                                         scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scan using Step Functions for complex workflows"""
        
        # Create Strands message for AI scanner
        strands_message = StrandsMessage(
            message_id=str(uuid.uuid4()),
            scan_id=scan_id,
            message_type=MessageType.REQUEST,
            source='CEO_AI',
            target='BEDROCK_UNIFIED',
            timestamp=datetime.utcnow().isoformat(),
            payload={
                'repository_url': repository_url,
                'branch': branch,
                'commit_hash': scan_options.get('commit_hash'),
                'scan_strategy': scan_strategy,
                'scan_options': scan_options,
                'priority': scan_options.get('priority', 'normal'),
                'use_ai_orchestrator': True  # Flag to use new AI orchestrator
            },
            metadata={
                'triggered_by': scan_options.get('triggered_by', 'manual'),
                'correlation_id': scan_id,
                'ai_features_enabled': True
            }
        )
        
        # Prepare Step Functions input
        step_input = {
            'scan_id': scan_id,
            'strands_message': strands_message.to_dict(),
            'execution_plan': scan_strategy,
            'repository_info': {
                'url': repository_url,
                'branch': branch
            },
            'ai_orchestration': {
                'enabled': True,
                'model': scan_strategy.get('model', 'claude-3-sonnet'),
                'workers': scan_strategy.get('workers', 10)
            }
        }
        
        # Start Step Functions execution
        execution_name = f"scan-{scan_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        response = stepfunctions.start_execution(
            stateMachineArn=self.state_machine_arn,
            name=execution_name,
            input=json.dumps(step_input)
        )
        
        # Update scan record with execution ARN
        self.scan_table.update_item(
            Key={'scan_id': scan_id},
            UpdateExpression='SET execution_arn = :arn, #st = :status',
            ExpressionAttributeNames={'#st': 'status'},
            ExpressionAttributeValues={
                ':arn': response['executionArn'],
                ':status': 'RUNNING'
            }
        )
        
        return {
            'scan_id': scan_id,
            'status': 'INITIATED',
            'execution_arn': response['executionArn'],
            'scan_strategy': scan_strategy,
            'execution_type': 'step_functions'
        }
    
    async def _determine_scan_strategy(self, repository_url: str, scan_options: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI to determine optimal scanning strategy"""
        
        # Use HASHIRU for cost optimization
        hashiru_recommendation = self.hashiru.optimize_scan_plan({
            'repository_url': repository_url,
            'scan_options': scan_options
        })
        
        # Get business context
        business_priority = self.business_context.get_repository_priority(repository_url)
        
        # Determine repository size and complexity using AI
        prompt = f"""Analyze this repository URL and scan options to determine the optimal scanning strategy.

Repository: {repository_url}
Scan Options: {json.dumps(scan_options)}
Business Priority: {business_priority}
Cost Optimization: {json.dumps(hashiru_recommendation)}

Based on the repository type, size, business importance, and requested scan depth, recommend:
1. Which Bedrock model to use (Claude 3 Sonnet for comprehensive, Claude Instant for quick)
2. Parallelization level (1-20 workers)
3. Memory allocation (3GB-30GB)
4. Execution environment (lambda for small, ecs for large)
5. Scan focus areas based on repository type and business context

Consider:
- Critical business assets need deeper analysis
- High-traffic repositories need faster scans
- Cost optimization for low-priority assets

Return a JSON object with the strategy:
{{
    "model": "claude-3-sonnet" or "claude-instant",
    "workers": number,
    "memory_gb": number,
    "execution_environment": "lambda" or "ecs",
    "focus_areas": ["code_security", "dependencies", "infrastructure", "api", "business_logic"],
    "estimated_duration_minutes": number,
    "estimated_cost_usd": number,
    "large_repository": true/false,
    "ai_analysis_depth": "shallow" or "deep",
    "business_impact_multiplier": 1.0-3.0,
    "reasoning": "explanation"
}}"""

        try:
            response = bedrock_runtime.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1024,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.1
                })
            )
            
            response_body = json.loads(response['body'].read())
            ai_response = response_body.get('content', [{}])[0].get('text', '{}')
            
            # Parse AI response
            import re
            json_match = re.search(r'\{[\s\S]*\}', ai_response)
            if json_match:
                strategy = json.loads(json_match.group())
            else:
                strategy = self._default_strategy()
            
            # Merge with HASHIRU recommendations
            strategy['cost_optimization'] = hashiru_recommendation
            
            # Apply business context adjustments
            if business_priority == 'critical':
                strategy['model'] = 'claude-3-sonnet'
                strategy['ai_analysis_depth'] = 'deep'
                strategy['business_impact_multiplier'] = strategy.get('business_impact_multiplier', 1.0) * 1.5
            
            # Add specific configurations based on scan options
            if scan_options.get('deep_scan'):
                strategy['model'] = 'claude-3-sonnet'
                strategy['workers'] = min(strategy.get('workers', 10) * 2, 20)
                strategy['ai_analysis_depth'] = 'deep'
            
            if scan_options.get('quick_scan'):
                strategy['model'] = 'claude-instant'
                strategy['execution_environment'] = 'lambda'
                strategy['ai_analysis_depth'] = 'shallow'
            
            return strategy
            
        except Exception as e:
            print(f"AI strategy determination failed: {str(e)}")
            return self._default_strategy()
    
    def _default_strategy(self) -> Dict[str, Any]:
        """Default scanning strategy"""
        return {
            'model': 'claude-3-sonnet',
            'workers': 10,
            'memory_gb': 10,
            'execution_environment': 'lambda',
            'focus_areas': ['code_security', 'dependencies', 'infrastructure', 'api', 'business_logic'],
            'estimated_duration_minutes': 5,
            'estimated_cost_usd': 0.50,
            'large_repository': False,
            'ai_analysis_depth': 'deep',
            'business_impact_multiplier': 1.0,
            'reasoning': 'Default balanced strategy for unknown repository'
        }
    
    async def _clone_repository(self, repository_url: str, branch: str, target_path: str):
        """Clone repository for scanning"""
        import subprocess
        
        # Create target directory
        os.makedirs(target_path, exist_ok=True)
        
        # Clone repository (simplified - in production use git2 or similar)
        try:
            # For demo purposes, just create some sample files
            sample_files = {
                'app.py': """
import os
import sqlite3

def get_user(user_id):
    # Potential SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect('database.db')
    return conn.execute(query).fetchone()

# Hardcoded secret
API_KEY = "sk-1234567890abcdef"
""",
                'requirements.txt': """
flask==2.0.1
requests==2.25.1
sqlalchemy==1.3.23
""",
                'Dockerfile': """
FROM python:3.8
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
USER root
CMD ["python", "app.py"]
"""
            }
            
            for filename, content in sample_files.items():
                with open(os.path.join(target_path, filename), 'w') as f:
                    f.write(content)
                    
        except Exception as e:
            print(f"Repository clone failed: {e}")
            raise


def handler(event, context):
    """Lambda handler for AI CEO Agent"""
    import asyncio
    
    ceo = AICEOAgent()
    
    # Create event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Handle different event sources
        if 'Records' in event:
            # SNS event
            results = []
            for record in event['Records']:
                message = json.loads(record['Sns']['Message'])
                result = loop.run_until_complete(ceo.process_scan_request(message))
                results.append(result)
            return results
        else:
            # Direct invocation
            return loop.run_until_complete(ceo.process_scan_request(event))
    finally:
        loop.close()