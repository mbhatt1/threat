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
from botocore.exceptions import ClientError
from functools import wraps
import time
import re
from urllib.parse import urlparse

# Add parent directories to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import AI orchestrator and shared modules
from shared.ai_orchestrator import AISecurityOrchestrator
from shared.strands import StrandsMessage, MessageType
from shared.hashiru import ExecutionPlanner
from shared.business_context import BusinessContextEngine

# AWS clients with retry configuration
from botocore.config import Config

retry_config = Config(
    retries={
        'max_attempts': 3,
        'mode': 'adaptive'
    }
)

stepfunctions = boto3.client('stepfunctions', config=retry_config)
dynamodb = boto3.resource('dynamodb', config=retry_config)
bedrock_runtime = boto3.client('bedrock-runtime', config=retry_config)
s3_client = boto3.client('s3', config=retry_config)


def retry_on_exception(max_retries=3, delay=1, backoff=2, exceptions=(Exception,)):
    """
    Decorator to retry function calls with exponential backoff
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retry_count = 0
            current_delay = delay
            
            while retry_count < max_retries:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        raise
                    
                    print(f"Attempt {retry_count} failed: {str(e)}. Retrying in {current_delay} seconds...")
                    time.sleep(current_delay)
                    current_delay *= backoff
                    
            return func(*args, **kwargs)
        return wrapper
    return decorator


class AICEOAgent:
    """AI-powered orchestrator using centralized AI orchestrator for security analysis"""
    
    def __init__(self):
        # Initialize AI components
        self.ai_orchestrator = AISecurityOrchestrator()
        self.business_context = BusinessContextEngine()
        self.hashiru = ExecutionPlanner()
        
        # DynamoDB tables
        self.scan_table = dynamodb.Table(os.environ.get('SCAN_TABLE', 'SecurityScans'))
        self.ai_scans_table = dynamodb.Table(os.environ.get('AI_SCANS_TABLE', 'SecurityAuditAIScans'))
        
        # Configuration
        self.state_machine_arn = os.environ.get('STATE_MACHINE_ARN')
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
        
    @retry_on_exception(max_retries=3, exceptions=(ClientError,))
    async def process_scan_request(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process scan request and orchestrate AI-based security scanning"""
        
        # Validate and sanitize input
        repository_url = self._validate_repository_url(event.get('repository_url'))
        branch = self._validate_branch(event.get('branch', 'main'))
        scan_options = self._validate_scan_options(event.get('scan_options', {}))
        
        if not repository_url:
            raise ValueError("repository_url is required in the event")
        
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
        
        # Store in DynamoDB with retry
        try:
            self.scan_table.put_item(Item=scan_record)
        except ClientError as e:
            print(f"Failed to store scan record: {e}")
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                raise ValueError(f"DynamoDB table {self.scan_table.table_name} not found")
            raise
        
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
    
    def _validate_repository_url(self, url: str) -> str:
        """Validate and sanitize repository URL"""
        if not url:
            return None
            
        # Remove any whitespace
        url = url.strip()
        
        # Parse and validate URL
        try:
            parsed = urlparse(url)
            
            # Only allow HTTPS and SSH protocols
            if parsed.scheme not in ['https', 'ssh', 'git']:
                raise ValueError(f"Invalid repository URL scheme: {parsed.scheme}. Only HTTPS, SSH, and Git protocols are allowed.")
            
            # Validate hostname
            if not parsed.hostname:
                raise ValueError("Invalid repository URL: missing hostname")
            
            # Check for common Git hosting services
            allowed_hosts = [
                'github.com', 'gitlab.com', 'bitbucket.org', 'codecommit',
                'github.enterprise.com', 'gitlab.enterprise.com'
            ]
            
            if not any(host in parsed.hostname for host in allowed_hosts):
                # For private repositories, ensure it's not a local file path
                if parsed.hostname in ['localhost', '127.0.0.1', '::1']:
                    raise ValueError("Local repository URLs are not allowed")
            
            # Validate path - prevent directory traversal
            if parsed.path:
                if '..' in parsed.path or parsed.path.startswith('/etc/') or parsed.path.startswith('/root/'):
                    raise ValueError("Invalid repository path")
                
                # Ensure path matches valid repository pattern
                if not re.match(r'^[/a-zA-Z0-9._\-]+$', parsed.path):
                    raise ValueError("Repository path contains invalid characters")
            
            return url
            
        except Exception as e:
            raise ValueError(f"Invalid repository URL: {str(e)}")
    
    def _validate_branch(self, branch: str) -> str:
        """Validate and sanitize branch name"""
        if not branch:
            return 'main'
            
        # Remove whitespace
        branch = branch.strip()
        
        # Validate branch name format
        if not re.match(r'^[a-zA-Z0-9/_\-\.]+$', branch):
            raise ValueError(f"Invalid branch name: {branch}")
        
        # Prevent special Git references that could be abused
        if branch.startswith('.') or branch in ['HEAD', 'FETCH_HEAD', 'ORIG_HEAD']:
            raise ValueError(f"Invalid branch name: {branch}")
        
        # Limit branch name length
        if len(branch) > 255:
            raise ValueError("Branch name too long (max 255 characters)")
        
        return branch
    
    def _validate_scan_options(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize scan options"""
        if not isinstance(options, dict):
            return {}
        
        validated_options = {}
        
        # Whitelist allowed options
        allowed_options = {
            'incremental': bool,
            'pr_scan': bool,
            'deep_scan': bool,
            'quick_scan': bool,
            'priority': str,
            'commit_hash': str,
            'base_branch': str,
            'triggered_by': str,
            'max_file_size': int,
            'exclude_patterns': list
        }
        
        for key, expected_type in allowed_options.items():
            if key in options:
                value = options[key]
                
                # Type validation
                if not isinstance(value, expected_type):
                    continue
                
                # Additional validation based on option
                if key == 'priority' and value not in ['low', 'normal', 'high', 'critical']:
                    continue
                    
                if key == 'commit_hash' and value:
                    # Validate commit hash format
                    if not re.match(r'^[a-f0-9]{7,40}$', value):
                        continue
                        
                if key == 'base_branch':
                    try:
                        value = self._validate_branch(value)
                    except ValueError:
                        continue
                        
                if key == 'triggered_by' and value not in ['manual', 'webhook', 'schedule', 'api']:
                    value = 'manual'
                    
                if key == 'max_file_size' and (value < 0 or value > 100 * 1024 * 1024):  # Max 100MB
                    value = 10 * 1024 * 1024  # Default 10MB
                    
                if key == 'exclude_patterns' and isinstance(value, list):
                    # Validate patterns
                    validated_patterns = []
                    for pattern in value[:10]:  # Limit to 10 patterns
                        if isinstance(pattern, str) and len(pattern) < 100:
                            # Basic pattern validation
                            if not re.match(r'^[a-zA-Z0-9\*\?\.\-_/]+$', pattern):
                                continue
                            validated_patterns.append(pattern)
                    value = validated_patterns
                
                validated_options[key] = value
        
        return validated_options

    async def _clone_repository(self, repository_url: str, branch: str, target_path: str):
        """Clone repository for scanning"""
        import subprocess
        import shutil
        
        # Create target directory
        os.makedirs(target_path, exist_ok=True)
        
        # Clone repository with security measures
        try:
            # Use Git with security flags
            git_command = [
                'git', 'clone',
                '--depth', '1',  # Shallow clone
                '--single-branch',
                '--branch', branch,
                '--no-tags',  # Don't fetch tags
                repository_url,
                target_path
            ]
            
            # Set security environment variables
            env = os.environ.copy()
            env.update({
                'GIT_TERMINAL_PROMPT': '0',  # Disable password prompts
                'GIT_ASKPASS': '/bin/echo',   # Disable password prompts
                'GIT_SSH_COMMAND': 'ssh -o StrictHostKeyChecking=accept-new'  # Auto-accept new hosts
            })
            
            # Execute with timeout
            result = subprocess.run(
                git_command,
                env=env,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            raise Exception("Repository clone timed out after 5 minutes")
        except Exception as e:
            # Cleanup on failure
            if os.path.exists(target_path):
                shutil.rmtree(target_path)
            raise Exception(f"Repository clone failed: {str(e)}")


def handler(event, context):
    """Lambda handler for AI CEO Agent"""
    import asyncio
    
    ceo = AICEOAgent()
    
    # Create event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Input validation for event structure
        if not isinstance(event, dict):
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid event format'})
            }
        
        # Handle different event sources
        if 'Records' in event:
            # SNS event
            if not isinstance(event.get('Records'), list):
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Invalid Records format'})
                }
                
            results = []
            for record in event['Records'][:10]:  # Process max 10 records
                try:
                    if 'Sns' in record and 'Message' in record['Sns']:
                        message = json.loads(record['Sns']['Message'])
                        result = loop.run_until_complete(ceo.process_scan_request(message))
                        results.append(result)
                except json.JSONDecodeError:
                    results.append({
                        'error': 'Invalid JSON in SNS message',
                        'record': record.get('Sns', {}).get('MessageId', 'unknown')
                    })
                except Exception as e:
                    results.append({
                        'error': f'Processing failed: {str(e)}',
                        'record': record.get('Sns', {}).get('MessageId', 'unknown')
                    })
            return results
        else:
            # Direct invocation
            return loop.run_until_complete(ceo.process_scan_request(event))
            
    except ValueError as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': str(e)})
        }
    except Exception as e:
        print(f"Handler error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Internal server error'})
        }
    finally:
        loop.close()