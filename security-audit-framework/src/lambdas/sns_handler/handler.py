"""
SNS Handler Lambda Function
Processes incoming SNS messages to trigger security scans
"""
import json
import os
import logging
import boto3
from datetime import datetime
from typing import Dict, Any, Optional
import uuid

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
stepfunctions = boto3.client('stepfunctions')
dynamodb = boto3.resource('dynamodb')

# Environment variables
STATE_MACHINE_ARN = os.environ['STATE_MACHINE_ARN']
SCAN_TABLE_NAME = os.environ['SCAN_TABLE_NAME']

class SNSHandler:
    """Handler for processing SNS messages to trigger security scans"""
    
    def __init__(self):
        self.scan_table = dynamodb.Table(SCAN_TABLE_NAME)
        self.supported_message_types = {
            'github_webhook': self._process_github_webhook,
            'codecommit_event': self._process_codecommit_event,
            'scheduled_scan': self._process_scheduled_scan,
            'manual_scan': self._process_manual_scan,
            'security_hub_finding': self._process_security_hub_finding,
            'custom_integration': self._process_custom_integration
        }
    
    def process_sns_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process incoming SNS event"""
        results = []
        
        for record in event.get('Records', []):
            try:
                # Extract SNS message
                sns_message = record['Sns']
                message_id = sns_message.get('MessageId')
                subject = sns_message.get('Subject', 'Security Scan Request')
                
                # Parse message body
                try:
                    message_body = json.loads(sns_message['Message'])
                except json.JSONDecodeError:
                    # Handle plain text messages
                    message_body = {
                        'type': 'manual_scan',
                        'repository_url': sns_message['Message'],
                        'source': 'sns_plain_text'
                    }
                
                # Extract message attributes
                message_attributes = sns_message.get('MessageAttributes', {})
                message_type = self._get_message_type(message_body, message_attributes)
                
                logger.info(f"Processing SNS message {message_id} of type: {message_type}")
                
                # Process based on message type
                if message_type in self.supported_message_types:
                    scan_config = self.supported_message_types[message_type](
                        message_body, 
                        message_attributes
                    )
                else:
                    scan_config = self._process_generic_message(
                        message_body, 
                        message_attributes
                    )
                
                # Add metadata
                scan_config['metadata'] = {
                    'sns_message_id': message_id,
                    'sns_subject': subject,
                    'sns_timestamp': sns_message.get('Timestamp'),
                    'sns_topic_arn': sns_message.get('TopicArn'),
                    'message_type': message_type
                }
                
                # Trigger security scan
                result = self._trigger_scan(scan_config)
                results.append(result)
                
            except Exception as e:
                logger.error(f"Error processing SNS record: {str(e)}")
                results.append({
                    'status': 'error',
                    'error': str(e),
                    'message_id': record.get('Sns', {}).get('MessageId')
                })
        
        return {
            'processed': len(results),
            'results': results
        }
    
    def _get_message_type(self, message_body: Dict[str, Any], 
                         attributes: Dict[str, Any]) -> str:
        """Determine message type from body and attributes"""
        # Check explicit type in message
        if 'type' in message_body:
            return message_body['type']
        
        # Check message attributes
        if 'MessageType' in attributes:
            return attributes['MessageType']['Value']
        
        # Detect based on content
        if 'repository' in message_body and 'ref' in message_body:
            return 'github_webhook'
        elif 'Records' in message_body and any(
            r.get('eventSource') == 'aws:codecommit' for r in message_body.get('Records', [])
        ):
            return 'codecommit_event'
        elif 'schedule' in message_body:
            return 'scheduled_scan'
        
        return 'manual_scan'
    
    def _process_github_webhook(self, message: Dict[str, Any], 
                               attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Process GitHub webhook messages"""
        return {
            'repository_url': message.get('repository', {}).get('clone_url'),
            'branch': message.get('ref', 'refs/heads/main').split('/')[-1],
            'commit_sha': message.get('after'),
            'trigger_source': 'github_webhook',
            'repository_metadata': {
                'name': message.get('repository', {}).get('name'),
                'owner': message.get('repository', {}).get('owner', {}).get('login'),
                'private': message.get('repository', {}).get('private', False),
                'language': message.get('repository', {}).get('language'),
                'pusher': message.get('pusher', {}).get('name')
            },
            'scan_options': self._extract_scan_options(attributes)
        }
    
    def _process_codecommit_event(self, message: Dict[str, Any], 
                                 attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Process AWS CodeCommit events"""
        records = message.get('Records', [])
        if not records:
            raise ValueError("No CodeCommit records found in message")
        
        record = records[0]  # Process first record
        codecommit = record.get('codecommit', {})
        references = codecommit.get('references', [])
        
        if not references:
            raise ValueError("No references found in CodeCommit event")
        
        ref = references[0]
        repository_name = record.get('eventSourceARN', '').split(':')[-1]
        
        return {
            'repository_url': f"codecommit::{repository_name}",
            'branch': ref.get('ref', 'refs/heads/main').split('/')[-1],
            'commit_sha': ref.get('commit'),
            'trigger_source': 'codecommit_event',
            'repository_metadata': {
                'name': repository_name,
                'region': record.get('awsRegion'),
                'account_id': record.get('userIdentityARN', '').split(':')[4]
            },
            'scan_options': self._extract_scan_options(attributes)
        }
    
    def _process_scheduled_scan(self, message: Dict[str, Any], 
                               attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Process scheduled scan requests"""
        return {
            'repository_url': message.get('repository_url'),
            'branch': message.get('branch', 'main'),
            'trigger_source': 'scheduled_scan',
            'schedule': message.get('schedule'),
            'scan_options': {
                **self._extract_scan_options(attributes),
                **message.get('scan_options', {})
            }
        }
    
    def _process_manual_scan(self, message: Dict[str, Any], 
                            attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Process manual scan requests"""
        # Support both structured and simple string formats
        if isinstance(message, str):
            repository_url = message
            scan_options = self._extract_scan_options(attributes)
        else:
            repository_url = message.get('repository_url', message.get('repository'))
            scan_options = {
                **self._extract_scan_options(attributes),
                **message.get('scan_options', {})
            }
        
        return {
            'repository_url': repository_url,
            'branch': message.get('branch', 'main') if isinstance(message, dict) else 'main',
            'trigger_source': 'manual_scan',
            'requester': attributes.get('Requester', {}).get('Value', 'unknown'),
            'scan_options': scan_options
        }
    
    def _process_security_hub_finding(self, message: Dict[str, Any], 
                                     attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Process Security Hub finding events"""
        finding = message.get('finding', message)
        
        # Extract repository information from finding
        resources = finding.get('Resources', [])
        repository_url = None
        
        for resource in resources:
            if 'codecommit' in resource.get('Type', '').lower():
                repository_url = f"codecommit::{resource.get('Id', '').split('/')[-1]}"
                break
            elif resource.get('Type') == 'Other':
                # Check for repository URL in details
                details = resource.get('Details', {})
                if 'repository' in details:
                    repository_url = details['repository']
        
        if not repository_url:
            raise ValueError("No repository information found in Security Hub finding")
        
        return {
            'repository_url': repository_url,
            'trigger_source': 'security_hub_finding',
            'finding_id': finding.get('Id'),
            'finding_severity': finding.get('Severity', {}).get('Label'),
            'scan_options': {
                **self._extract_scan_options(attributes),
                'deep_scan': True,  # Security Hub findings trigger deep scans
                'priority': 'high'
            }
        }
    
    def _process_custom_integration(self, message: Dict[str, Any], 
                                   attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Process custom integration messages"""
        return {
            'repository_url': message.get('repository_url'),
            'branch': message.get('branch', 'main'),
            'trigger_source': 'custom_integration',
            'integration_name': message.get('integration_name', 'unknown'),
            'custom_data': message.get('custom_data', {}),
            'scan_options': {
                **self._extract_scan_options(attributes),
                **message.get('scan_options', {})
            }
        }
    
    def _process_generic_message(self, message: Dict[str, Any], 
                                attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Process generic messages"""
        return {
            'repository_url': message.get('repository_url', message.get('repository')),
            'branch': message.get('branch', 'main'),
            'trigger_source': 'generic_sns',
            'scan_options': {
                **self._extract_scan_options(attributes),
                **message.get('scan_options', {})
            }
        }
    
    def _extract_scan_options(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Extract scan options from SNS message attributes"""
        options = {}
        
        # Map of attribute names to option keys
        attribute_mapping = {
            'DeepScan': 'deep_scan',
            'Priority': 'priority',
            'CostLimit': 'cost_limit',
            'Agents': 'specific_agents',
            'SkipAgents': 'skip_agents',
            'NotificationEmail': 'notification_email',
            'Tags': 'tags'
        }
        
        for attr_name, option_key in attribute_mapping.items():
            if attr_name in attributes:
                value = attributes[attr_name].get('Value')
                
                # Convert string booleans
                if value.lower() in ['true', 'false']:
                    value = value.lower() == 'true'
                # Convert numeric values
                elif option_key == 'cost_limit':
                    try:
                        value = float(value)
                    except ValueError:
                        pass
                # Convert comma-separated lists
                elif option_key in ['specific_agents', 'skip_agents', 'tags']:
                    value = [v.strip() for v in value.split(',')]
                
                options[option_key] = value
        
        return options
    
    def _trigger_scan(self, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger security scan via Step Functions"""
        scan_id = str(uuid.uuid4())
        
        # Prepare input for state machine
        state_machine_input = {
            'scan_id': scan_id,
            'repository_url': scan_config['repository_url'],
            'branch': scan_config.get('branch', 'main'),
            'trigger_source': scan_config.get('trigger_source', 'sns'),
            'scan_options': scan_config.get('scan_options', {}),
            'metadata': scan_config.get('metadata', {}),
            'repository_metadata': scan_config.get('repository_metadata', {}),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Record scan request in DynamoDB
        self.scan_table.put_item(
            Item={
                'scan_id': scan_id,
                'status': 'INITIATED',
                'trigger_source': scan_config.get('trigger_source', 'sns'),
                'repository_url': scan_config['repository_url'],
                'branch': scan_config.get('branch', 'main'),
                'created_at': datetime.utcnow().isoformat(),
                'metadata': scan_config.get('metadata', {}),
                'scan_options': scan_config.get('scan_options', {})
            }
        )
        
        # Start Step Functions execution
        try:
            response = stepfunctions.start_execution(
                stateMachineArn=STATE_MACHINE_ARN,
                name=f"scan-{scan_id}",
                input=json.dumps(state_machine_input)
            )
            
            logger.info(f"Started scan {scan_id} with execution ARN: {response['executionArn']}")
            
            return {
                'status': 'success',
                'scan_id': scan_id,
                'execution_arn': response['executionArn'],
                'repository_url': scan_config['repository_url']
            }
            
        except Exception as e:
            logger.error(f"Failed to start scan execution: {str(e)}")
            
            # Update scan status
            self.scan_table.update_item(
                Key={'scan_id': scan_id},
                UpdateExpression='SET #status = :status, error = :error',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': 'FAILED',
                    ':error': str(e)
                }
            )
            
            raise


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler function"""
    handler = SNSHandler()
    
    try:
        result = handler.process_sns_event(event)
        
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }
        
    except Exception as e:
        logger.error(f"Error processing SNS event: {str(e)}")
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'message': 'Failed to process SNS event'
            })
        }