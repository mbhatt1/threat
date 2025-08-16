"""
SNS Handler Lambda - Processes SNS messages for the security audit framework
"""
import os
import json
import boto3
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
import hashlib

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
lambda_client = boto3.client('lambda')
stepfunctions = boto3.client('stepfunctions')
dynamodb = boto3.resource('dynamodb')
sqs_client = boto3.client('sqs')

# Environment variables
STATE_MACHINE_ARN = os.environ.get('STATE_MACHINE_ARN')
CEO_AGENT_LAMBDA = os.environ.get('CEO_AGENT_LAMBDA_ARN')
AI_SECURITY_ANALYZER_LAMBDA = os.environ.get('AI_SECURITY_ANALYZER_LAMBDA_ARN')
SCAN_TABLE = os.environ.get('SCAN_TABLE', 'SecurityScans')
NOTIFICATION_TABLE = os.environ.get('NOTIFICATION_TABLE', 'SecurityNotifications')
DLQ_URL = os.environ.get('DLQ_URL')


class SNSMessageHandler:
    """Handles different types of SNS messages"""
    
    def __init__(self):
        self.scan_table = dynamodb.Table(SCAN_TABLE)
        if NOTIFICATION_TABLE:
            self.notification_table = dynamodb.Table(NOTIFICATION_TABLE)
        else:
            self.notification_table = None
            
        self.message_handlers = {
            'scan_request': self._handle_scan_request,
            'webhook': self._handle_webhook,
            'alert': self._handle_alert,
            'status_update': self._handle_status_update,
            'integration': self._handle_integration,
            'scheduled_scan': self._handle_scheduled_scan,
            'manual_trigger': self._handle_manual_trigger,
            'ai_security_analysis': self._handle_ai_security_analysis,
            'hephaestus_analysis': self._handle_hephaestus_analysis
        }
    
    def process_sns_message(self, sns_message: Dict[str, Any]) -> Dict[str, Any]:
        """Process incoming SNS message"""
        
        message_id = sns_message.get('MessageId', 'unknown')
        subject = sns_message.get('Subject', '')
        message_body = sns_message.get('Message', '{}')
        timestamp = sns_message.get('Timestamp', datetime.utcnow().isoformat())
        
        # Log message receipt
        logger.info(f"Processing SNS message: {message_id}, Subject: {subject}")
        
        try:
            # Parse message body
            if isinstance(message_body, str):
                try:
                    message_data = json.loads(message_body)
                except json.JSONDecodeError:
                    # Plain text message
                    message_data = {'text': message_body}
            else:
                message_data = message_body
            
            # Determine message type
            message_type = self._determine_message_type(subject, message_data)
            
            # Store notification record
            if self.notification_table:
                self._store_notification(message_id, message_type, message_data, timestamp)
            
            # Get appropriate handler
            handler = self.message_handlers.get(
                message_type,
                self._handle_unknown_message
            )
            
            # Process message
            result = handler(message_data, sns_message)
            
            return {
                'statusCode': 200,
                'message_id': message_id,
                'message_type': message_type,
                'processed': True,
                'result': result
            }
            
        except Exception as e:
            logger.error(f"Failed to process SNS message: {e}", exc_info=True)
            
            # Send to DLQ if configured
            if DLQ_URL:
                self._send_to_dlq(sns_message, str(e))
            
            return {
                'statusCode': 500,
                'message_id': message_id,
                'error': str(e)
            }
    
    def _determine_message_type(self, subject: str, message_data: Dict) -> str:
        """Determine the type of SNS message"""
        
        # Check subject first
        subject_lower = subject.lower()
        if 'scan' in subject_lower and 'request' in subject_lower:
            return 'scan_request'
        elif 'webhook' in subject_lower:
            return 'webhook'
        elif 'alert' in subject_lower:
            return 'alert'
        elif 'status' in subject_lower:
            return 'status_update'
        elif 'scheduled' in subject_lower:
            return 'scheduled_scan'
        
        # Check message content
        if 'action' in message_data:
            action = message_data['action']
            if action in self.message_handlers:
                return action
        
        if 'repository_url' in message_data:
            return 'scan_request'
        
        if 'webhook_type' in message_data:
            return 'webhook'
        
        if 'alert_type' in message_data:
            return 'alert'
        
        return 'unknown'
    
    def _handle_scan_request(self, message_data: Dict, sns_message: Dict) -> Dict[str, Any]:
        """Handle security scan request"""
        
        repository_url = message_data.get('repository_url')
        if not repository_url:
            raise ValueError("repository_url is required for scan requests")
        
        # Extract scan configuration
        scan_config = {
            'repository_url': repository_url,
            'branch': message_data.get('branch', 'main'),
            'scan_options': message_data.get('scan_options', {}),
            'triggered_by': message_data.get('triggered_by', 'sns'),
            'priority': message_data.get('priority', 'normal')
        }
        
        # Add metadata
        scan_config['scan_options']['sns_message_id'] = sns_message.get('MessageId')
        scan_config['scan_options']['sns_timestamp'] = sns_message.get('Timestamp')
        
        # Trigger scan
        if CEO_AGENT_LAMBDA:
            # Direct Lambda invocation
            response = lambda_client.invoke(
                FunctionName=CEO_AGENT_LAMBDA,
                InvocationType='Event',  # Async
                Payload=json.dumps(scan_config)
            )
            
            return {
                'action': 'scan_triggered',
                'method': 'lambda',
                'status_code': response['StatusCode']
            }
            
        elif STATE_MACHINE_ARN:
            # Step Functions execution
            execution_name = f"sns-scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{hashlib.md5(repository_url.encode()).hexdigest()[:8]}"
            
            response = stepfunctions.start_execution(
                stateMachineArn=STATE_MACHINE_ARN,
                name=execution_name,
                input=json.dumps(scan_config)
            )
            
            return {
                'action': 'scan_triggered',
                'method': 'step_functions',
                'execution_arn': response['executionArn']
            }
        else:
            raise ValueError("No execution method configured (CEO_AGENT_LAMBDA or STATE_MACHINE_ARN)")
    
    def _handle_webhook(self, message_data: Dict, sns_message: Dict) -> Dict[str, Any]:
        """Handle webhook notifications (GitHub, GitLab, etc.)"""
        
        webhook_type = message_data.get('webhook_type', 'unknown')
        
        if webhook_type == 'github':
            return self._handle_github_webhook(message_data)
        elif webhook_type == 'gitlab':
            return self._handle_gitlab_webhook(message_data)
        elif webhook_type == 'bitbucket':
            return self._handle_bitbucket_webhook(message_data)
        else:
            logger.warning(f"Unknown webhook type: {webhook_type}")
            return {'action': 'ignored', 'reason': 'unknown_webhook_type'}
    
    def _handle_github_webhook(self, webhook_data: Dict) -> Dict[str, Any]:
        """Handle GitHub webhook"""
        
        event_type = webhook_data.get('event_type', '')
        repository = webhook_data.get('repository', {})
        
        # Handle different GitHub events
        if event_type == 'push':
            # Trigger scan on push
            branch = webhook_data.get('ref', '').replace('refs/heads/', '')
            if branch in ['main', 'master', 'develop']:
                scan_config = {
                    'repository_url': repository.get('clone_url'),
                    'branch': branch,
                    'scan_options': {
                        'triggered_by': 'github_push',
                        'commit_sha': webhook_data.get('after'),
                        'pusher': webhook_data.get('pusher', {}).get('name')
                    }
                }
                return self._handle_scan_request(scan_config, {})
                
        elif event_type == 'pull_request':
            # Handle PR events
            pr = webhook_data.get('pull_request', {})
            action = webhook_data.get('action', '')
            
            if action in ['opened', 'synchronize']:
                scan_config = {
                    'repository_url': repository.get('clone_url'),
                    'branch': pr.get('head', {}).get('ref'),
                    'scan_options': {
                        'triggered_by': 'github_pr',
                        'pr_number': pr.get('number'),
                        'pr_title': pr.get('title'),
                        'base_branch': pr.get('base', {}).get('ref'),
                        'pr_scan': True
                    }
                }
                return self._handle_scan_request(scan_config, {})
        
        elif event_type == 'security_advisory':
            # Handle security advisories
            return {
                'action': 'security_advisory_received',
                'severity': webhook_data.get('security_advisory', {}).get('severity'),
                'stored': True
            }
        
        return {'action': 'ignored', 'reason': f'unhandled_github_event: {event_type}'}
    
    def _handle_gitlab_webhook(self, webhook_data: Dict) -> Dict[str, Any]:
        """Handle GitLab webhook"""
        
        event_type = webhook_data.get('object_kind', '')
        
        if event_type == 'push':
            project = webhook_data.get('project', {})
            scan_config = {
                'repository_url': project.get('git_http_url'),
                'branch': webhook_data.get('ref', '').replace('refs/heads/', ''),
                'scan_options': {
                    'triggered_by': 'gitlab_push',
                    'commit_sha': webhook_data.get('after'),
                    'user_name': webhook_data.get('user_name')
                }
            }
            return self._handle_scan_request(scan_config, {})
            
        elif event_type == 'merge_request':
            mr = webhook_data.get('merge_request', {})
            if webhook_data.get('action') in ['open', 'update']:
                scan_config = {
                    'repository_url': mr.get('source', {}).get('git_http_url'),
                    'branch': mr.get('source_branch'),
                    'scan_options': {
                        'triggered_by': 'gitlab_mr',
                        'mr_id': mr.get('iid'),
                        'mr_title': mr.get('title'),
                        'target_branch': mr.get('target_branch'),
                        'pr_scan': True
                    }
                }
                return self._handle_scan_request(scan_config, {})
        
        return {'action': 'ignored', 'reason': f'unhandled_gitlab_event: {event_type}'}
    
    def _handle_bitbucket_webhook(self, webhook_data: Dict) -> Dict[str, Any]:
        """Handle Bitbucket webhook"""
        
        event_key = webhook_data.get('eventKey', '')
        
        if event_key == 'repo:push':
            repository = webhook_data.get('repository', {})
            changes = webhook_data.get('changes', [])
            
            if changes:
                change = changes[0]
                scan_config = {
                    'repository_url': repository.get('links', {}).get('clone', [{}])[0].get('href'),
                    'branch': change.get('ref', {}).get('displayId'),
                    'scan_options': {
                        'triggered_by': 'bitbucket_push',
                        'commit_sha': change.get('toHash'),
                        'author': webhook_data.get('actor', {}).get('displayName')
                    }
                }
                return self._handle_scan_request(scan_config, {})
                
        elif event_key == 'pr:opened' or event_key == 'pr:modified':
            pr = webhook_data.get('pullRequest', {})
            scan_config = {
                'repository_url': pr.get('fromRef', {}).get('repository', {}).get('links', {}).get('clone', [{}])[0].get('href'),
                'branch': pr.get('fromRef', {}).get('displayId'),
                'scan_options': {
                    'triggered_by': 'bitbucket_pr',
                    'pr_id': pr.get('id'),
                    'pr_title': pr.get('title'),
                    'target_branch': pr.get('toRef', {}).get('displayId'),
                    'pr_scan': True
                }
            }
            return self._handle_scan_request(scan_config, {})
        
        return {'action': 'ignored', 'reason': f'unhandled_bitbucket_event: {event_key}'}
    
    def _handle_alert(self, message_data: Dict, sns_message: Dict) -> Dict[str, Any]:
        """Handle security alerts"""
        
        alert_type = message_data.get('alert_type', 'unknown')
        severity = message_data.get('severity', 'medium')
        
        # Store alert
        alert_record = {
            'alert_id': f"alert-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{hashlib.md5(json.dumps(message_data).encode()).hexdigest()[:8]}",
            'alert_type': alert_type,
            'severity': severity,
            'timestamp': datetime.utcnow().isoformat(),
            'message': message_data.get('message', ''),
            'source': message_data.get('source', 'sns'),
            'metadata': message_data.get('metadata', {})
        }
        
        # Route based on severity
        if severity == 'critical':
            # Trigger immediate action
            if 'scan_id' in message_data:
                # Trigger remediation
                logger.info(f"Critical alert for scan {message_data['scan_id']}")
            
            # Send to security team
            self._notify_security_team(alert_record)
        
        return {
            'action': 'alert_processed',
            'alert_id': alert_record['alert_id'],
            'severity': severity
        }
    
    def _handle_status_update(self, message_data: Dict, sns_message: Dict) -> Dict[str, Any]:
        """Handle scan status updates"""
        
        scan_id = message_data.get('scan_id')
        status = message_data.get('status')
        
        if not scan_id or not status:
            return {'action': 'ignored', 'reason': 'missing_required_fields'}
        
        # Update scan status in DynamoDB
        try:
            self.scan_table.update_item(
                Key={'scan_id': scan_id},
                UpdateExpression='SET #st = :status, last_updated = :timestamp',
                ExpressionAttributeNames={'#st': 'status'},
                ExpressionAttributeValues={
                    ':status': status,
                    ':timestamp': datetime.utcnow().isoformat()
                }
            )
            
            # Handle specific status transitions
            if status == 'COMPLETED':
                self._handle_scan_completion(scan_id, message_data)
            elif status == 'FAILED':
                self._handle_scan_failure(scan_id, message_data)
            
            return {
                'action': 'status_updated',
                'scan_id': scan_id,
                'status': status
            }
            
        except Exception as e:
            logger.error(f"Failed to update scan status: {e}")
            return {'action': 'failed', 'error': str(e)}
    
    def _handle_integration(self, message_data: Dict, sns_message: Dict) -> Dict[str, Any]:
        """Handle third-party integration messages"""
        
        integration_type = message_data.get('integration_type', 'unknown')
        
        integrations = {
            'jira': self._handle_jira_integration,
            'slack': self._handle_slack_integration,
            'pagerduty': self._handle_pagerduty_integration,
            'servicenow': self._handle_servicenow_integration
        }
        
        handler = integrations.get(integration_type)
        if handler:
            return handler(message_data)
        
        return {'action': 'ignored', 'reason': f'unknown_integration: {integration_type}'}
    
    def _handle_scheduled_scan(self, message_data: Dict, sns_message: Dict) -> Dict[str, Any]:
        """Handle scheduled scan triggers"""
        
        schedule_name = message_data.get('schedule_name', 'unknown')
        repositories = message_data.get('repositories', [])
        
        triggered_scans = []
        
        for repo in repositories:
            if isinstance(repo, str):
                repo_config = {'repository_url': repo}
            else:
                repo_config = repo
            
            repo_config['scan_options'] = repo_config.get('scan_options', {})
            repo_config['scan_options']['triggered_by'] = f'schedule:{schedule_name}'
            repo_config['scan_options']['scheduled_scan'] = True
            
            try:
                result = self._handle_scan_request(repo_config, {})
                triggered_scans.append({
                    'repository': repo_config['repository_url'],
                    'status': 'triggered',
                    'result': result
                })
            except Exception as e:
                triggered_scans.append({
                    'repository': repo_config['repository_url'],
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {
            'action': 'scheduled_scans_triggered',
            'schedule_name': schedule_name,
            'total_repositories': len(repositories),
            'triggered': len([s for s in triggered_scans if s['status'] == 'triggered']),
            'scans': triggered_scans
        }
    
    def _handle_manual_trigger(self, message_data: Dict, sns_message: Dict) -> Dict[str, Any]:
        """Handle manual scan triggers"""
        
        user = message_data.get('user', 'unknown')
        reason = message_data.get('reason', 'manual trigger')
        
        # Add user information to scan options
        message_data['scan_options'] = message_data.get('scan_options', {})
        message_data['scan_options']['triggered_by'] = f'manual:{user}'
        message_data['scan_options']['trigger_reason'] = reason
        
        return self._handle_scan_request(message_data, sns_message)
    
    def _handle_ai_security_analysis(self, message_data: Dict, sns_message: Dict) -> Dict[str, Any]:
        """Handle AI security analysis requests"""
        
        if not AI_SECURITY_ANALYZER_LAMBDA:
            raise ValueError("AI_SECURITY_ANALYZER_LAMBDA_ARN not configured")
        
        # Extract analysis configuration
        analysis_config = {
            'action': message_data.get('action', 'analyze_sql'),
            'payload': message_data.get('payload', {}),
            'triggered_by': 'sns',
            'sns_message_id': sns_message.get('MessageId')
        }
        
        # Invoke AI Security Analyzer Lambda
        response = lambda_client.invoke(
            FunctionName=AI_SECURITY_ANALYZER_LAMBDA,
            InvocationType='Event',  # Async
            Payload=json.dumps(analysis_config)
        )
        
        return {
            'action': 'ai_analysis_triggered',
            'status_code': response['StatusCode'],
            'analysis_type': analysis_config['action']
        }
    
    def _handle_hephaestus_analysis(self, message_data: Dict, sns_message: Dict) -> Dict[str, Any]:
        """Handle Hephaestus cognitive vulnerability analysis requests"""
        
        if not AI_SECURITY_ANALYZER_LAMBDA:
            raise ValueError("AI_SECURITY_ANALYZER_LAMBDA_ARN not configured")
        
        # Extract Hephaestus configuration
        hephaestus_config = {
            'action': 'hephaestus_cognitive',
            'payload': {
                'repository_url': message_data.get('repository_url'),
                'branch': message_data.get('branch', 'main'),
                'scan_type': message_data.get('scan_type', 'full'),
                'max_vulnerabilities': message_data.get('max_vulnerabilities', 10),
                'enable_evolution': message_data.get('enable_evolution', True),
                'custom_patterns': message_data.get('custom_patterns', [])
            },
            'triggered_by': 'sns',
            'sns_message_id': sns_message.get('MessageId')
        }
        
        # Validate required fields
        if not hephaestus_config['payload']['repository_url']:
            raise ValueError("repository_url is required for Hephaestus analysis")
        
        # Invoke AI Security Analyzer Lambda with Hephaestus action
        response = lambda_client.invoke(
            FunctionName=AI_SECURITY_ANALYZER_LAMBDA,
            InvocationType='Event',  # Async due to long-running analysis
            Payload=json.dumps(hephaestus_config)
        )
        
        # Store analysis request in DynamoDB
        scan_id = f"hephaestus-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{hashlib.md5(hephaestus_config['payload']['repository_url'].encode()).hexdigest()[:8]}"
        
        self.scan_table.put_item(
            Item={
                'scan_id': scan_id,
                'scan_type': 'hephaestus_cognitive',
                'status': 'INITIATED',
                'repository_url': hephaestus_config['payload']['repository_url'],
                'initiated_at': datetime.utcnow().isoformat(),
                'triggered_by': 'sns',
                'config': hephaestus_config
            }
        )
        
        return {
            'action': 'hephaestus_analysis_triggered',
            'status_code': response['StatusCode'],
            'scan_id': scan_id
        }
    
    def _handle_unknown_message(self, message_data: Dict, sns_message: Dict) -> Dict[str, Any]:
        """Handle unknown message types"""
        
        logger.warning(f"Unknown message type: {json.dumps(message_data)[:200]}")
        
        # Store for debugging
        if self.notification_table:
            self._store_notification(
                sns_message.get('MessageId', 'unknown'),
                'unknown',
                message_data,
                datetime.utcnow().isoformat()
            )
        
        return {'action': 'stored', 'type': 'unknown'}
    
    def _store_notification(self, message_id: str, message_type: str, data: Dict, timestamp: str):
        """Store notification in DynamoDB"""
        
        if not self.notification_table:
            return
        
        try:
            self.notification_table.put_item(
                Item={
                    'message_id': message_id,
                    'message_type': message_type,
                    'timestamp': timestamp,
                    'data': data,
                    'ttl': int(datetime.utcnow().timestamp()) + 2592000  # 30 days
                }
            )
        except Exception as e:
            logger.error(f"Failed to store notification: {e}")
    
    def _send_to_dlq(self, message: Dict, error: str):
        """Send failed message to Dead Letter Queue"""
        
        if not DLQ_URL:
            return
        
        try:
            sqs_client.send_message(
                QueueUrl=DLQ_URL,
                MessageBody=json.dumps({
                    'original_message': message,
                    'error': error,
                    'timestamp': datetime.utcnow().isoformat()
                })
            )
        except Exception as e:
            logger.error(f"Failed to send to DLQ: {e}")
    
    def _handle_scan_completion(self, scan_id: str, data: Dict):
        """Handle scan completion events"""
        
        # Trigger post-scan workflows
        findings_count = data.get('findings_count', 0)
        critical_count = data.get('critical_findings', 0)
        
        if critical_count > 0:
            # Notify security team
            logger.info(f"Scan {scan_id} completed with {critical_count} critical findings")
    
    def _handle_scan_failure(self, scan_id: str, data: Dict):
        """Handle scan failure events"""
        
        error_message = data.get('error', 'Unknown error')
        logger.error(f"Scan {scan_id} failed: {error_message}")
        
        # Could trigger retry logic here
    
    def _notify_security_team(self, alert: Dict):
        """Notify security team of critical alerts"""
        
        # In production, integrate with notification service
        logger.critical(f"SECURITY ALERT: {alert['alert_type']} - {alert['message']}")
    
    def _handle_jira_integration(self, data: Dict) -> Dict[str, Any]:
        """Handle JIRA integration messages"""
        
        action = data.get('action', '')
        
        if action == 'create_issue':
            # Would create JIRA issue for findings
            return {
                'action': 'jira_issue_created',
                'issue_key': 'SEC-123'  # Mock
            }
        
        return {'action': 'ignored', 'reason': f'unknown_jira_action: {action}'}
    
    def _handle_slack_integration(self, data: Dict) -> Dict[str, Any]:
        """Handle Slack integration messages"""
        
        # Would send to Slack webhook
        return {
            'action': 'slack_notification_sent',
            'channel': data.get('channel', '#security')
        }
    
    def _handle_pagerduty_integration(self, data: Dict) -> Dict[str, Any]:
        """Handle PagerDuty integration messages"""
        
        # Would create PagerDuty incident
        return {
            'action': 'pagerduty_incident_created',
            'incident_key': 'mock-incident'
        }
    
    def _handle_servicenow_integration(self, data: Dict) -> Dict[str, Any]:
        """Handle ServiceNow integration messages"""
        
        # Would create ServiceNow ticket
        return {
            'action': 'servicenow_ticket_created',
            'ticket_number': 'INC0012345'
        }


def lambda_handler(event, context):
    """Lambda handler for SNS messages"""
    
    handler = SNSMessageHandler()
    
    try:
        # Handle SNS event
        if 'Records' in event:
            results = []
            
            for record in event['Records']:
                if record.get('EventSource') == 'aws:sns':
                    sns_message = record['Sns']
                    result = handler.process_sns_message(sns_message)
                    results.append(result)
            
            return {
                'statusCode': 200,
                'processed': len(results),
                'results': results
            }
        else:
            # Direct invocation (for testing)
            return handler.process_sns_message(event)
            
    except Exception as e:
        logger.error(f"SNS handler failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e)
        }