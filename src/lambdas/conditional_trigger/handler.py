"""
Conditional Trigger Lambda - Evaluates conditions and triggers appropriate workflows
"""
import os
import json
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from decimal import Decimal

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
dynamodb = boto3.resource('dynamodb')
stepfunctions = boto3.client('stepfunctions')
sns_client = boto3.client('sns')
cloudwatch = boto3.client('cloudwatch')

# Environment variables
SCAN_TABLE = os.environ.get('SCAN_TABLE', 'SecurityScans')
AI_SCANS_TABLE = os.environ.get('AI_SCANS_TABLE', 'SecurityAuditAIScans')
FINDINGS_TABLE = os.environ.get('AI_FINDINGS_TABLE', 'SecurityAuditAIFindings')
STATE_MACHINE_ARN = os.environ.get('STATE_MACHINE_ARN')
ALERT_TOPIC_ARN = os.environ.get('ALERT_TOPIC_ARN')
SCAN_REQUEST_TOPIC = os.environ.get('SCAN_REQUEST_TOPIC_ARN')


class ConditionalTriggerHandler:
    """Handles conditional triggers for security workflows"""
    
    def __init__(self):
        self.scan_table = dynamodb.Table(SCAN_TABLE)
        self.ai_scans_table = dynamodb.Table(AI_SCANS_TABLE)
        self.findings_table = dynamodb.Table(FINDINGS_TABLE)
        self.conditions = self._load_trigger_conditions()
        
    def evaluate_triggers(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate conditions and trigger appropriate actions
        
        Event sources:
        1. Scheduled CloudWatch Events (periodic checks)
        2. DynamoDB Streams (real-time triggers)
        3. Direct invocation from other services
        4. SNS notifications
        """
        
        trigger_type = event.get('trigger_type', 'scan_complete')
        
        if trigger_type == 'scan_complete':
            return self._handle_scan_complete(event)
        elif trigger_type == 'critical_finding':
            return self._handle_critical_finding(event)
        elif trigger_type == 'scheduled_check':
            return self._handle_scheduled_check(event)
        elif trigger_type == 'threshold_breach':
            return self._handle_threshold_breach(event)
        elif trigger_type == 'dependency_update':
            return self._handle_dependency_update(event)
        elif trigger_type == 'compliance_check':
            return self._handle_compliance_check(event)
        else:
            logger.warning(f"Unknown trigger type: {trigger_type}")
            return {'statusCode': 400, 'message': f'Unknown trigger type: {trigger_type}'}
    
    def _handle_scan_complete(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle scan completion triggers"""
        scan_id = event.get('scan_id')
        ai_scan_id = event.get('ai_scan_id')
        
        if not scan_id and not ai_scan_id:
            return {'statusCode': 400, 'message': 'scan_id or ai_scan_id required'}
        
        # Get scan results
        scan_data = self._get_scan_data(scan_id, ai_scan_id)
        if not scan_data:
            return {'statusCode': 404, 'message': 'Scan not found'}
        
        triggered_actions = []
        
        # Check critical findings threshold
        critical_count = scan_data.get('critical_findings', 0)
        if critical_count > 0:
            # Trigger immediate remediation
            action = self._trigger_remediation_workflow(scan_data)
            triggered_actions.append(action)
            
            # Send critical alert
            alert = self._send_critical_alert(scan_data)
            triggered_actions.append(alert)
        
        # Check high findings threshold
        high_count = scan_data.get('high_findings', 0)
        if high_count >= 5:  # Configurable threshold
            # Trigger detailed analysis
            action = self._trigger_detailed_analysis(scan_data)
            triggered_actions.append(action)
        
        # Check business risk threshold
        business_risk = float(scan_data.get('business_risk_score', 0))
        if business_risk >= 0.7:  # High business risk
            # Trigger executive notification
            action = self._trigger_executive_notification(scan_data)
            triggered_actions.append(action)
        
        # Check for specific vulnerability types
        if event.get('findings'):
            vuln_actions = self._check_vulnerability_patterns(event['findings'])
            triggered_actions.extend(vuln_actions)
        
        # Update CloudWatch metrics
        self._update_metrics(scan_data)
        
        return {
            'statusCode': 200,
            'scan_id': scan_id,
            'ai_scan_id': ai_scan_id,
            'triggered_actions': triggered_actions,
            'metrics_updated': True
        }
    
    def _handle_critical_finding(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle critical finding triggers"""
        finding = event.get('finding', {})
        scan_id = event.get('scan_id')
        
        triggered_actions = []
        
        # Check if finding requires immediate action
        if self._requires_immediate_action(finding):
            # Trigger emergency response
            action = {
                'type': 'emergency_response',
                'status': 'triggered',
                'finding_id': finding.get('finding_id'),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Execute emergency response workflow
            if STATE_MACHINE_ARN:
                execution = stepfunctions.start_execution(
                    stateMachineArn=STATE_MACHINE_ARN,
                    name=f"emergency-{finding.get('finding_id')}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    input=json.dumps({
                        'action': 'emergency_response',
                        'finding': finding,
                        'scan_id': scan_id
                    })
                )
                action['execution_arn'] = execution['executionArn']
            
            triggered_actions.append(action)
            
            # Send immediate notification
            self._send_emergency_notification(finding)
        
        # Check if finding affects critical assets
        if finding.get('asset_criticality') == 'critical':
            # Trigger asset protection workflow
            action = self._trigger_asset_protection(finding)
            triggered_actions.append(action)
        
        # Check for active exploitation
        if self._check_active_exploitation(finding):
            # Trigger incident response
            action = self._trigger_incident_response(finding)
            triggered_actions.append(action)
        
        return {
            'statusCode': 200,
            'finding_id': finding.get('finding_id'),
            'triggered_actions': triggered_actions
        }
    
    def _handle_scheduled_check(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle scheduled checks"""
        check_type = event.get('check_type', 'compliance')
        
        if check_type == 'compliance':
            return self._run_compliance_checks()
        elif check_type == 'drift_detection':
            return self._run_drift_detection()
        elif check_type == 'vulnerability_trends':
            return self._analyze_vulnerability_trends()
        elif check_type == 'stale_findings':
            return self._check_stale_findings()
        else:
            return {'statusCode': 400, 'message': f'Unknown check type: {check_type}'}
    
    def _handle_threshold_breach(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle metric threshold breaches"""
        metric_name = event.get('metric_name')
        current_value = event.get('current_value')
        threshold = event.get('threshold')
        
        triggered_actions = []
        
        if metric_name == 'vulnerability_density':
            # High vulnerability density detected
            if current_value > threshold:
                # Trigger comprehensive scan
                action = self._trigger_comprehensive_scan(event.get('repository'))
                triggered_actions.append(action)
        
        elif metric_name == 'false_positive_rate':
            # High false positive rate
            if current_value > threshold:
                # Trigger model retraining
                action = self._trigger_model_retraining()
                triggered_actions.append(action)
        
        elif metric_name == 'scan_failure_rate':
            # High scan failure rate
            if current_value > threshold:
                # Trigger system health check
                action = self._trigger_health_check()
                triggered_actions.append(action)
        
        return {
            'statusCode': 200,
            'metric_name': metric_name,
            'breach_handled': True,
            'triggered_actions': triggered_actions
        }
    
    def _handle_dependency_update(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle dependency update triggers"""
        dependency = event.get('dependency', {})
        severity = event.get('severity', 'unknown')
        affected_repos = event.get('affected_repositories', [])
        
        triggered_actions = []
        
        # Critical dependency vulnerability
        if severity == 'CRITICAL':
            for repo in affected_repos:
                # Trigger immediate scan
                action = self._trigger_dependency_scan(repo, dependency)
                triggered_actions.append(action)
        
        # Check if dependency is in critical path
        if self._is_critical_dependency(dependency):
            # Trigger emergency patch workflow
            action = self._trigger_emergency_patch(dependency, affected_repos)
            triggered_actions.append(action)
        
        return {
            'statusCode': 200,
            'dependency': dependency.get('name'),
            'severity': severity,
            'affected_count': len(affected_repos),
            'triggered_actions': triggered_actions
        }
    
    def _handle_compliance_check(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle compliance check triggers"""
        framework = event.get('compliance_framework', 'PCI-DSS')
        check_results = event.get('results', {})
        
        triggered_actions = []
        
        # Check for compliance failures
        failures = [r for r in check_results.get('checks', []) if r.get('status') == 'FAILED']
        
        if failures:
            # Generate compliance report
            report = self._generate_compliance_report(framework, failures)
            triggered_actions.append({
                'type': 'compliance_report_generated',
                'report_id': report['report_id']
            })
            
            # Check if any failures are critical
            critical_failures = [f for f in failures if f.get('severity') == 'CRITICAL']
            if critical_failures:
                # Trigger compliance remediation
                action = self._trigger_compliance_remediation(framework, critical_failures)
                triggered_actions.append(action)
        
        return {
            'statusCode': 200,
            'framework': framework,
            'total_checks': len(check_results.get('checks', [])),
            'failures': len(failures),
            'triggered_actions': triggered_actions
        }
    
    def _load_trigger_conditions(self) -> Dict[str, Any]:
        """Load trigger conditions from configuration"""
        # In production, load from DynamoDB or S3
        return {
            'critical_finding_threshold': 1,
            'high_finding_threshold': 5,
            'business_risk_threshold': 0.7,
            'vulnerability_density_threshold': 0.3,
            'false_positive_threshold': 0.2,
            'immediate_action_types': [
                'remote_code_execution',
                'sql_injection',
                'authentication_bypass',
                'privilege_escalation'
            ],
            'critical_dependencies': [
                'authentication',
                'authorization',
                'encryption',
                'payment_processing'
            ]
        }
    
    def _get_scan_data(self, scan_id: Optional[str], ai_scan_id: Optional[str]) -> Optional[Dict]:
        """Retrieve scan data from DynamoDB"""
        try:
            if ai_scan_id:
                response = self.ai_scans_table.get_item(Key={'scan_id': ai_scan_id})
                return response.get('Item')
            elif scan_id:
                response = self.scan_table.get_item(Key={'scan_id': scan_id})
                return response.get('Item')
        except Exception as e:
            logger.error(f"Error retrieving scan data: {e}")
        return None
    
    def _trigger_remediation_workflow(self, scan_data: Dict) -> Dict[str, Any]:
        """Trigger automated remediation workflow"""
        action = {
            'type': 'remediation_workflow',
            'status': 'triggered',
            'scan_id': scan_data.get('scan_id'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if STATE_MACHINE_ARN:
            try:
                execution = stepfunctions.start_execution(
                    stateMachineArn=STATE_MACHINE_ARN,
                    name=f"remediation-{scan_data.get('scan_id')}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    input=json.dumps({
                        'action': 'remediate',
                        'scan_id': scan_data.get('scan_id'),
                        'critical_findings': scan_data.get('critical_findings', 0)
                    })
                )
                action['execution_arn'] = execution['executionArn']
                action['status'] = 'success'
            except Exception as e:
                logger.error(f"Failed to trigger remediation: {e}")
                action['status'] = 'failed'
                action['error'] = str(e)
        
        return action
    
    def _send_critical_alert(self, scan_data: Dict) -> Dict[str, Any]:
        """Send critical finding alert"""
        action = {
            'type': 'critical_alert',
            'status': 'sent',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if ALERT_TOPIC_ARN:
            try:
                message = f"""
CRITICAL SECURITY ALERT

Scan ID: {scan_data.get('scan_id')}
Repository: {scan_data.get('repository', 'Unknown')}
Critical Findings: {scan_data.get('critical_findings', 0)}
Business Risk Score: {scan_data.get('business_risk_score', 0)}

Immediate action required. Automated remediation has been triggered.
"""
                
                sns_client.publish(
                    TopicArn=ALERT_TOPIC_ARN,
                    Subject='[CRITICAL] Security Findings Detected',
                    Message=message,
                    MessageAttributes={
                        'severity': {'DataType': 'String', 'StringValue': 'CRITICAL'},
                        'scan_id': {'DataType': 'String', 'StringValue': str(scan_data.get('scan_id', ''))}
                    }
                )
                action['status'] = 'success'
            except Exception as e:
                logger.error(f"Failed to send alert: {e}")
                action['status'] = 'failed'
                action['error'] = str(e)
        
        return action
    
    def _trigger_detailed_analysis(self, scan_data: Dict) -> Dict[str, Any]:
        """Trigger detailed analysis for high findings"""
        action = {
            'type': 'detailed_analysis',
            'status': 'triggered',
            'reason': 'high_findings_threshold_exceeded',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Trigger attack path analysis
        try:
            if 'LAMBDA_ATTACK_PATH_ARN' in os.environ:
                lambda_client = boto3.client('lambda')
                lambda_client.invoke(
                    FunctionName=os.environ['LAMBDA_ATTACK_PATH_ARN'],
                    InvocationType='Event',
                    Payload=json.dumps({
                        'scan_id': scan_data.get('scan_id'),
                        'ai_scan_id': scan_data.get('ai_scan_id')
                    })
                )
                action['components'] = ['attack_path_analysis']
                action['status'] = 'success'
        except Exception as e:
            logger.error(f"Failed to trigger analysis: {e}")
            action['status'] = 'failed'
            action['error'] = str(e)
        
        return action
    
    def _check_vulnerability_patterns(self, findings: List[Dict]) -> List[Dict]:
        """Check for specific vulnerability patterns that require action"""
        actions = []
        
        # Check for authentication vulnerabilities
        auth_vulns = [f for f in findings if 'auth' in f.get('finding_type', '').lower()]
        if len(auth_vulns) >= 3:
            actions.append({
                'type': 'pattern_detected',
                'pattern': 'multiple_auth_vulnerabilities',
                'action': 'security_review',
                'count': len(auth_vulns)
            })
        
        # Check for SQL injection cluster
        sql_vulns = [f for f in findings if 'sql' in f.get('finding_type', '').lower()]
        if len(sql_vulns) >= 2:
            actions.append({
                'type': 'pattern_detected',
                'pattern': 'sql_injection_cluster',
                'action': 'database_security_audit',
                'count': len(sql_vulns)
            })
        
        # Check for exposed secrets
        secret_vulns = [f for f in findings if any(term in f.get('finding_type', '').lower() 
                        for term in ['secret', 'credential', 'key', 'token'])]
        if secret_vulns:
            actions.append({
                'type': 'pattern_detected',
                'pattern': 'exposed_secrets',
                'action': 'secret_rotation',
                'count': len(secret_vulns),
                'immediate': True
            })
        
        return actions
    
    def _update_metrics(self, scan_data: Dict):
        """Update CloudWatch metrics"""
        try:
            namespace = 'SecurityAudit'
            
            # Put metrics
            cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        'MetricName': 'CriticalFindings',
                        'Value': float(scan_data.get('critical_findings', 0)),
                        'Unit': 'Count',
                        'Timestamp': datetime.utcnow()
                    },
                    {
                        'MetricName': 'BusinessRiskScore',
                        'Value': float(scan_data.get('business_risk_score', 0)),
                        'Unit': 'None',
                        'Timestamp': datetime.utcnow()
                    },
                    {
                        'MetricName': 'TotalFindings',
                        'Value': float(scan_data.get('total_findings', 0)),
                        'Unit': 'Count',
                        'Timestamp': datetime.utcnow()
                    }
                ]
            )
        except Exception as e:
            logger.error(f"Failed to update metrics: {e}")
    
    def _requires_immediate_action(self, finding: Dict) -> bool:
        """Check if finding requires immediate action"""
        finding_type = finding.get('finding_type', '').lower()
        
        # Check against immediate action types
        for action_type in self.conditions['immediate_action_types']:
            if action_type in finding_type:
                return True
        
        # Critical severity with high confidence
        if finding.get('severity') == 'CRITICAL' and float(finding.get('confidence', 0)) > 0.8:
            return True
        
        # Actively exploited vulnerability
        if finding.get('actively_exploited', False):
            return True
        
        return False
    
    def _check_active_exploitation(self, finding: Dict) -> bool:
        """Check if vulnerability is being actively exploited"""
        # In production, check threat intelligence feeds
        # For now, check for specific indicators
        indicators = finding.get('exploitation_indicators', [])
        return len(indicators) > 0
    
    def _run_compliance_checks(self) -> Dict[str, Any]:
        """Run scheduled compliance checks"""
        # Get recent scans
        recent_scans = self._get_recent_scans(hours=24)
        
        compliance_issues = []
        for scan in recent_scans:
            # Check compliance criteria
            if scan.get('critical_findings', 0) > 0:
                compliance_issues.append({
                    'scan_id': scan.get('scan_id'),
                    'issue': 'unresolved_critical_findings',
                    'count': scan.get('critical_findings')
                })
        
        if compliance_issues:
            # Generate compliance alert
            self._send_compliance_alert(compliance_issues)
        
        return {
            'statusCode': 200,
            'type': 'compliance_check',
            'scans_checked': len(recent_scans),
            'issues_found': len(compliance_issues)
        }
    
    def _get_recent_scans(self, hours: int = 24) -> List[Dict]:
        """Get scans from the last N hours"""
        # In production, query DynamoDB with timestamp filter
        # This is a simplified version
        return []
    
    def _send_emergency_notification(self, finding: Dict):
        """Send emergency notification for critical findings"""
        if ALERT_TOPIC_ARN:
            try:
                sns_client.publish(
                    TopicArn=ALERT_TOPIC_ARN,
                    Subject='[EMERGENCY] Immediate Security Action Required',
                    Message=json.dumps({
                        'finding_id': finding.get('finding_id'),
                        'type': finding.get('finding_type'),
                        'severity': 'CRITICAL',
                        'requires_immediate_action': True,
                        'file': finding.get('file_path'),
                        'description': finding.get('description')
                    }, indent=2),
                    MessageAttributes={
                        'priority': {'DataType': 'String', 'StringValue': 'EMERGENCY'}
                    }
                )
            except Exception as e:
                logger.error(f"Failed to send emergency notification: {e}")
    
    def _trigger_comprehensive_scan(self, repository: str) -> Dict[str, Any]:
        """Trigger comprehensive security scan"""
        action = {
            'type': 'comprehensive_scan',
            'repository': repository,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if SCAN_REQUEST_TOPIC:
            try:
                sns_client.publish(
                    TopicArn=SCAN_REQUEST_TOPIC,
                    Message=json.dumps({
                        'repository_url': repository,
                        'scan_options': {
                            'deep_scan': True,
                            'all_branches': True,
                            'include_history': True
                        }
                    })
                )
                action['status'] = 'triggered'
            except Exception as e:
                action['status'] = 'failed'
                action['error'] = str(e)
        
        return action
    
    def _is_critical_dependency(self, dependency: Dict) -> bool:
        """Check if dependency is critical"""
        dep_name = dependency.get('name', '').lower()
        
        for critical in self.conditions['critical_dependencies']:
            if critical in dep_name:
                return True
        
        return dependency.get('criticality') == 'critical'


def lambda_handler(event, context):
    """Lambda handler for conditional triggers"""
    
    handler = ConditionalTriggerHandler()
    
    try:
        # Handle different event sources
        if 'Records' in event:
            # DynamoDB Stream or SNS
            results = []
            for record in event['Records']:
                if 'dynamodb' in record:
                    # DynamoDB stream event
                    if record['eventName'] in ['INSERT', 'MODIFY']:
                        new_image = record['dynamodb'].get('NewImage', {})
                        trigger_event = {
                            'trigger_type': 'scan_complete',
                            'scan_id': new_image.get('scan_id', {}).get('S')
                        }
                        result = handler.evaluate_triggers(trigger_event)
                        results.append(result)
                elif 'Sns' in record:
                    # SNS event
                    message = json.loads(record['Sns']['Message'])
                    result = handler.evaluate_triggers(message)
                    results.append(result)
            
            return {
                'statusCode': 200,
                'results': results
            }
        else:
            # Direct invocation
            return handler.evaluate_triggers(event)
            
    except Exception as e:
        logger.error(f"Conditional trigger failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e)
        }