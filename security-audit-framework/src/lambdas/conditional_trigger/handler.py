"""
Conditional Agent Triggering Lambda - Analyzes findings and triggers additional agents based on conditions
"""
import os
import json
import boto3
from typing import Dict, List, Any, Set
from datetime import datetime

s3_client = boto3.client('s3')
ecs_client = boto3.client('ecs')
dynamodb = boto3.resource('dynamodb')


class ConditionalTrigger:
    """Decides which additional agents to trigger based on findings"""
    
    def __init__(self):
        self.scan_table = dynamodb.Table(os.environ.get('SCAN_TABLE', 'SecurityScans'))
        self.ecs_cluster = os.environ.get('ECS_CLUSTER_NAME')
        self.trigger_rules = self._load_trigger_rules()
        
    def _load_trigger_rules(self) -> List[Dict[str, Any]]:
        """Load conditional triggering rules"""
        return [
            {
                'name': 'AWS Key Found - Trigger Container Security',
                'condition': {
                    'finding_type': 'SECRETS_AWS_KEY',
                    'severity': ['CRITICAL', 'HIGH']
                },
                'trigger_agent': 'CONTAINER_SECURITY',
                'reason': 'AWS keys found - checking for container misconfigurations'
            },
            {
                'name': 'Hardcoded Secrets - Deep API Scan',
                'condition': {
                    'finding_type': 'SECRETS_HARDCODED',
                    'count_threshold': 5
                },
                'trigger_agent': 'API_SECURITY',
                'reason': 'Multiple hardcoded secrets found - checking API security'
            },
            {
                'name': 'SQL Injection - Business Logic Check',
                'condition': {
                    'finding_type': 'SAST_SQL_INJECTION',
                    'severity': ['HIGH', 'CRITICAL']
                },
                'trigger_agent': 'BUSINESS_LOGIC',
                'reason': 'SQL injection found - checking for business logic flaws'
            },
            {
                'name': 'Container Issues - Kubernetes Deep Scan',
                'condition': {
                    'finding_type': 'CONTAINER_ROOT_USER',
                    'file_pattern': 'Dockerfile'
                },
                'trigger_agent': 'CONTAINER_SECURITY',
                'additional_config': {'focus': 'kubernetes'}
            },
            {
                'name': 'Authentication Issues - Full Security Audit',
                'condition': {
                    'finding_types': ['API_NO_AUTH_ENDPOINT', 'AUTH_BYPASS'],
                    'match_any': True
                },
                'trigger_agents': ['API_SECURITY', 'BUSINESS_LOGIC'],
                'reason': 'Authentication vulnerabilities require comprehensive analysis'
            },
            {
                'name': 'Critical Mass - Autonomous Analysis',
                'condition': {
                    'total_critical_findings': 10
                },
                'trigger_agent': 'AUTONOMOUS',
                'reason': 'High number of critical findings - AI analysis needed'
            }
        ]
    
    def analyze_and_trigger(self, scan_id: str, agent_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze agent results and determine which additional agents to trigger"""
        # Aggregate findings from all agents
        all_findings = []
        findings_by_type = {}
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for result in agent_results:
            if result.get('status') == 'COMPLETED':
                agent_type = result.get('agent_type')
                s3_path = result.get('results', {}).get('output_s3_path', '')
                
                if s3_path:
                    # Load findings from S3
                    findings = self._load_findings_from_s3(s3_path)
                    for finding in findings:
                        all_findings.append(finding)
                        finding_type = finding.get('vulnerability_type', 'UNKNOWN')
                        if finding_type not in findings_by_type:
                            findings_by_type[finding_type] = []
                        findings_by_type[finding_type].append(finding)
                        
                        severity = finding.get('severity', 'MEDIUM')
                        if severity in severity_counts:
                            severity_counts[severity] += 1
        
        # Evaluate trigger rules
        triggered_agents = []
        for rule in self.trigger_rules:
            if self._evaluate_rule(rule, findings_by_type, severity_counts):
                agents = rule.get('trigger_agents', [rule.get('trigger_agent')])
                if not isinstance(agents, list):
                    agents = [agents]
                
                for agent in agents:
                    triggered_agents.append({
                        'agent_type': agent,
                        'trigger_rule': rule['name'],
                        'reason': rule.get('reason', 'Conditional trigger'),
                        'config': rule.get('additional_config', {})
                    })
        
        # Remove duplicates
        unique_agents = {}
        for agent in triggered_agents:
            agent_type = agent['agent_type']
            if agent_type not in unique_agents:
                unique_agents[agent_type] = agent
        
        triggered_agents = list(unique_agents.values())
        
        # Update scan metadata
        self._update_scan_metadata(scan_id, triggered_agents)
        
        return {
            'scan_id': scan_id,
            'analyzed_findings': len(all_findings),
            'triggered_agents': triggered_agents,
            'trigger_summary': {
                'total_triggers': len(triggered_agents),
                'reasons': [agent['reason'] for agent in triggered_agents]
            }
        }
    
    def _evaluate_rule(self, rule: Dict[str, Any], findings_by_type: Dict[str, List], 
                      severity_counts: Dict[str, int]) -> bool:
        """Evaluate if a trigger rule matches current findings"""
        condition = rule['condition']
        
        # Check single finding type
        if 'finding_type' in condition:
            finding_type = condition['finding_type']
            if finding_type not in findings_by_type:
                return False
            
            findings = findings_by_type[finding_type]
            
            # Check severity
            if 'severity' in condition:
                required_severities = condition['severity']
                if not any(f.get('severity') in required_severities for f in findings):
                    return False
            
            # Check count threshold
            if 'count_threshold' in condition:
                if len(findings) < condition['count_threshold']:
                    return False
            
            # Check file pattern
            if 'file_pattern' in condition:
                pattern = condition['file_pattern']
                if not any(pattern in f.get('file_path', '') for f in findings):
                    return False
            
            return True
        
        # Check multiple finding types
        if 'finding_types' in condition:
            finding_types = condition['finding_types']
            match_any = condition.get('match_any', False)
            
            if match_any:
                return any(ft in findings_by_type for ft in finding_types)
            else:
                return all(ft in findings_by_type for ft in finding_types)
        
        # Check total critical findings
        if 'total_critical_findings' in condition:
            return severity_counts['CRITICAL'] >= condition['total_critical_findings']
        
        return False
    
    def _load_findings_from_s3(self, s3_path: str) -> List[Dict[str, Any]]:
        """Load findings from S3"""
        try:
            # Parse S3 path
            if s3_path.startswith('s3://'):
                s3_path = s3_path[5:]
            
            parts = s3_path.split('/', 1)
            if len(parts) != 2:
                return []
            
            bucket, key = parts
            
            response = s3_client.get_object(Bucket=bucket, Key=key)
            data = json.loads(response['Body'].read())
            
            return data.get('findings', [])
        except Exception as e:
            print(f"Error loading findings from {s3_path}: {e}")
            return []
    
    def _update_scan_metadata(self, scan_id: str, triggered_agents: List[Dict[str, Any]]):
        """Update scan metadata with conditional triggers"""
        try:
            self.scan_table.update_item(
                Key={'scan_id': scan_id},
                UpdateExpression='SET conditional_triggers = :triggers, trigger_timestamp = :ts',
                ExpressionAttributeValues={
                    ':triggers': triggered_agents,
                    ':ts': datetime.utcnow().isoformat()
                }
            )
        except Exception as e:
            print(f"Error updating scan metadata: {e}")


class AdaptiveScanDepth:
    """Implements adaptive scan depth based on initial findings"""
    
    def __init__(self):
        self.depth_rules = [
            {
                'name': 'High Risk - Deep Scan',
                'condition': {
                    'critical_findings': 5,
                    'or_high_findings': 20
                },
                'scan_depth': 'deep',
                'additional_checks': ['dependency_tree', 'transitive_dependencies', 'advanced_patterns']
            },
            {
                'name': 'Suspicious Patterns - Extended Scan',
                'condition': {
                    'pattern_matches': ['backdoor', 'rootkit', 'crypto_miner']
                },
                'scan_depth': 'extended',
                'additional_checks': ['behavioral_analysis', 'entropy_check']
            },
            {
                'name': 'Clean Initial Scan - Standard Depth',
                'condition': {
                    'max_severity': 'LOW',
                    'finding_count': 10
                },
                'scan_depth': 'standard'
            }
        ]
    
    def determine_scan_depth(self, initial_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Determine appropriate scan depth based on initial findings"""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        patterns_found = set()
        
        for finding in initial_findings:
            severity = finding.get('severity', 'MEDIUM')
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Check for suspicious patterns
            message = finding.get('message', '').lower()
            for pattern in ['backdoor', 'rootkit', 'crypto', 'miner', 'malware']:
                if pattern in message:
                    patterns_found.add(pattern)
        
        # Evaluate depth rules
        for rule in self.depth_rules:
            condition = rule['condition']
            
            if 'critical_findings' in condition:
                if severity_counts['CRITICAL'] >= condition['critical_findings']:
                    return {
                        'depth': rule['scan_depth'],
                        'reason': rule['name'],
                        'additional_checks': rule.get('additional_checks', [])
                    }
            
            if 'or_high_findings' in condition:
                if severity_counts['HIGH'] >= condition['or_high_findings']:
                    return {
                        'depth': rule['scan_depth'],
                        'reason': rule['name'],
                        'additional_checks': rule.get('additional_checks', [])
                    }
            
            if 'pattern_matches' in condition:
                if any(p in patterns_found for p in condition['pattern_matches']):
                    return {
                        'depth': rule['scan_depth'],
                        'reason': rule['name'],
                        'additional_checks': rule.get('additional_checks', [])
                    }
        
        # Default depth
        return {
            'depth': 'standard',
            'reason': 'Default scan depth',
            'additional_checks': []
        }


def lambda_handler(event, context):
    """Lambda handler for conditional agent triggering"""
    try:
        scan_id = event['scan_id']
        agent_results = event.get('agent_results', [])
        
        # Analyze and determine conditional triggers
        trigger = ConditionalTrigger()
        trigger_results = trigger.analyze_and_trigger(scan_id, agent_results)
        
        # Determine adaptive scan depth for triggered agents
        adaptive = AdaptiveScanDepth()
        
        # Load initial findings for depth analysis
        all_findings = []
        for result in agent_results:
            if result.get('status') == 'COMPLETED':
                s3_path = result.get('results', {}).get('output_s3_path', '')
                if s3_path:
                    findings = trigger._load_findings_from_s3(s3_path)
                    all_findings.extend(findings)
        
        depth_config = adaptive.determine_scan_depth(all_findings)
        
        # Enhance triggered agents with depth configuration
        for agent in trigger_results['triggered_agents']:
            agent['scan_depth'] = depth_config['depth']
            agent['depth_reason'] = depth_config['reason']
            if depth_config.get('additional_checks'):
                agent['config']['additional_checks'] = depth_config['additional_checks']
        
        # Prepare response
        response = {
            'scan_id': scan_id,
            'conditional_triggers': trigger_results,
            'adaptive_depth': depth_config,
            'next_agents': [
                {
                    'agent_type': agent['agent_type'],
                    'priority': 'high',
                    'config': agent.get('config', {}),
                    'trigger_metadata': {
                        'reason': agent['reason'],
                        'scan_depth': agent['scan_depth']
                    }
                }
                for agent in trigger_results['triggered_agents']
            ]
        }
        
        # Store analysis results
        results_bucket = os.environ.get('RESULTS_BUCKET')
        output_path = f"processed/{scan_id}/conditional_triggers.json"
        s3_client.put_object(
            Bucket=results_bucket,
            Key=output_path,
            Body=json.dumps(response, indent=2),
            ContentType='application/json'
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Conditional trigger analysis completed',
                'triggered_agents': len(trigger_results['triggered_agents']),
                'scan_depth': depth_config['depth']
            })
        }
        
    except Exception as e:
        print(f"Error in conditional trigger: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }