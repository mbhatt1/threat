"""
Data Transformer Lambda - Converts agent outputs to Athena-compatible format
Transforms raw agent findings into partitioned JSONL format for Athena queries
"""
import os
import json
import boto3
import logging
from datetime import datetime
from typing import Dict, Any, List
from decimal import Decimal

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

# Environment variables
RESULTS_BUCKET = os.environ.get('RESULTS_BUCKET')
SCAN_TABLE = os.environ.get('SCAN_TABLE', 'SecurityScans')


class DataTransformer:
    """Transforms security findings for Athena consumption"""
    
    def __init__(self):
        self.results_bucket = RESULTS_BUCKET
        self.scan_table = dynamodb.Table(SCAN_TABLE)
    
    def transform_findings(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Transform agent findings to Athena-compatible format"""
        scan_id = event.get('scan_id')
        if not scan_id:
            raise ValueError("scan_id is required")
        
        logger.info(f"Starting data transformation for scan_id: {scan_id}")
        
        try:
            # Get scan metadata
            scan_metadata = self._get_scan_metadata(scan_id)
            scan_date = scan_metadata.get('scan_date', datetime.utcnow().strftime('%Y-%m-%d'))
            repository = self._extract_repository_name(scan_metadata.get('repository_url', 'default'))
            
            # Collect findings from all agent outputs
            all_findings = self._collect_agent_findings(scan_id)
            
            # Transform findings to JSONL format
            findings_jsonl = self._transform_to_jsonl(all_findings, scan_id, scan_date, repository)
            
            # Write individual findings for Athena
            findings_key = f"raw/{scan_date}/{repository}/findings.json"
            self._write_jsonl_to_s3(findings_key, findings_jsonl)
            
            # Write scan summary
            scan_summary = self._create_scan_summary(scan_id, scan_metadata, all_findings)
            summary_key = f"scans/{scan_date}/{repository}/{scan_id}.json"
            self._write_json_to_s3(summary_key, scan_summary)
            
            # Update scan record
            self._update_scan_record(scan_id, {
                'athena_data_ready': True,
                'findings_location': findings_key,
                'summary_location': summary_key,
                'transformed_at': datetime.utcnow().isoformat()
            })
            
            return {
                'statusCode': 200,
                'scan_id': scan_id,
                'findings_count': len(all_findings),
                'findings_location': findings_key,
                'summary_location': summary_key,
                'message': 'Data transformation completed successfully'
            }
            
        except Exception as e:
            logger.error(f"Data transformation failed: {str(e)}", exc_info=True)
            return {
                'statusCode': 500,
                'error': str(e)
            }
    
    def _get_scan_metadata(self, scan_id: str) -> Dict[str, Any]:
        """Retrieve scan metadata from DynamoDB"""
        try:
            response = self.scan_table.get_item(Key={'scan_id': scan_id})
            item = response.get('Item', {})
            
            # Convert Decimal to float for JSON serialization
            return json.loads(json.dumps(item, default=self._decimal_default))
        except Exception as e:
            logger.warning(f"Could not retrieve scan metadata: {e}")
            return {}
    
    def _decimal_default(self, obj):
        """Handle Decimal serialization"""
        if isinstance(obj, Decimal):
            return float(obj)
        raise TypeError
    
    def _extract_repository_name(self, repository_url: str) -> str:
        """Extract repository name from URL"""
        if not repository_url or repository_url == 'Unknown':
            return 'default'
        
        # Handle various Git URL formats
        repository_url = repository_url.rstrip('/')
        if repository_url.endswith('.git'):
            repository_url = repository_url[:-4]
        
        # Extract repository name
        parts = repository_url.split('/')
        if len(parts) >= 2:
            return parts[-1].replace(' ', '_').replace('-', '_').lower()
        
        return 'default'
    
    def _collect_agent_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Collect findings from all agent outputs"""
        all_findings = []
        
        # List of agent types to check
        agent_types = [
            'sast', 'secrets', 'iac', 'dependency', 
            'autonomous', 'bedrock_sast', 'bedrock_unified',
            'autonomous_code_analyzer', 'autonomous_threat_intel',
            'autonomous_infra_security', 'autonomous_supply_chain'
        ]
        
        for agent_type in agent_types:
            findings = self._read_agent_findings(scan_id, agent_type)
            all_findings.extend(findings)
        
        # Also check aggregated results
        aggregated = self._read_aggregated_findings(scan_id)
        if aggregated:
            all_findings.extend(aggregated)
        
        logger.info(f"Collected {len(all_findings)} total findings from all agents")
        return all_findings
    
    def _read_agent_findings(self, scan_id: str, agent_type: str) -> List[Dict[str, Any]]:
        """Read findings from a specific agent"""
        findings = []
        
        # Try multiple possible paths
        paths = [
            f"raw/{scan_id}/{agent_type}/results.json",
            f"raw/{scan_id}/{agent_type}_results.json",
            f"scans/{scan_id}/{agent_type}_results.json"
        ]
        
        for path in paths:
            try:
                response = s3_client.get_object(Bucket=self.results_bucket, Key=path)
                data = json.loads(response['Body'].read())
                
                # Extract findings from various possible structures
                if isinstance(data, dict):
                    if 'findings' in data:
                        agent_findings = data['findings']
                    elif 'results' in data and isinstance(data['results'], list):
                        agent_findings = data['results']
                    elif 'vulnerabilities' in data:
                        agent_findings = data['vulnerabilities']
                    else:
                        # Treat the entire dict as a single finding
                        agent_findings = [data]
                elif isinstance(data, list):
                    agent_findings = data
                else:
                    agent_findings = []
                
                # Add agent type to each finding
                for finding in agent_findings:
                    if isinstance(finding, dict):
                        finding['agent_type'] = agent_type
                        findings.append(finding)
                
                logger.info(f"Found {len(findings)} findings from {agent_type}")
                break
                
            except Exception as e:
                continue
        
        return findings
    
    def _read_aggregated_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Read aggregated findings"""
        try:
            # Look for AI scan ID format
            ai_scan_key = f"aggregated/ai-scan-{scan_id}/results.json"
            response = s3_client.get_object(Bucket=self.results_bucket, Key=ai_scan_key)
            data = json.loads(response['Body'].read())
            
            if 'findings' in data and isinstance(data['findings'], list):
                return data['findings']
            
        except:
            pass
        
        try:
            # Try regular scan ID
            key = f"aggregated/{scan_id}/results.json"
            response = s3_client.get_object(Bucket=self.results_bucket, Key=key)
            data = json.loads(response['Body'].read())
            
            if 'findings' in data and isinstance(data['findings'], list):
                return data['findings']
                
        except:
            pass
        
        return []
    
    def _transform_to_jsonl(self, findings: List[Dict[str, Any]], 
                           scan_id: str, scan_date: str, repository: str) -> str:
        """Transform findings to JSONL format for Athena"""
        jsonl_lines = []
        
        for idx, finding in enumerate(findings):
            # Create Athena-compatible record
            athena_record = {
                'finding_id': finding.get('finding_id', f"{scan_id}_{idx}"),
                'scan_id': scan_id,
                'scan_date': scan_date,
                'repository': repository,
                'type': finding.get('type', finding.get('finding_type', 'unknown')),
                'severity': finding.get('severity', 'MEDIUM'),
                'confidence': finding.get('confidence', 'medium'),
                'message': finding.get('message', finding.get('description', '')),
                'file_path': finding.get('file_path', finding.get('file', '')),
                'start_line': finding.get('start_line', finding.get('line', 0)),
                'end_line': finding.get('end_line', finding.get('line', 0)),
                'code_snippet': finding.get('code_snippet', ''),
                'remediation_suggestion': finding.get('remediation_suggestion', 
                                                    finding.get('remediation', '')),
                'cve_id': finding.get('cve_id', ''),
                'cwe_id': finding.get('cwe_id', ''),
                'owasp_category': finding.get('owasp_category', ''),
                'dependency_name': finding.get('dependency_name', ''),
                'dependency_version': finding.get('dependency_version', ''),
                'agent_type': finding.get('agent_type', 'unknown'),
                'found_at': datetime.utcnow().isoformat(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Add business context if available
            if 'business_risk_score' in finding:
                athena_record['business_risk_score'] = finding['business_risk_score']
            if 'asset_criticality' in finding:
                athena_record['asset_criticality'] = finding['asset_criticality']
            
            # Convert to JSON line
            jsonl_lines.append(json.dumps(athena_record))
        
        return '\n'.join(jsonl_lines)
    
    def _create_scan_summary(self, scan_id: str, metadata: Dict[str, Any], 
                           findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create scan summary for Athena scans table"""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        agent_counts = {}
        
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM')
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            agent = finding.get('agent_type', 'unknown')
            agent_counts[agent] = agent_counts.get(agent, 0) + 1
        
        return {
            'scan_id': scan_id,
            'repository_url': metadata.get('repository_url', 'Unknown'),
            'branch': metadata.get('branch', 'main'),
            'commit_hash': metadata.get('commit_hash', ''),
            'scan_type': metadata.get('scan_type', 'comprehensive'),
            'priority': metadata.get('priority', 'medium'),
            'status': 'COMPLETED',
            'started_at': metadata.get('started_at', datetime.utcnow().isoformat()),
            'completed_at': datetime.utcnow().isoformat(),
            'total_findings': len(findings),
            'critical_findings': severity_counts['CRITICAL'],
            'high_findings': severity_counts['HIGH'],
            'medium_findings': severity_counts['MEDIUM'],
            'low_findings': severity_counts['LOW'],
            'info_findings': severity_counts['INFO'],
            'total_cost_usd': metadata.get('total_cost', 0.0),
            'agents_executed': list(agent_counts.keys()),
            'execution_time_seconds': metadata.get('execution_time', 0)
        }
    
    def _write_jsonl_to_s3(self, key: str, content: str):
        """Write JSONL content to S3"""
        s3_client.put_object(
            Bucket=self.results_bucket,
            Key=key,
            Body=content.encode('utf-8'),
            ContentType='application/x-ndjson'
        )
        logger.info(f"Wrote JSONL data to s3://{self.results_bucket}/{key}")
    
    def _write_json_to_s3(self, key: str, data: Dict[str, Any]):
        """Write JSON data to S3"""
        s3_client.put_object(
            Bucket=self.results_bucket,
            Key=key,
            Body=json.dumps(data).encode('utf-8'),
            ContentType='application/json'
        )
        logger.info(f"Wrote JSON data to s3://{self.results_bucket}/{key}")
    
    def _update_scan_record(self, scan_id: str, updates: Dict[str, Any]):
        """Update scan record in DynamoDB"""
        try:
            update_expr = []
            expr_values = {}
            
            for key, value in updates.items():
                update_expr.append(f"{key} = :{key}")
                expr_values[f":{key}"] = value
            
            self.scan_table.update_item(
                Key={'scan_id': scan_id},
                UpdateExpression='SET ' + ', '.join(update_expr),
                ExpressionAttributeValues=expr_values
            )
        except Exception as e:
            logger.warning(f"Could not update scan record: {e}")


def lambda_handler(event, context):
    """Lambda handler function"""
    transformer = DataTransformer()
    
    # Handle both direct invocation and S3 events
    if 'Records' in event:
        # S3 event trigger
        for record in event['Records']:
            if record['eventName'].startswith('ObjectCreated'):
                bucket = record['s3']['bucket']['name']
                key = record['s3']['object']['key']
                
                # Extract scan_id from aggregated results path
                if 'aggregated/' in key and key.endswith('results.json'):
                    scan_id = key.split('/')[1].replace('ai-scan-', '')
                    return transformer.transform_findings({'scan_id': scan_id})
    else:
        # Direct invocation
        return transformer.transform_findings(event)
    
    return {'statusCode': 200, 'message': 'No action taken'}