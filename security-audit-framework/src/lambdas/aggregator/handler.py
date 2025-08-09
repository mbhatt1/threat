"""
AI Results Aggregator - Aggregates findings from AI DynamoDB tables
"""
import os
import sys
import json
import boto3
from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict
import hashlib
from pathlib import Path
from decimal import Decimal

# Add parent directories to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import AI components
from shared.ai_explainability import AIExplainabilityEngine
from shared.business_context import BusinessContextEngine

# AWS clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
bedrock_runtime = boto3.client('bedrock-runtime')
securityhub = boto3.client('securityhub')


class AIResultsAggregator:
    """Aggregates and processes AI-generated security findings from DynamoDB"""
    
    def __init__(self):
        # AI Components
        self.explainability = AIExplainabilityEngine()
        self.business_context = BusinessContextEngine()
        
        # S3 buckets
        self.results_bucket = os.environ.get('RESULTS_BUCKET')
        
        # DynamoDB tables
        self.ai_findings_table = dynamodb.Table(
            os.environ.get('AI_FINDINGS_TABLE', 'SecurityAuditAIFindings')
        )
        self.ai_scans_table = dynamodb.Table(
            os.environ.get('AI_SCANS_TABLE', 'SecurityAuditAIScans')
        )
        self.scan_table = dynamodb.Table(
            os.environ.get('SCAN_TABLE', 'SecurityScans')
        )
        
        # Configuration
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
    
    def aggregate_results(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate AI scan results from DynamoDB with intelligent deduplication and prioritization"""
        
        # Extract scan IDs
        scan_id = event.get('scan_id')  # Legacy scan ID
        ai_scan_id = event.get('ai_scan_id') or event.get('results', {}).get('ai_scan_id')
        
        if not ai_scan_id:
            # Try to get AI scan ID from legacy scan table
            ai_scan_id = self._get_ai_scan_id(scan_id)
        
        if not ai_scan_id:
            raise ValueError("No AI scan ID found")
        
        # Get scan metadata
        scan_metadata = self._get_scan_metadata(ai_scan_id)
        
        # Retrieve all findings from DynamoDB
        all_findings = self._retrieve_findings_from_dynamodb(ai_scan_id)
        
        # Use AI for intelligent deduplication
        deduplicated_findings = self._ai_deduplicate_findings(all_findings)
        
        # Enhance findings with business context
        enhanced_findings = self._enhance_with_business_context(deduplicated_findings)
        
        # Group and prioritize
        severity_groups = self._group_by_severity(enhanced_findings)
        prioritized_findings = self._prioritize_findings(enhanced_findings)
        
        # Get AI insights from S3
        ai_insights = self._get_ai_insights(ai_scan_id)
        
        # Calculate statistics
        statistics = {
            'total_findings': len(enhanced_findings),
            'by_severity': {
                'CRITICAL': len(severity_groups.get('CRITICAL', [])),
                'HIGH': len(severity_groups.get('HIGH', [])),
                'MEDIUM': len(severity_groups.get('MEDIUM', [])),
                'LOW': len(severity_groups.get('LOW', []))
            },
            'by_category': self._count_by_category(enhanced_findings),
            'by_confidence_level': self._count_by_confidence(enhanced_findings),
            'business_risk_score': scan_metadata.get('business_risk_score', 0),
            'ai_confidence_score': scan_metadata.get('ai_confidence_score', 0),
            'false_positive_rate': self._calculate_false_positive_rate(enhanced_findings)
        }
        
        # Extract attack scenarios
        attack_scenarios = self._extract_attack_scenarios(enhanced_findings)
        
        # Generate comprehensive remediation plan
        remediation_plan = self._generate_remediation_plan(
            prioritized_findings, ai_insights, attack_scenarios
        )
        
        # Create aggregated result
        aggregated = {
            'scan_id': scan_id,
            'ai_scan_id': ai_scan_id,
            'timestamp': datetime.utcnow().isoformat(),
            'findings': prioritized_findings[:100],  # Top 100 findings
            'attack_scenarios': attack_scenarios,
            'remediation_plan': remediation_plan,
            'ai_insights': ai_insights,
            'statistics': statistics,
            'scan_metadata': {
                'ai_model': self.model_id,
                'scan_type': scan_metadata.get('scan_type', 'unknown'),
                'repository': scan_metadata.get('repository', ''),
                'branch': scan_metadata.get('branch', 'main'),
                'scan_duration': self._calculate_scan_duration(scan_metadata),
                'files_analyzed': len(set(f.get('file_path', '') for f in all_findings))
            },
            'explainability_summary': self._generate_explainability_summary(enhanced_findings)
        }
        
        # Send to Security Hub
        self._send_to_security_hub(ai_scan_id, prioritized_findings[:100])
        
        # Save aggregated results to S3
        self._save_to_s3(ai_scan_id, aggregated)
        
        # Update scan status
        self._update_scan_status(scan_id, ai_scan_id, statistics)
        
        return aggregated
    
    def _retrieve_findings_from_dynamodb(self, ai_scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve all findings for a scan from DynamoDB"""
        findings = []
        
        try:
            # Query findings by scan ID using GSI
            response = self.ai_findings_table.query(
                IndexName='ScanIndex',
                KeyConditionExpression='scan_id = :scan_id',
                ExpressionAttributeValues={
                    ':scan_id': ai_scan_id
                }
            )
            
            findings.extend(response.get('Items', []))
            
            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = self.ai_findings_table.query(
                    IndexName='ScanIndex',
                    KeyConditionExpression='scan_id = :scan_id',
                    ExpressionAttributeValues={
                        ':scan_id': ai_scan_id
                    },
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                findings.extend(response.get('Items', []))
                
        except Exception as e:
            print(f"Error retrieving findings: {e}")
        
        # Convert Decimal to float for JSON serialization
        for finding in findings:
            if 'confidence' in finding:
                finding['confidence'] = float(finding['confidence'])
            if 'business_risk_score' in finding:
                finding['business_risk_score'] = float(finding['business_risk_score'])
        
        return findings
    
    def _get_scan_metadata(self, ai_scan_id: str) -> Dict[str, Any]:
        """Get scan metadata from DynamoDB"""
        try:
            response = self.ai_scans_table.get_item(
                Key={'scan_id': ai_scan_id}
            )
            return response.get('Item', {})
        except Exception as e:
            print(f"Error getting scan metadata: {e}")
            return {}
    
    def _get_ai_scan_id(self, scan_id: str) -> str:
        """Get AI scan ID from legacy scan table"""
        try:
            response = self.scan_table.get_item(
                Key={'scan_id': scan_id}
            )
            item = response.get('Item', {})
            return item.get('ai_scan_id', '')
        except Exception as e:
            print(f"Error getting AI scan ID: {e}")
            return ''
    
    def _enhance_with_business_context(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance findings with business context"""
        enhanced = []
        
        for finding in findings:
            # Add business context if not already present
            if 'business_risk_score' not in finding:
                finding['business_risk_score'] = self.business_context.calculate_business_risk_score(finding)
            
            # Get asset criticality
            file_path = finding.get('file_path', '')
            asset_criticality = self.business_context.get_asset_criticality(file_path)
            finding['asset_criticality'] = asset_criticality
            
            # Adjust priority based on business impact
            if asset_criticality == 'critical' and finding.get('severity') == 'HIGH':
                finding['adjusted_severity'] = 'CRITICAL'
            else:
                finding['adjusted_severity'] = finding.get('severity', 'MEDIUM')
            
            enhanced.append(finding)
        
        return enhanced
    
    def _ai_deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use AI to intelligently deduplicate findings"""
        if not findings:
            return []
        
        # For large numbers of findings, process in batches
        if len(findings) > 50:
            deduplicated = []
            for i in range(0, len(findings), 50):
                batch = findings[i:i+50]
                deduplicated.extend(self._ai_deduplicate_batch(batch))
            
            # Do a final pass on the deduplicated results
            if len(deduplicated) > 50:
                return self._simple_deduplicate(deduplicated)
            else:
                return self._ai_deduplicate_batch(deduplicated)
        else:
            return self._ai_deduplicate_batch(findings)
    
    def _ai_deduplicate_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate a batch of findings using AI"""
        # Prepare findings for AI analysis
        findings_summary = []
        for i, finding in enumerate(findings):
            findings_summary.append({
                'index': i,
                'type': finding.get('finding_type', 'unknown'),
                'file': finding.get('file_path', ''),
                'severity': finding.get('severity', 'MEDIUM'),
                'description': finding.get('description', '')[:100],
                'confidence': finding.get('confidence', 0)
            })
        
        prompt = f"""Analyze these security findings and identify duplicates.

Findings:
{json.dumps(findings_summary, indent=2)}

Identify which findings are duplicates. Consider:
1. Same vulnerability type in same file/location
2. Similar descriptions that refer to the same issue
3. Cascading effects (one root cause creating multiple findings)

For duplicates, keep the one with:
- Higher confidence score
- More detailed description
- Higher severity

Return a JSON object with:
{{
    "unique_indices": [list of indices to keep],
    "duplicate_groups": [
        {{
            "primary": index_to_keep,
            "duplicates": [indices_that_are_duplicates],
            "reason": "why they are duplicates"
        }}
    ]
}}"""

        try:
            response = bedrock_runtime.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 2048,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1
                })
            )
            
            response_body = json.loads(response['body'].read())
            ai_response = response_body.get('content', [{}])[0].get('text', '{}')
            
            # Parse AI response
            import re
            json_match = re.search(r'\{[\s\S]*\}', ai_response)
            if json_match:
                dedup_info = json.loads(json_match.group())
                unique_indices = dedup_info.get('unique_indices', list(range(len(findings))))
                
                # Keep unique findings
                return [findings[i] for i in unique_indices if i < len(findings)]
            
        except Exception as e:
            print(f"AI deduplication failed: {str(e)}")
        
        # Fallback to simple deduplication
        return self._simple_deduplicate(findings)
    
    def _simple_deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Simple deduplication based on hash"""
        seen = set()
        deduplicated = []
        
        for finding in findings:
            # Create hash of key fields
            key = f"{finding.get('finding_type')}:{finding.get('file_path')}:{finding.get('description', '')[:50]}"
            finding_hash = hashlib.md5(key.encode()).hexdigest()
            
            if finding_hash not in seen:
                seen.add(finding_hash)
                deduplicated.append(finding)
        
        return deduplicated
    
    def _prioritize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize findings based on multiple factors"""
        # Calculate priority score for each finding
        for finding in findings:
            severity_scores = {'CRITICAL': 40, 'HIGH': 30, 'MEDIUM': 20, 'LOW': 10}
            
            priority_score = (
                severity_scores.get(finding.get('adjusted_severity', 'MEDIUM'), 20) +
                finding.get('business_risk_score', 0) * 20 +
                finding.get('confidence', 0.5) * 20 +
                (10 if finding.get('asset_criticality') == 'critical' else 0) +
                (10 if len(finding.get('false_positive_indicators', [])) == 0 else -5)
            )
            
            finding['priority_score'] = priority_score
        
        # Sort by priority score descending
        return sorted(findings, key=lambda x: x.get('priority_score', 0), reverse=True)
    
    def _extract_attack_scenarios(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract potential attack scenarios from findings"""
        # Group high-severity findings that could be chained
        high_severity = [f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']]
        
        # Look for common attack patterns
        scenarios = []
        
        # Check for authentication bypass + data access
        auth_issues = [f for f in high_severity if 'auth' in f.get('description', '').lower()]
        data_access = [f for f in high_severity if any(term in f.get('description', '').lower() 
                                                      for term in ['sql', 'data', 'database', 'api'])]
        
        if auth_issues and data_access:
            scenarios.append({
                'name': 'Authentication Bypass to Data Exfiltration',
                'severity': 'CRITICAL',
                'steps': [
                    {'vulnerability': auth_issues[0].get('description', ''),
                     'file': auth_issues[0].get('file_path', '')},
                    {'vulnerability': data_access[0].get('description', ''),
                     'file': data_access[0].get('file_path', '')}
                ],
                'impact': 'Complete system compromise and data breach'
            })
        
        return scenarios
    
    def _generate_remediation_plan(self, 
                                 findings: List[Dict[str, Any]], 
                                 ai_insights: Dict[str, Any],
                                 attack_scenarios: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive remediation plan"""
        plan = {
            'immediate_actions': [],
            'short_term': [],
            'long_term': [],
            'security_improvements': []
        }
        
        # Immediate actions for critical findings
        critical_findings = [f for f in findings[:20] if f.get('adjusted_severity') == 'CRITICAL']
        for finding in critical_findings[:5]:
            plan['immediate_actions'].append({
                'action': f"Fix {finding.get('finding_type', 'vulnerability')} in {finding.get('file_path', '')}",
                'description': finding.get('description', ''),
                'remediation': finding.get('remediation', 'Review and fix immediately'),
                'priority': 1,
                'estimated_time': '1-4 hours',
                'business_impact': f"Risk Score: {finding.get('business_risk_score', 0):.1f}"
            })
        
        # Add AI-recommended priorities
        if ai_insights and 'remediation_priorities' in ai_insights:
            for i, priority in enumerate(ai_insights['remediation_priorities'][:3]):
                plan['short_term'].append({
                    'action': priority,
                    'priority': i + 1,
                    'estimated_time': '1-2 weeks',
                    'source': 'AI recommendation'
                })
        
        # Security improvements based on patterns
        if len([f for f in findings if 'sql' in f.get('description', '').lower()]) > 3:
            plan['security_improvements'].append({
                'improvement': 'Implement parameterized queries framework-wide',
                'benefit': 'Eliminate SQL injection vulnerabilities',
                'implementation_guide': 'Use ORM or prepared statements for all database queries'
            })
        
        return plan
    
    def _generate_explainability_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of AI explainability metrics"""
        confidence_levels = [f.get('confidence_level', 'unknown') for f in findings]
        
        return {
            'average_confidence': sum(f.get('confidence', 0) for f in findings) / len(findings) if findings else 0,
            'confidence_distribution': {
                'very_high': confidence_levels.count('very_high'),
                'high': confidence_levels.count('high'),
                'medium': confidence_levels.count('medium'),
                'low': confidence_levels.count('low'),
                'very_low': confidence_levels.count('very_low')
            },
            'findings_with_evidence': len([f for f in findings if f.get('evidence')]),
            'findings_with_reasoning': len([f for f in findings if f.get('reasoning')]),
            'potential_false_positives': len([f for f in findings if f.get('false_positive_indicators')])
        }
    
    def _count_by_confidence(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by confidence level"""
        counts = defaultdict(int)
        for finding in findings:
            level = finding.get('confidence_level', 'unknown')
            counts[level] += 1
        return dict(counts)
    
    def _calculate_false_positive_rate(self, findings: List[Dict[str, Any]]) -> float:
        """Estimate false positive rate based on indicators"""
        if not findings:
            return 0.0
        
        potential_fps = len([f for f in findings if len(f.get('false_positive_indicators', [])) > 0])
        return round(potential_fps / len(findings), 3)
    
    def _calculate_scan_duration(self, scan_metadata: Dict[str, Any]) -> float:
        """Calculate scan duration in seconds"""
        started = scan_metadata.get('started_at')
        completed = scan_metadata.get('completed_at')
        
        if started and completed:
            try:
                start_time = datetime.fromisoformat(started.replace('Z', '+00:00'))
                end_time = datetime.fromisoformat(completed.replace('Z', '+00:00'))
                return (end_time - start_time).total_seconds()
            except:
                pass
        
        return 0
    
    def _get_ai_insights(self, ai_scan_id: str) -> Dict[str, Any]:
        """Retrieve AI insights from S3"""
        try:
            response = s3_client.get_object(
                Bucket=self.results_bucket,
                Key=f"reports/{ai_scan_id}.json"
            )
            
            report = json.loads(response['Body'].read())
            return report.get('insights', {})
            
        except Exception as e:
            print(f"Error retrieving insights: {e}")
            return {}
    
    def _group_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by severity"""
        groups = defaultdict(list)
        for finding in findings:
            severity = finding.get('adjusted_severity', finding.get('severity', 'MEDIUM'))
            groups[severity].append(finding)
        return dict(groups)
    
    def _count_by_category(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by category/type"""
        counts = defaultdict(int)
        for finding in findings:
            category = finding.get('finding_type', 'unknown')
            counts[category] += 1
        return dict(counts)
    
    def _send_to_security_hub(self, ai_scan_id: str, findings: List[Dict[str, Any]]) -> None:
        """Send findings to AWS Security Hub with AI metadata"""
        try:
            security_findings = []
            
            for finding in findings:
                security_finding = {
                    'SchemaVersion': '2018-10-08',
                    'Id': f"{ai_scan_id}/{finding.get('finding_id', '')}",
                    'ProductArn': f"arn:aws:securityhub:{os.environ.get('AWS_REGION', 'us-east-1')}:{os.environ.get('AWS_ACCOUNT_ID', '')}:product/{os.environ.get('AWS_ACCOUNT_ID', '')}/ai-security-scanner",
                    'GeneratorId': 'ai-security-scanner-bedrock',
                    'AwsAccountId': os.environ.get('AWS_ACCOUNT_ID', ''),
                    'Types': [f"Software and Configuration Checks/{finding.get('finding_type', 'Vulnerability')}"],
                    'CreatedAt': finding.get('created_at', datetime.utcnow().isoformat()) + 'Z',
                    'UpdatedAt': datetime.utcnow().isoformat() + 'Z',
                    'Severity': {
                        'Label': finding.get('adjusted_severity', finding.get('severity', 'MEDIUM'))
                    },
                    'Confidence': int(finding.get('confidence', 0.8) * 100),
                    'Title': finding.get('description', 'Security Issue')[:256],
                    'Description': self._create_security_hub_description(finding),
                    'Remediation': {
                        'Recommendation': {
                            'Text': finding.get('remediation', 'Review and fix the security issue')
                        }
                    },
                    'Resources': [{
                        'Type': 'Other',
                        'Id': finding.get('file_path', 'unknown'),
                        'Details': {
                            'Other': {
                                'BusinessRiskScore': str(finding.get('business_risk_score', 0)),
                                'AIConfidence': str(finding.get('confidence', 0.95)),
                                'ConfidenceLevel': finding.get('confidence_level', 'unknown'),
                                'AssetCriticality': finding.get('asset_criticality', 'normal'),
                                'FalsePositiveIndicators': json.dumps(finding.get('false_positive_indicators', []))
                            }
                        }
                    }]
                }
                security_findings.append(security_finding)
            
            if security_findings:
                # Batch import findings
                for i in range(0, len(security_findings), 100):
                    batch = security_findings[i:i+100]
                    securityhub.batch_import_findings(Findings=batch)
                    
        except Exception as e:
            print(f"Error sending to Security Hub: {str(e)}")
    
    def _create_security_hub_description(self, finding: Dict[str, Any]) -> str:
        """Create detailed description for Security Hub"""
        parts = [finding.get('description', 'Security issue detected')]
        
        # Add AI explanation
        if finding.get('reasoning'):
            parts.append(f"\n\nAI Analysis: {finding['reasoning'][0]}")
        
        # Add business context
        if finding.get('business_risk_score'):
            parts.append(f"\n\nBusiness Risk Score: {finding['business_risk_score']:.1f}/100")
        
        # Add evidence summary
        if finding.get('evidence'):
            parts.append(f"\n\nEvidence: {len(finding['evidence'])} supporting indicators")
        
        return '\n'.join(parts)[:1024]  # Security Hub description limit
    
    def _save_to_s3(self, ai_scan_id: str, aggregated: Dict[str, Any]) -> None:
        """Save aggregated results to S3"""
        if self.results_bucket:
            s3_key = f"aggregated/{ai_scan_id}/results.json"
            s3_client.put_object(
                Bucket=self.results_bucket,
                Key=s3_key,
                Body=json.dumps(aggregated, indent=2, default=str),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            print(f"Aggregated results saved to S3: {s3_key}")
    
    def _update_scan_status(self, scan_id: str, ai_scan_id: str, statistics: Dict[str, Any]):
        """Update scan status in DynamoDB"""
        if scan_id:
            try:
                self.scan_table.update_item(
                    Key={'scan_id': scan_id},
                    UpdateExpression='SET aggregation_complete = :complete, '
                                   'total_findings = :total, critical_findings = :critical, '
                                   'high_findings = :high, aggregated_at = :timestamp',
                    ExpressionAttributeValues={
                        ':complete': True,
                        ':total': statistics['total_findings'],
                        ':critical': statistics['by_severity']['CRITICAL'],
                        ':high': statistics['by_severity']['HIGH'],
                        ':timestamp': datetime.utcnow().isoformat()
                    }
                )
            except Exception as e:
                print(f"Error updating scan status: {e}")
    
    def _invoke_data_transformer(self, ai_scan_id: str):
        """Invoke data transformer Lambda to prepare data for Athena"""
        try:
            data_transformer_lambda = os.environ.get('DATA_TRANSFORMER_LAMBDA_NAME', 'DataTransformerLambda')
            
            # Extract original scan_id from ai_scan_id
            scan_id = ai_scan_id.replace('ai-scan-', '') if ai_scan_id.startswith('ai-scan-') else ai_scan_id
            
            response = lambda_client.invoke(
                FunctionName=data_transformer_lambda,
                InvocationType='Event',  # Async invocation
                Payload=json.dumps({
                    'scan_id': scan_id
                })
            )
            
            if response['StatusCode'] == 202:
                print(f"Data transformer invoked successfully for scan_id: {scan_id}")
            else:
                print(f"Data transformer invocation failed with status: {response['StatusCode']}")
                
        except Exception as e:
            print(f"Error invoking data transformer: {e}")
            # Continue processing even if transformation fails


def handler(event, context):
    """Lambda handler for AI results aggregation"""
    aggregator = AIResultsAggregator()
    
    # Aggregate results
    aggregated = aggregator.aggregate_results(event)
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'scan_id': aggregated.get('scan_id'),
            'ai_scan_id': aggregated.get('ai_scan_id'),
            'total_findings': aggregated['statistics']['total_findings'],
            'business_risk_score': aggregated['statistics']['business_risk_score'],
            'critical_findings': aggregated['statistics']['by_severity']['CRITICAL'],
            'high_findings': aggregated['statistics']['by_severity']['HIGH'],
            'false_positive_rate': aggregated['statistics']['false_positive_rate'],
            's3_location': f"s3://{os.environ.get('RESULTS_BUCKET')}/aggregated/{aggregated.get('ai_scan_id')}/results.json"
        })
    }