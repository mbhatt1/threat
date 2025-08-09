"""
Unified Bedrock AI Security Scanner - Uses centralized AI Orchestrator
"""
import os
import sys
import json
import boto3
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path

# Add parent directories to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import AI orchestrator and other components
from shared.ai_orchestrator import AISecurityOrchestrator
from shared.ai_explainability import AIExplainabilityEngine
from shared.advanced_features import AISecurityFeatures
from shared.business_context import BusinessContextEngine

# Initialize AWS clients
s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')


class BedrockUnifiedSecurityScanner:
    """Unified AI agent that uses centralized AI orchestrator for all security scanning"""
    
    def __init__(self):
        # Initialize AI components
        self.orchestrator = AISecurityOrchestrator()
        self.explainability = AIExplainabilityEngine()
        self.ai_features = AISecurityFeatures()
        self.business_context = BusinessContextEngine()
        
        # AWS resources
        self.results_bucket = os.environ.get('RESULTS_BUCKET')
        self.scan_table = dynamodb.Table(os.environ.get('SCAN_TABLE', 'SecurityScans'))
        self.ai_scans_table = dynamodb.Table(os.environ.get('AI_SCANS_TABLE', 'SecurityAuditAIScans'))
        self.ai_findings_table = dynamodb.Table(os.environ.get('AI_FINDINGS_TABLE', 'SecurityAuditAIFindings'))
        
    async def scan_repository(self, repo_path: str, scan_id: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive AI-based security scan using centralized orchestrator"""
        start_time = datetime.utcnow()
        
        # Update scan status
        self._update_scan_status(scan_id, 'IN_PROGRESS', 'Starting AI security analysis')
        
        try:
            # Determine scan type from config
            scan_type = scan_config.get('scan_type', 'full')
            branch = scan_config.get('branch', 'main')
            base_branch = scan_config.get('base_branch')
            
            # Use AI orchestrator for scanning
            scan_result = await self.orchestrator.orchestrate_security_scan(
                repository_path=repo_path,
                scan_type=scan_type,
                branch=branch,
                base_branch=base_branch
            )
            
            # Get detailed findings from DynamoDB
            findings = self._get_scan_findings(scan_result.scan_id)
            
            # Get AI insights
            insights = self._get_ai_insights(scan_result.scan_id)
            
            # Prepare comprehensive results
            results = {
                'scan_id': scan_id,
                'ai_scan_id': scan_result.scan_id,
                'timestamp': start_time.isoformat(),
                'repository_path': repo_path,
                'scan_type': 'BEDROCK_UNIFIED_AI',
                'status': scan_result.scan_status,
                'total_findings': scan_result.total_findings,
                'critical_findings': scan_result.critical_findings,
                'high_findings': scan_result.high_findings,
                'business_risk_score': scan_result.business_risk_score,
                'ai_confidence_score': scan_result.ai_confidence_score,
                'vulnerabilities': self._organize_findings_by_type(findings),
                'attack_scenarios': self._extract_attack_scenarios(findings),
                'remediation_plan': self._generate_remediation_plan(findings, insights),
                'ai_insights': insights,
                'scan_duration_seconds': (datetime.utcnow() - start_time).total_seconds()
            }
            
            # Save results to S3 and DynamoDB
            self._save_results(results)
            
            # Update scan status
            self._update_scan_status(scan_id, 'COMPLETED', 'AI security analysis completed')
            
            return results
            
        except Exception as e:
            error_msg = f"AI scan failed: {str(e)}"
            self._update_scan_status(scan_id, 'FAILED', error_msg)
            raise
    
    def _organize_findings_by_type(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Any]]:
        """Organize findings by vulnerability type"""
        organized = {
            'code_vulnerabilities': [],
            'dependency_issues': [],
            'secrets_exposed': [],
            'infrastructure_misconfigs': [],
            'api_vulnerabilities': [],
            'container_issues': [],
            'business_logic_flaws': [],
            'supply_chain_risks': [],
            'policy_violations': []
        }
        
        for finding in findings:
            finding_type = finding.get('finding_type', 'unknown')
            
            # Enhanced finding with explainability
            enhanced_finding = {
                'type': finding.get('description', 'Unknown vulnerability'),
                'severity': finding.get('severity', 'MEDIUM'),
                'confidence': finding.get('confidence', 0.8),
                'confidence_level': finding.get('confidence_level', 'medium'),
                'file_path': finding.get('file_path', ''),
                'line_numbers': self._extract_line_numbers(finding),
                'description': finding.get('description', ''),
                'remediation': finding.get('remediation', ''),
                'business_risk_score': finding.get('business_risk_score', 0),
                'evidence': finding.get('evidence', []),
                'reasoning': finding.get('reasoning', []),
                'false_positive_indicators': finding.get('false_positive_indicators', []),
                'ai_explanation': self._format_explanation(finding)
            }
            
            # Categorize by type
            if finding_type == 'vulnerability':
                organized['code_vulnerabilities'].append(enhanced_finding)
            elif finding_type == 'supply_chain':
                organized['supply_chain_risks'].append(enhanced_finding)
            elif finding_type == 'policy_violation':
                organized['policy_violations'].append(enhanced_finding)
            elif 'secret' in finding.get('description', '').lower():
                organized['secrets_exposed'].append(enhanced_finding)
            elif 'dependency' in finding.get('description', '').lower():
                organized['dependency_issues'].append(enhanced_finding)
            elif 'infrastructure' in finding.get('file_path', '').lower():
                organized['infrastructure_misconfigs'].append(enhanced_finding)
            elif 'api' in finding.get('description', '').lower():
                organized['api_vulnerabilities'].append(enhanced_finding)
            elif 'container' in finding.get('file_path', '').lower() or 'docker' in finding.get('file_path', '').lower():
                organized['container_issues'].append(enhanced_finding)
            else:
                organized['code_vulnerabilities'].append(enhanced_finding)
        
        return organized
    
    def _extract_line_numbers(self, finding: Dict[str, Any]) -> List[int]:
        """Extract line numbers from finding data"""
        # Try different possible formats
        if 'line_numbers' in finding:
            return finding['line_numbers']
        elif 'line' in finding:
            return [finding['line']]
        elif 'source_lines' in finding:
            return finding['source_lines']
        
        # Try to extract from evidence
        for evidence in finding.get('evidence', []):
            if 'source_lines' in evidence and evidence['source_lines']:
                return evidence['source_lines']
        
        return []
    
    def _format_explanation(self, finding: Dict[str, Any]) -> str:
        """Format AI explanation for a finding"""
        explanation_parts = []
        
        # Add confidence level
        confidence_level = finding.get('confidence_level', 'unknown')
        explanation_parts.append(f"AI Confidence: {confidence_level}")
        
        # Add reasoning
        reasoning = finding.get('reasoning', [])
        if reasoning:
            explanation_parts.append("\nAI Reasoning:")
            for i, step in enumerate(reasoning[:3], 1):
                explanation_parts.append(f"  {i}. {step}")
        
        # Add evidence
        evidence = finding.get('evidence', [])
        if evidence:
            explanation_parts.append("\nEvidence:")
            for e in evidence[:3]:
                explanation_parts.append(f"  • {e.get('description', 'Unknown evidence')}")
        
        # Add false positive indicators
        fp_indicators = finding.get('false_positive_indicators', [])
        if fp_indicators:
            explanation_parts.append("\nPossible False Positive:")
            for indicator in fp_indicators:
                explanation_parts.append(f"  - {indicator}")
        
        return "\n".join(explanation_parts)
    
    def _extract_attack_scenarios(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract attack scenarios from findings"""
        # Use AI to identify attack chains
        high_risk_findings = [f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']]
        
        if len(high_risk_findings) < 2:
            return []
        
        # Use the AI flow analyzer to predict attack paths
        try:
            # Prepare code context from findings
            code_snippets = []
            for finding in high_risk_findings[:10]:
                if 'code_context' in finding:
                    code_snippets.append(finding['code_context'])
            
            # Get attack path predictions
            attack_paths = self.ai_features.flow_analyzer.predict_attack_paths(
                application_context="Security scan findings",
                code_snippets=code_snippets
            )
            
            return attack_paths
        except Exception as e:
            print(f"Failed to extract attack scenarios: {e}")
            return []
    
    def _generate_remediation_plan(self, findings: List[Dict[str, Any]], insights: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive remediation plan"""
        # Group findings by severity
        critical = [f for f in findings if f.get('severity') == 'CRITICAL']
        high = [f for f in findings if f.get('severity') == 'HIGH']
        
        plan = {
            'immediate_actions': [],
            'short_term': [],
            'long_term': [],
            'security_improvements': []
        }
        
        # Immediate actions for critical findings
        for finding in critical[:5]:
            plan['immediate_actions'].append({
                'action': f"Fix {finding.get('description', 'critical vulnerability')}",
                'location': finding.get('file_path', 'Unknown'),
                'remediation': finding.get('remediation', 'Review and fix immediately'),
                'priority': 1,
                'estimated_time': '1-2 hours'
            })
        
        # Short term actions for high findings
        for finding in high[:10]:
            plan['short_term'].append({
                'action': f"Address {finding.get('description', 'high severity issue')}",
                'location': finding.get('file_path', 'Unknown'),
                'remediation': finding.get('remediation', 'Fix within one week'),
                'priority': 2,
                'estimated_time': '2-4 hours'
            })
        
        # Add AI recommendations
        if insights and 'remediation_priorities' in insights:
            for priority in insights['remediation_priorities'][:3]:
                plan['long_term'].append({
                    'action': priority,
                    'priority': 3,
                    'estimated_time': '1-2 weeks'
                })
        
        # Security improvements based on findings
        if findings:
            plan['security_improvements'] = [
                {
                    'improvement': 'Implement automated security scanning in CI/CD',
                    'benefit': 'Catch vulnerabilities before production',
                    'implementation_guide': 'Add AI security scanner to build pipeline'
                },
                {
                    'improvement': 'Enable real-time security monitoring',
                    'benefit': 'Detect and respond to threats immediately',
                    'implementation_guide': 'Deploy AI monitoring agents'
                }
            ]
        
        return plan
    
    def _get_scan_findings(self, ai_scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve findings from DynamoDB"""
        findings = []
        
        try:
            # Query findings by scan ID
            response = self.ai_findings_table.query(
                IndexName='ScanIndex',
                KeyConditionExpression='scan_id = :scan_id',
                ExpressionAttributeValues={
                    ':scan_id': ai_scan_id
                }
            )
            
            findings = response.get('Items', [])
            
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
        
        return findings
    
    def _get_ai_insights(self, ai_scan_id: str) -> Dict[str, Any]:
        """Retrieve AI insights from S3"""
        try:
            # Get insights from S3 report
            response = s3_client.get_object(
                Bucket=self.results_bucket,
                Key=f"reports/{ai_scan_id}.json"
            )
            
            report = json.loads(response['Body'].read())
            return report.get('insights', {})
            
        except Exception as e:
            print(f"Error retrieving insights: {e}")
            return {}
    
    def _save_results(self, results: Dict[str, Any]) -> None:
        """Save results to S3 and DynamoDB"""
        scan_id = results['scan_id']
        
        # Save to S3
        try:
            s3_key = f"raw/{scan_id}/unified_results.json"
            s3_client.put_object(
                Bucket=self.results_bucket,
                Key=s3_key,
                Body=json.dumps(results, default=str),
                ContentType='application/json',
                ServerSideEncryption='AES256',
                Tagging=f"ScanId={scan_id}&ScanType=unified&Priority=high"
            )
            print(f"Results saved to S3: {s3_key}")
        except Exception as e:
            print(f"Error saving to S3: {e}")
        
        # Update DynamoDB scan record
        try:
            self.scan_table.update_item(
                Key={'scan_id': scan_id},
                UpdateExpression="SET #st = :status, total_findings = :total, critical_findings = :critical, "
                               "high_findings = :high, business_risk_score = :risk, ai_confidence_score = :conf, "
                               "s3_key = :s3_key, completed_at = :completed",
                ExpressionAttributeNames={
                    '#st': 'status'
                },
                ExpressionAttributeValues={
                    ':status': 'COMPLETED',
                    ':total': results['total_findings'],
                    ':critical': results['critical_findings'],
                    ':high': results['high_findings'],
                    ':risk': results['business_risk_score'],
                    ':conf': results['ai_confidence_score'],
                    ':s3_key': f"raw/{scan_id}/unified_results.json",
                    ':completed': datetime.utcnow().isoformat()
                }
            )
        except Exception as e:
            print(f"Error updating DynamoDB: {e}")
    
    def _update_scan_status(self, scan_id: str, status: str, message: str = None) -> None:
        """Update scan status in DynamoDB"""
        try:
            update_expr = "SET #st = :status, last_updated = :updated"
            expr_values = {
                ':status': status,
                ':updated': datetime.utcnow().isoformat()
            }
            
            if message:
                update_expr += ", status_message = :message"
                expr_values[':message'] = message
            
            self.scan_table.update_item(
                Key={'scan_id': scan_id},
                UpdateExpression=update_expr,
                ExpressionAttributeNames={
                    '#st': 'status'
                },
                ExpressionAttributeValues=expr_values
            )
        except Exception as e:
            print(f"Error updating scan status: {e}")


def handler(event, context):
    """Lambda handler for ECS task"""
    import asyncio
    
    print(f"Received event: {json.dumps(event)}")
    
    # Extract parameters
    scan_id = event.get('scan_id')
    repo_url = event.get('repository_url')
    scan_config = event.get('scan_config', {})
    
    if not scan_id or not repo_url:
        raise ValueError("scan_id and repository_url are required")
    
    # Initialize scanner
    scanner = BedrockUnifiedSecurityScanner()
    
    # Clone repository (simplified for demo)
    repo_path = f"/tmp/{scan_id}"
    os.makedirs(repo_path, exist_ok=True)
    
    # Run async scan
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        results = loop.run_until_complete(
            scanner.scan_repository(repo_path, scan_id, scan_config)
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'scan_id': scan_id,
                'status': 'completed',
                'findings': results['total_findings'],
                'risk_score': results['business_risk_score']
            })
        }
    finally:
        loop.close()
        
        # Cleanup
        import shutil
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)