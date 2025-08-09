"""
Attack Path Analysis Lambda - Analyzes potential attack chains in vulnerabilities
"""
import os
import sys
import json
import boto3
import logging
from datetime import datetime
from typing import Dict, List, Any, Tuple, Set
from collections import defaultdict, deque
from pathlib import Path
import networkx as nx

# Add parent directories to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from shared.ai_explainability import AIExplainabilityEngine
from shared.business_context import BusinessContextEngine

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
dynamodb = boto3.resource('dynamodb')
bedrock_runtime = boto3.client('bedrock-runtime')
s3_client = boto3.client('s3')

# Environment variables
FINDINGS_TABLE = os.environ.get('AI_FINDINGS_TABLE', 'SecurityAuditAIFindings')
RESULTS_BUCKET = os.environ.get('RESULTS_BUCKET')
MODEL_ID = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')


class AttackPathAnalyzer:
    """Analyzes attack paths from security findings"""
    
    def __init__(self):
        self.findings_table = dynamodb.Table(FINDINGS_TABLE)
        self.explainability = AIExplainabilityEngine()
        self.business_context = BusinessContextEngine()
        
    def analyze_attack_paths(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Main entry point for attack path analysis"""
        
        scan_id = event.get('scan_id')
        ai_scan_id = event.get('ai_scan_id')
        
        if not scan_id and not ai_scan_id:
            raise ValueError("Either scan_id or ai_scan_id must be provided")
        
        # Retrieve findings
        findings = self._get_findings(ai_scan_id or scan_id)
        
        if not findings:
            return {
                'scan_id': scan_id,
                'ai_scan_id': ai_scan_id,
                'attack_paths': [],
                'message': 'No findings to analyze'
            }
        
        # Build vulnerability graph
        vuln_graph = self._build_vulnerability_graph(findings)
        
        # Find attack chains
        attack_paths = self._find_attack_paths(vuln_graph, findings)
        
        # Analyze with AI for complex paths
        enhanced_paths = self._enhance_paths_with_ai(attack_paths, findings)
        
        # Calculate risk scores
        scored_paths = self._calculate_path_risks(enhanced_paths, findings)
        
        # Generate remediation priorities
        remediation_plan = self._generate_remediation_priorities(scored_paths)
        
        # Store results
        results = {
            'scan_id': scan_id,
            'ai_scan_id': ai_scan_id,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'total_findings': len(findings),
            'attack_paths_found': len(scored_paths),
            'critical_paths': len([p for p in scored_paths if p['risk_score'] >= 0.8]),
            'attack_paths': scored_paths[:50],  # Top 50 paths
            'remediation_priorities': remediation_plan,
            'graph_metrics': self._calculate_graph_metrics(vuln_graph)
        }
        
        # Save to S3
        if RESULTS_BUCKET and ai_scan_id:
            self._save_results(ai_scan_id, results)
        
        return results
    
    def _get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve findings from DynamoDB"""
        findings = []
        
        try:
            # Query using GSI
            response = self.findings_table.query(
                IndexName='ScanIndex',
                KeyConditionExpression='scan_id = :scan_id',
                ExpressionAttributeValues={':scan_id': scan_id}
            )
            
            findings.extend(response.get('Items', []))
            
            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = self.findings_table.query(
                    IndexName='ScanIndex',
                    KeyConditionExpression='scan_id = :scan_id',
                    ExpressionAttributeValues={':scan_id': scan_id},
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                findings.extend(response.get('Items', []))
                
        except Exception as e:
            logger.error(f"Error retrieving findings: {e}")
        
        return findings
    
    def _build_vulnerability_graph(self, findings: List[Dict[str, Any]]) -> nx.DiGraph:
        """Build a directed graph of vulnerability relationships"""
        G = nx.DiGraph()
        
        # Add nodes for each finding
        for finding in findings:
            finding_id = finding.get('finding_id')
            G.add_node(finding_id, **{
                'type': finding.get('finding_type'),
                'severity': finding.get('severity'),
                'file': finding.get('file_path'),
                'confidence': float(finding.get('confidence', 0.5)),
                'business_risk': float(finding.get('business_risk_score', 0))
            })
        
        # Add edges based on relationships
        for i, finding1 in enumerate(findings):
            for j, finding2 in enumerate(findings):
                if i != j:
                    # Check if vulnerabilities can be chained
                    if self._can_chain_vulnerabilities(finding1, finding2):
                        weight = self._calculate_edge_weight(finding1, finding2)
                        G.add_edge(
                            finding1['finding_id'],
                            finding2['finding_id'],
                            weight=weight
                        )
        
        return G
    
    def _can_chain_vulnerabilities(self, vuln1: Dict, vuln2: Dict) -> bool:
        """Determine if two vulnerabilities can be chained"""
        
        # Authentication bypass -> Any other vulnerability
        if 'auth' in vuln1.get('finding_type', '').lower():
            return True
        
        # SQL Injection -> Data access
        if 'sql' in vuln1.get('finding_type', '').lower() and \
           any(term in vuln2.get('finding_type', '').lower() for term in ['data', 'file', 'command']):
            return True
        
        # XSS -> Session hijacking
        if 'xss' in vuln1.get('finding_type', '').lower() and \
           any(term in vuln2.get('finding_type', '').lower() for term in ['session', 'auth', 'csrf']):
            return True
        
        # File upload -> Code execution
        if 'upload' in vuln1.get('finding_type', '').lower() and \
           any(term in vuln2.get('finding_type', '').lower() for term in ['exec', 'command', 'code']):
            return True
        
        # SSRF -> Internal access
        if 'ssrf' in vuln1.get('finding_type', '').lower():
            return True
        
        # Same file vulnerabilities
        if vuln1.get('file_path') == vuln2.get('file_path'):
            return True
        
        # API to API chaining
        if 'api' in vuln1.get('file_path', '').lower() and \
           'api' in vuln2.get('file_path', '').lower():
            return True
        
        return False
    
    def _calculate_edge_weight(self, vuln1: Dict, vuln2: Dict) -> float:
        """Calculate the weight of an edge (likelihood of successful chaining)"""
        weight = 1.0
        
        # Factor in severity
        severity_map = {'CRITICAL': 1.0, 'HIGH': 0.8, 'MEDIUM': 0.5, 'LOW': 0.3}
        weight *= severity_map.get(vuln1.get('severity', 'MEDIUM'), 0.5)
        weight *= severity_map.get(vuln2.get('severity', 'MEDIUM'), 0.5)
        
        # Factor in confidence
        weight *= float(vuln1.get('confidence', 0.5))
        weight *= float(vuln2.get('confidence', 0.5))
        
        # Same file bonus
        if vuln1.get('file_path') == vuln2.get('file_path'):
            weight *= 1.5
        
        return min(weight, 1.0)
    
    def _find_attack_paths(self, G: nx.DiGraph, findings: List[Dict]) -> List[Dict[str, Any]]:
        """Find potential attack paths in the vulnerability graph"""
        attack_paths = []
        
        # Identify entry points (external-facing vulnerabilities)
        entry_points = self._identify_entry_points(G, findings)
        
        # Identify targets (high-value assets)
        targets = self._identify_targets(G, findings)
        
        # Find paths from entry points to targets
        for entry in entry_points:
            for target in targets:
                if entry != target:
                    try:
                        # Find all simple paths (to avoid cycles)
                        paths = list(nx.all_simple_paths(
                            G, entry, target, cutoff=5
                        ))
                        
                        for path in paths[:10]:  # Limit to 10 paths per pair
                            attack_paths.append({
                                'path': path,
                                'entry_point': entry,
                                'target': target,
                                'length': len(path),
                                'vulnerabilities': [
                                    self._get_finding_summary(f_id, findings)
                                    for f_id in path
                                ]
                            })
                    except nx.NetworkXNoPath:
                        continue
        
        # Sort by path length (shorter paths are often more dangerous)
        attack_paths.sort(key=lambda x: x['length'])
        
        return attack_paths
    
    def _identify_entry_points(self, G: nx.DiGraph, findings: List[Dict]) -> List[str]:
        """Identify potential entry points for attackers"""
        entry_points = []
        
        for finding in findings:
            finding_id = finding.get('finding_id')
            file_path = finding.get('file_path', '').lower()
            finding_type = finding.get('finding_type', '').lower()
            
            # External-facing components
            if any(term in file_path for term in ['api', 'web', 'public', 'endpoint', 'route']):
                entry_points.append(finding_id)
            
            # Authentication/authorization issues
            elif any(term in finding_type for term in ['auth', 'access', 'permission']):
                entry_points.append(finding_id)
            
            # Input validation issues
            elif any(term in finding_type for term in ['injection', 'xss', 'input']):
                entry_points.append(finding_id)
        
        return entry_points
    
    def _identify_targets(self, G: nx.DiGraph, findings: List[Dict]) -> List[str]:
        """Identify high-value targets"""
        targets = []
        
        for finding in findings:
            finding_id = finding.get('finding_id')
            file_path = finding.get('file_path', '').lower()
            
            # Database/data access
            if any(term in file_path for term in ['database', 'db', 'data', 'model']):
                targets.append(finding_id)
            
            # Admin/privileged functions
            elif any(term in file_path for term in ['admin', 'manage', 'config']):
                targets.append(finding_id)
            
            # Critical business logic
            elif finding.get('asset_criticality') == 'critical':
                targets.append(finding_id)
            
            # High business risk findings
            elif float(finding.get('business_risk_score', 0)) > 0.8:
                targets.append(finding_id)
        
        return targets
    
    def _enhance_paths_with_ai(self, paths: List[Dict], findings: List[Dict]) -> List[Dict]:
        """Use AI to analyze and enhance attack paths"""
        if not paths:
            return paths
        
        # Prepare paths for AI analysis
        paths_summary = []
        for i, path in enumerate(paths[:20]):  # Analyze top 20 paths
            path_desc = {
                'path_id': i,
                'steps': [
                    {
                        'type': v['type'],
                        'severity': v['severity'],
                        'file': v['file']
                    }
                    for v in path['vulnerabilities']
                ]
            }
            paths_summary.append(path_desc)
        
        prompt = f"""Analyze these potential attack paths and provide insights:

{json.dumps(paths_summary, indent=2)}

For each path, assess:
1. Likelihood of successful exploitation
2. Potential impact if exploited
3. Difficulty for attacker
4. Detection difficulty
5. Business impact

Return JSON:
{{
  "path_analysis": [
    {{
      "path_id": 0,
      "exploitation_likelihood": "high|medium|low",
      "potential_impact": "critical|high|medium|low",
      "attacker_difficulty": "easy|moderate|hard",
      "detection_difficulty": "easy|moderate|hard",
      "business_impact": "description",
      "attack_narrative": "step by step description"
    }}
  ]
}}"""

        try:
            response = bedrock_runtime.invoke_model(
                modelId=MODEL_ID,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4000,
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
                ai_analysis = json.loads(json_match.group())
                
                # Merge AI insights with paths
                path_lookup = {a['path_id']: a for a in ai_analysis.get('path_analysis', [])}
                
                for i, path in enumerate(paths[:20]):
                    if i in path_lookup:
                        path['ai_analysis'] = path_lookup[i]
                        
        except Exception as e:
            logger.error(f"AI path analysis failed: {e}")
        
        return paths
    
    def _calculate_path_risks(self, paths: List[Dict], findings: List[Dict]) -> List[Dict]:
        """Calculate risk scores for each attack path"""
        for path in paths:
            risk_score = 0.0
            
            # Base score from path length (shorter = higher risk)
            risk_score += (1.0 / (path['length'] + 1)) * 0.2
            
            # Severity of vulnerabilities in path
            severity_scores = {'CRITICAL': 1.0, 'HIGH': 0.8, 'MEDIUM': 0.5, 'LOW': 0.3}
            avg_severity = sum(
                severity_scores.get(v['severity'], 0.5)
                for v in path['vulnerabilities']
            ) / len(path['vulnerabilities'])
            risk_score += avg_severity * 0.3
            
            # Business risk
            avg_business_risk = sum(
                v['business_risk'] for v in path['vulnerabilities']
            ) / len(path['vulnerabilities'])
            risk_score += avg_business_risk * 0.2
            
            # AI assessment if available
            if 'ai_analysis' in path:
                ai = path['ai_analysis']
                likelihood_map = {'high': 1.0, 'medium': 0.6, 'low': 0.3}
                impact_map = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.3}
                
                risk_score += likelihood_map.get(ai.get('exploitation_likelihood', 'medium'), 0.5) * 0.15
                risk_score += impact_map.get(ai.get('potential_impact', 'medium'), 0.5) * 0.15
            
            path['risk_score'] = min(risk_score, 1.0)
        
        # Sort by risk score
        paths.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return paths
    
    def _generate_remediation_priorities(self, paths: List[Dict]) -> List[Dict]:
        """Generate prioritized remediation recommendations"""
        
        # Count vulnerability occurrences across paths
        vuln_impact = defaultdict(lambda: {'count': 0, 'total_risk': 0.0, 'paths': []})
        
        for path in paths:
            for vuln in path['vulnerabilities']:
                vuln_id = vuln['finding_id']
                vuln_impact[vuln_id]['count'] += 1
                vuln_impact[vuln_id]['total_risk'] += path['risk_score']
                vuln_impact[vuln_id]['paths'].append(path)
                vuln_impact[vuln_id]['details'] = vuln
        
        # Calculate remediation priority
        priorities = []
        for vuln_id, impact in vuln_impact.items():
            priority_score = (
                impact['total_risk'] * 0.5 +  # Risk contribution
                (impact['count'] / len(paths)) * 0.3 +  # Frequency
                severity_scores.get(impact['details']['severity'], 0.5) * 0.2  # Severity
            )
            
            priorities.append({
                'finding_id': vuln_id,
                'priority_score': priority_score,
                'appears_in_paths': impact['count'],
                'total_risk_contribution': impact['total_risk'],
                'severity': impact['details']['severity'],
                'type': impact['details']['type'],
                'file': impact['details']['file'],
                'remediation_impact': f"Fixes {impact['count']} attack paths"
            })
        
        # Sort by priority
        priorities.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return priorities[:20]  # Top 20 priorities
    
    def _calculate_graph_metrics(self, G: nx.DiGraph) -> Dict[str, Any]:
        """Calculate graph metrics for the vulnerability network"""
        return {
            'total_nodes': G.number_of_nodes(),
            'total_edges': G.number_of_edges(),
            'density': nx.density(G),
            'is_connected': nx.is_weakly_connected(G),
            'number_of_components': nx.number_weakly_connected_components(G),
            'average_degree': sum(dict(G.degree()).values()) / G.number_of_nodes() if G.number_of_nodes() > 0 else 0
        }
    
    def _get_finding_summary(self, finding_id: str, findings: List[Dict]) -> Dict:
        """Get summary of a finding by ID"""
        for finding in findings:
            if finding.get('finding_id') == finding_id:
                return {
                    'finding_id': finding_id,
                    'type': finding.get('finding_type'),
                    'severity': finding.get('severity'),
                    'file': finding.get('file_path'),
                    'confidence': float(finding.get('confidence', 0.5)),
                    'business_risk': float(finding.get('business_risk_score', 0))
                }
        return {}
    
    def _save_results(self, scan_id: str, results: Dict[str, Any]):
        """Save attack path analysis results to S3"""
        try:
            s3_client.put_object(
                Bucket=RESULTS_BUCKET,
                Key=f"attack-paths/{scan_id}/analysis.json",
                Body=json.dumps(results, indent=2, default=str),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            
            # Also save a summary
            summary = {
                'scan_id': scan_id,
                'timestamp': results['analysis_timestamp'],
                'total_paths': results['attack_paths_found'],
                'critical_paths': results['critical_paths'],
                'top_entry_points': self._get_top_entry_points(results['attack_paths']),
                'top_targets': self._get_top_targets(results['attack_paths']),
                'remediation_summary': [
                    {
                        'finding_id': r['finding_id'],
                        'priority_score': r['priority_score'],
                        'impact': r['remediation_impact']
                    }
                    for r in results['remediation_priorities'][:5]
                ]
            }
            
            s3_client.put_object(
                Bucket=RESULTS_BUCKET,
                Key=f"attack-paths/{scan_id}/summary.json",
                Body=json.dumps(summary, indent=2),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    def _get_top_entry_points(self, paths: List[Dict]) -> List[Dict]:
        """Get most common entry points"""
        entry_count = defaultdict(int)
        entry_details = {}
        
        for path in paths:
            entry = path['entry_point']
            entry_count[entry] += 1
            if entry not in entry_details:
                entry_details[entry] = path['vulnerabilities'][0]
        
        top_entries = sorted(entry_count.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return [
            {
                'finding_id': entry,
                'count': count,
                'type': entry_details[entry]['type'],
                'file': entry_details[entry]['file']
            }
            for entry, count in top_entries
        ]
    
    def _get_top_targets(self, paths: List[Dict]) -> List[Dict]:
        """Get most common targets"""
        target_count = defaultdict(int)
        target_details = {}
        
        for path in paths:
            target = path['target']
            target_count[target] += 1
            if target not in target_details:
                target_details[target] = path['vulnerabilities'][-1]
        
        top_targets = sorted(target_count.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return [
            {
                'finding_id': target,
                'count': count,
                'type': target_details[target]['type'],
                'file': target_details[target]['file']
            }
            for target, count in top_targets
        ]


# Severity scores for priority calculation
severity_scores = {'CRITICAL': 1.0, 'HIGH': 0.8, 'MEDIUM': 0.5, 'LOW': 0.3}


def lambda_handler(event, context):
    """Lambda handler for attack path analysis"""
    
    analyzer = AttackPathAnalyzer()
    
    try:
        results = analyzer.analyze_attack_paths(event)
        
        return {
            'statusCode': 200,
            'body': json.dumps(results, default=str)
        }
        
    except Exception as e:
        logger.error(f"Attack path analysis failed: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'error': str(e)
        }