"""
Attack Path Visualization Lambda - Analyzes findings to identify and visualize attack paths
"""
import os
import json
import boto3
from typing import Dict, List, Any, Set, Tuple
from datetime import datetime
import hashlib
from collections import defaultdict, deque

s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')


class AttackPathAnalyzer:
    """Analyzes security findings to identify potential attack paths"""
    
    def __init__(self):
        self.findings_by_type = defaultdict(list)
        self.attack_paths = []
        self.kill_chains = []
        self.exploitability_scores = {}
        
        # MITRE ATT&CK mapping
        self.mitre_mapping = {
            'SECRETS_HARDCODED': ['T1552.001', 'T1078'],  # Unsecured Credentials, Valid Accounts
            'API_NO_AUTH_ENDPOINT': ['T1190'],  # Exploit Public-Facing Application
            'CONTAINER_PRIVILEGED': ['T1611', 'T1610'],  # Escape to Host, Deploy Container
            'K8S_WILDCARD_RBAC': ['T1078.001'],  # Valid Accounts: Default Accounts
            'IDOR_DIRECT_REFERENCE': ['T1548'],  # Abuse Elevation Control Mechanism
            'SAST_SQL_INJECTION': ['T1190'],  # Exploit Public-Facing Application
            'DEPENDENCY_VULNERABLE': ['T1195.001'],  # Supply Chain Compromise
            'IAC_SECURITY_GROUP_OPEN': ['T1133'],  # External Remote Services
        }
        
    def analyze(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze findings to identify attack paths"""
        # Group findings by type and file
        self._group_findings(findings)
        
        # Identify potential attack chains
        self._identify_attack_chains()
        
        # Calculate exploitability scores
        self._calculate_exploitability()
        
        # Build kill chain visualization
        self._build_kill_chains()
        
        # Create attack graph
        attack_graph = self._build_attack_graph()
        
        return {
            'attack_paths': self.attack_paths,
            'kill_chains': self.kill_chains,
            'attack_graph': attack_graph,
            'exploitability_scores': self.exploitability_scores,
            'risk_summary': self._calculate_risk_summary()
        }
    
    def _group_findings(self, findings: List[Dict[str, Any]]):
        """Group findings by vulnerability type and location"""
        for finding in findings:
            vuln_type = finding.get('vulnerability_type', 'UNKNOWN')
            self.findings_by_type[vuln_type].append(finding)
    
    def _identify_attack_chains(self):
        """Identify potential chains of vulnerabilities"""
        # Common attack patterns
        attack_patterns = [
            {
                'name': 'Credential Theft to Privilege Escalation',
                'chain': ['SECRETS_HARDCODED', 'API_NO_AUTH_ENDPOINT', 'CONTAINER_PRIVILEGED'],
                'description': 'Attacker finds hardcoded credentials, accesses unprotected API, gains privileged container access'
            },
            {
                'name': 'Supply Chain to Code Execution',
                'chain': ['DEPENDENCY_VULNERABLE', 'SAST_CODE_INJECTION', 'CONTAINER_ROOT_USER'],
                'description': 'Vulnerable dependency exploited to inject code running as root'
            },
            {
                'name': 'IDOR to Data Exfiltration',
                'chain': ['IDOR_DIRECT_REFERENCE', 'API_NO_AUTH_ENDPOINT', 'IAC_S3_PUBLIC'],
                'description': 'IDOR vulnerability allows access to sensitive data stored in public S3'
            },
            {
                'name': 'Container Escape to Cloud Takeover',
                'chain': ['CONTAINER_PRIVILEGED', 'K8S_WILDCARD_RBAC', 'IAC_OVERLY_PERMISSIVE'],
                'description': 'Privileged container escape leads to Kubernetes cluster compromise'
            }
        ]
        
        for pattern in attack_patterns:
            # Check if we have findings matching this pattern
            matching_findings = []
            for vuln_type in pattern['chain']:
                if vuln_type in self.findings_by_type:
                    matching_findings.append({
                        'type': vuln_type,
                        'findings': self.findings_by_type[vuln_type][:3]  # Limit to 3 examples
                    })
            
            if len(matching_findings) >= 2:  # At least 2 steps in the chain found
                self.attack_paths.append({
                    'path_id': hashlib.md5(pattern['name'].encode()).hexdigest()[:8],
                    'name': pattern['name'],
                    'description': pattern['description'],
                    'steps': matching_findings,
                    'likelihood': self._calculate_likelihood(matching_findings),
                    'impact': self._calculate_impact(pattern['chain'])
                })
    
    def _calculate_exploitability(self):
        """Calculate exploitability scores for each vulnerability type"""
        # CVSS-like scoring
        base_scores = {
            'CRITICAL': 9.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5,
            'INFO': 0.5
        }
        
        for vuln_type, findings in self.findings_by_type.items():
            if findings:
                # Calculate average severity
                severities = [f.get('severity', 'MEDIUM') for f in findings]
                avg_score = sum(base_scores.get(s, 5.0) for s in severities) / len(severities)
                
                # Adjust based on confidence
                confidences = [f.get('confidence', 'MEDIUM') for f in findings]
                confidence_multiplier = {
                    'HIGH': 1.0,
                    'MEDIUM': 0.8,
                    'LOW': 0.6
                }
                avg_confidence = sum(confidence_multiplier.get(c, 0.8) for c in confidences) / len(confidences)
                
                # Adjust based on occurrence count
                occurrence_factor = min(1.0 + (len(findings) * 0.1), 2.0)  # Cap at 2x
                
                self.exploitability_scores[vuln_type] = round(avg_score * avg_confidence * occurrence_factor, 2)
    
    def _build_kill_chains(self):
        """Build MITRE ATT&CK kill chain visualization"""
        # Group findings by MITRE tactics
        tactics_order = [
            'Initial Access',
            'Execution',
            'Persistence',
            'Privilege Escalation',
            'Defense Evasion',
            'Credential Access',
            'Discovery',
            'Lateral Movement',
            'Collection',
            'Exfiltration',
            'Impact'
        ]
        
        tactic_mapping = {
            'T1190': 'Initial Access',  # Exploit Public-Facing Application
            'T1195.001': 'Initial Access',  # Supply Chain Compromise
            'T1133': 'Initial Access',  # External Remote Services
            'T1078': 'Persistence',  # Valid Accounts
            'T1078.001': 'Persistence',  # Valid Accounts: Default Accounts
            'T1548': 'Privilege Escalation',  # Abuse Elevation Control Mechanism
            'T1611': 'Privilege Escalation',  # Escape to Host
            'T1610': 'Defense Evasion',  # Deploy Container
            'T1552.001': 'Credential Access',  # Unsecured Credentials
        }
        
        kill_chain_steps = defaultdict(list)
        
        for vuln_type, findings in self.findings_by_type.items():
            if vuln_type in self.mitre_mapping:
                for technique in self.mitre_mapping[vuln_type]:
                    if technique in tactic_mapping:
                        tactic = tactic_mapping[technique]
                        kill_chain_steps[tactic].append({
                            'technique': technique,
                            'vulnerability': vuln_type,
                            'count': len(findings),
                            'severity': findings[0].get('severity', 'MEDIUM') if findings else 'MEDIUM'
                        })
        
        # Build ordered kill chain
        for tactic in tactics_order:
            if tactic in kill_chain_steps:
                self.kill_chains.append({
                    'tactic': tactic,
                    'techniques': kill_chain_steps[tactic]
                })
    
    def _build_attack_graph(self) -> Dict[str, Any]:
        """Build a graph representation of attack paths"""
        nodes = []
        edges = []
        node_map = {}
        
        # Create nodes for each vulnerability type
        for i, (vuln_type, findings) in enumerate(self.findings_by_type.items()):
            node_id = f"node_{i}"
            node_map[vuln_type] = node_id
            nodes.append({
                'id': node_id,
                'label': vuln_type,
                'type': 'vulnerability',
                'count': len(findings),
                'exploitability': self.exploitability_scores.get(vuln_type, 0),
                'findings': [f['finding_id'] for f in findings[:5]]  # Sample finding IDs
            })
        
        # Create edges based on attack paths
        for path in self.attack_paths:
            steps = path['steps']
            for i in range(len(steps) - 1):
                source_type = steps[i]['type']
                target_type = steps[i + 1]['type']
                
                if source_type in node_map and target_type in node_map:
                    edges.append({
                        'source': node_map[source_type],
                        'target': node_map[target_type],
                        'label': path['name'],
                        'likelihood': path['likelihood']
                    })
        
        # Add impact nodes
        impact_types = ['data_breach', 'service_disruption', 'privilege_escalation', 'lateral_movement']
        for impact in impact_types:
            impact_node_id = f"impact_{impact}"
            nodes.append({
                'id': impact_node_id,
                'label': impact.replace('_', ' ').title(),
                'type': 'impact'
            })
            
            # Connect high-risk vulnerabilities to impacts
            for vuln_type, score in self.exploitability_scores.items():
                if score > 7.0 and vuln_type in node_map:
                    if (impact == 'data_breach' and 'IDOR' in vuln_type) or \
                       (impact == 'privilege_escalation' and 'PRIVILEGE' in vuln_type) or \
                       (impact == 'service_disruption' and 'DOS' in vuln_type):
                        edges.append({
                            'source': node_map[vuln_type],
                            'target': impact_node_id,
                            'label': 'leads to',
                            'likelihood': 'high'
                        })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'metadata': {
                'total_vulnerabilities': len(self.findings_by_type),
                'total_paths': len(self.attack_paths),
                'highest_risk_path': max(self.attack_paths, key=lambda p: p['likelihood'])['name'] if self.attack_paths else None
            }
        }
    
    def _calculate_likelihood(self, matching_findings: List[Dict]) -> str:
        """Calculate likelihood of attack path exploitation"""
        # Simple heuristic based on number of findings and their severity
        total_findings = sum(len(mf['findings']) for mf in matching_findings)
        
        if total_findings > 10:
            return 'very_high'
        elif total_findings > 5:
            return 'high'
        elif total_findings > 2:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_impact(self, chain: List[str]) -> str:
        """Calculate potential impact of attack chain"""
        high_impact_vulns = ['CONTAINER_PRIVILEGED', 'K8S_WILDCARD_RBAC', 'SECRETS_HARDCODED', 'DATA_EXPOSURE']
        
        if any(vuln in chain for vuln in high_impact_vulns):
            return 'critical'
        elif len(chain) > 3:
            return 'high'
        else:
            return 'medium'
    
    def _calculate_risk_summary(self) -> Dict[str, Any]:
        """Calculate overall risk summary"""
        total_exploitability = sum(self.exploitability_scores.values())
        avg_exploitability = total_exploitability / len(self.exploitability_scores) if self.exploitability_scores else 0
        
        risk_level = 'critical' if avg_exploitability > 8 else \
                     'high' if avg_exploitability > 6 else \
                     'medium' if avg_exploitability > 4 else 'low'
        
        return {
            'overall_risk_level': risk_level,
            'average_exploitability': round(avg_exploitability, 2),
            'total_attack_paths': len(self.attack_paths),
            'high_risk_paths': len([p for p in self.attack_paths if p['likelihood'] in ['high', 'very_high']]),
            'recommendations': self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Check for critical patterns
        if 'CONTAINER_PRIVILEGED' in self.findings_by_type:
            recommendations.append("Remove privileged container configurations immediately")
        
        if 'SECRETS_HARDCODED' in self.findings_by_type:
            recommendations.append("Rotate all hardcoded secrets and implement proper secret management")
        
        if 'API_NO_AUTH_ENDPOINT' in self.findings_by_type:
            recommendations.append("Implement authentication on all API endpoints")
        
        if len(self.attack_paths) > 5:
            recommendations.append("Multiple attack paths detected - implement defense in depth strategy")
        
        return recommendations[:5]  # Top 5 recommendations


def lambda_handler(event, context):
    """Lambda handler for attack path visualization"""
    try:
        scan_id = event['scan_id']
        results_bucket = os.environ.get('RESULTS_BUCKET')
        
        # Load aggregated findings
        aggregated_path = f"processed/{scan_id}/aggregated_findings.json"
        response = s3_client.get_object(Bucket=results_bucket, Key=aggregated_path)
        aggregated_data = json.loads(response['Body'].read())
        
        findings = aggregated_data.get('findings', [])
        
        # Analyze attack paths
        analyzer = AttackPathAnalyzer()
        attack_analysis = analyzer.analyze(findings)
        
        # Add metadata
        attack_analysis['metadata'] = {
            'scan_id': scan_id,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'total_findings_analyzed': len(findings),
            'mitre_techniques_identified': len(set(sum(analyzer.mitre_mapping.values(), [])))
        }
        
        # Store results
        output_path = f"processed/{scan_id}/attack_paths.json"
        s3_client.put_object(
            Bucket=results_bucket,
            Key=output_path,
            Body=json.dumps(attack_analysis, indent=2),
            ContentType='application/json'
        )
        
        # Create visualization data for QuickSight
        quicksight_data = {
            'scan_id': scan_id,
            'timestamp': datetime.utcnow().isoformat(),
            'risk_level': attack_analysis['risk_summary']['overall_risk_level'],
            'total_paths': attack_analysis['risk_summary']['total_attack_paths'],
            'exploitability_scores': attack_analysis['exploitability_scores']
        }
        
        quicksight_path = f"quicksight-data/{scan_id}/attack_visualization.json"
        s3_client.put_object(
            Bucket=results_bucket,
            Key=quicksight_path,
            Body=json.dumps(quicksight_data),
            ContentType='application/json'
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Attack path analysis completed',
                'scan_id': scan_id,
                'attack_paths_found': len(attack_analysis['attack_paths']),
                'risk_level': attack_analysis['risk_summary']['overall_risk_level'],
                'output_path': f"s3://{results_bucket}/{output_path}"
            })
        }
        
    except Exception as e:
        print(f"Error in attack path analysis: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }


if __name__ == "__main__":
    # For testing
    test_event = {
        'scan_id': 'test-scan-123'
    }
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))