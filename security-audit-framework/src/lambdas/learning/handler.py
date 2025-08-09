"""
Learning from Results Lambda - Analyzes historical scan data to improve future scans
"""
import os
import json
import boto3
from typing import Dict, List, Any, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib

s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
athena_client = boto3.client('athena')


class LearningEngine:
    """Machine learning-inspired engine for improving scan effectiveness"""
    
    def __init__(self):
        self.scan_table = dynamodb.Table(os.environ.get('SCAN_TABLE', 'SecurityScans'))
        self.learning_table = dynamodb.Table(os.environ.get('LEARNING_TABLE', 'SecurityLearning'))
        self.results_bucket = os.environ.get('RESULTS_BUCKET')
        
        # Learning patterns storage
        self.false_positive_patterns = []
        self.high_value_patterns = []
        self.scan_performance_metrics = {}
        
    def learn_from_scan(self, scan_id: str) -> Dict[str, Any]:
        """Analyze a completed scan to extract learnings"""
        # Load scan metadata
        scan_metadata = self._load_scan_metadata(scan_id)
        
        # Load findings
        findings = self._load_scan_findings(scan_id)
        
        # Load feedback if available
        feedback = self._load_feedback(scan_id)
        
        # Extract learnings
        learnings = {
            'scan_id': scan_id,
            'timestamp': datetime.utcnow().isoformat(),
            'patterns': self._extract_patterns(findings, feedback),
            'performance': self._analyze_performance(scan_metadata),
            'effectiveness': self._calculate_effectiveness(findings, feedback),
            'recommendations': self._generate_recommendations(findings, scan_metadata)
        }
        
        # Store learnings
        self._store_learnings(scan_id, learnings)
        
        # Update global learning model
        self._update_global_model(learnings)
        
        return learnings
    
    def _extract_patterns(self, findings: List[Dict[str, Any]], 
                         feedback: Dict[str, Any]) -> Dict[str, Any]:
        """Extract patterns from findings and feedback"""
        patterns = {
            'false_positives': [],
            'true_positives': [],
            'severity_accuracy': {},
            'tool_effectiveness': defaultdict(dict)
        }
        
        # Process feedback on findings
        if feedback and 'finding_feedback' in feedback:
            for finding_id, fb in feedback['finding_feedback'].items():
                finding = next((f for f in findings if f.get('finding_id') == finding_id), None)
                if finding:
                    if fb.get('is_false_positive'):
                        patterns['false_positives'].append({
                            'type': finding.get('vulnerability_type'),
                            'pattern': self._extract_finding_pattern(finding),
                            'tool': finding.get('type', 'UNKNOWN')
                        })
                    else:
                        patterns['true_positives'].append({
                            'type': finding.get('vulnerability_type'),
                            'severity': finding.get('severity'),
                            'confidence': finding.get('confidence')
                        })
                    
                    # Track severity accuracy
                    if fb.get('actual_severity'):
                        reported = finding.get('severity', 'MEDIUM')
                        actual = fb['actual_severity']
                        key = f"{reported}_to_{actual}"
                        patterns['severity_accuracy'][key] = \
                            patterns['severity_accuracy'].get(key, 0) + 1
        
        # Analyze tool effectiveness
        for finding in findings:
            tool = finding.get('type', 'UNKNOWN')
            severity = finding.get('severity', 'MEDIUM')
            patterns['tool_effectiveness'][tool][severity] = \
                patterns['tool_effectiveness'][tool].get(severity, 0) + 1
        
        return patterns
    
    def _extract_finding_pattern(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Extract pattern features from a finding"""
        return {
            'file_extension': os.path.splitext(finding.get('file_path', ''))[1],
            'code_pattern': self._normalize_code_pattern(finding.get('code_snippet', '')),
            'message_keywords': self._extract_keywords(finding.get('message', '')),
            'line_context': finding.get('start_line', 0) // 100  # Rough position in file
        }
    
    def _normalize_code_pattern(self, code: str) -> str:
        """Normalize code pattern for comparison"""
        # Simple normalization - in production, use AST
        normalized = code.lower()
        # Replace variable names with placeholders
        import re
        normalized = re.sub(r'\b[a-z_][a-z0-9_]*\b', 'VAR', normalized)
        normalized = re.sub(r'\b\d+\b', 'NUM', normalized)
        normalized = re.sub(r'[\'"].*?[\'"]', 'STR', normalized)
        return normalized[:100]  # Truncate
    
    def _extract_keywords(self, message: str) -> List[str]:
        """Extract keywords from finding message"""
        stop_words = {'the', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'of', 'with'}
        words = message.lower().split()
        return [w for w in words if len(w) > 3 and w not in stop_words][:5]
    
    def _analyze_performance(self, scan_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan performance metrics"""
        execution_plan = scan_metadata.get('execution_plan', {})
        
        performance = {
            'total_duration': scan_metadata.get('duration_seconds', 0),
            'total_cost': execution_plan.get('total_estimated_cost', 0),
            'agents_used': len(execution_plan.get('tasks', [])),
            'cost_per_finding': 0,
            'scan_efficiency': 0
        }
        
        # Calculate cost per finding
        total_findings = scan_metadata.get('total_findings', 0)
        if total_findings > 0:
            performance['cost_per_finding'] = performance['total_cost'] / total_findings
            performance['scan_efficiency'] = total_findings / max(performance['total_duration'], 1)
        
        return performance
    
    def _calculate_effectiveness(self, findings: List[Dict[str, Any]], 
                               feedback: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate scan effectiveness metrics"""
        total_findings = len(findings)
        
        effectiveness = {
            'total_findings': total_findings,
            'true_positive_rate': 0,
            'false_positive_rate': 0,
            'severity_distribution': defaultdict(int),
            'confidence_accuracy': 0
        }
        
        if feedback and 'finding_feedback' in feedback:
            false_positives = sum(1 for fb in feedback['finding_feedback'].values() 
                                if fb.get('is_false_positive'))
            true_positives = total_findings - false_positives
            
            effectiveness['true_positive_rate'] = true_positives / total_findings if total_findings > 0 else 0
            effectiveness['false_positive_rate'] = false_positives / total_findings if total_findings > 0 else 0
        
        # Severity distribution
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM')
            effectiveness['severity_distribution'][severity] += 1
        
        return effectiveness
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]], 
                                 scan_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations for future scans"""
        recommendations = []
        
        # Analyze finding patterns
        vuln_types = defaultdict(int)
        file_types = defaultdict(int)
        
        for finding in findings:
            vuln_types[finding.get('vulnerability_type', 'UNKNOWN')] += 1
            file_ext = os.path.splitext(finding.get('file_path', ''))[1]
            if file_ext:
                file_types[file_ext] += 1
        
        # Recommend focused agents
        if vuln_types['API_NO_AUTH_ENDPOINT'] > 5:
            recommendations.append({
                'type': 'agent_focus',
                'agent': 'API_SECURITY',
                'reason': 'High number of API authentication issues detected',
                'priority': 'high'
            })
        
        if vuln_types['CONTAINER_ROOT_USER'] > 0:
            recommendations.append({
                'type': 'agent_addition',
                'agent': 'CONTAINER_SECURITY',
                'config': {'deep_scan': True},
                'reason': 'Container security issues require deeper analysis'
            })
        
        # Recommend scan optimization
        cost_per_finding = scan_metadata.get('cost_per_finding', 0)
        if cost_per_finding > 0.50:  # $0.50 per finding threshold
            recommendations.append({
                'type': 'optimization',
                'suggestion': 'Consider using Sub-CEO prioritization for large repositories',
                'reason': f'High cost per finding: ${cost_per_finding:.2f}'
            })
        
        # File type specific recommendations
        if file_types.get('.yaml', 0) + file_types.get('.yml', 0) > 10:
            recommendations.append({
                'type': 'agent_focus',
                'agent': 'IAC',
                'reason': 'Large number of YAML files suggest IaC focus needed'
            })
        
        return recommendations
    
    def _update_global_model(self, learnings: Dict[str, Any]):
        """Update global learning model with new insights"""
        try:
            # Store patterns for false positive detection
            for fp_pattern in learnings['patterns']['false_positives']:
                pattern_hash = hashlib.md5(
                    json.dumps(fp_pattern, sort_keys=True).encode()
                ).hexdigest()
                
                self.learning_table.put_item(
                    Item={
                        'pattern_id': pattern_hash,
                        'pattern_type': 'false_positive',
                        'pattern_data': fp_pattern,
                        'occurrence_count': 1,
                        'last_seen': datetime.utcnow().isoformat(),
                        'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())
                    }
                )
            
            # Store performance benchmarks
            scan_type = learnings.get('scan_type', 'standard')
            self.learning_table.put_item(
                Item={
                    'pattern_id': f"performance_{scan_type}_{datetime.utcnow().strftime('%Y%m%d')}",
                    'pattern_type': 'performance',
                    'metrics': learnings['performance'],
                    'timestamp': datetime.utcnow().isoformat(),
                    'ttl': int((datetime.utcnow() + timedelta(days=30)).timestamp())
                }
            )
            
        except Exception as e:
            print(f"Error updating global model: {e}")
    
    def get_scan_recommendations(self, repo_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Get recommendations for a new scan based on historical learnings"""
        recommendations = {
            'agent_config': {},
            'scan_optimizations': [],
            'expected_patterns': []
        }
        
        # Query historical patterns for similar repositories
        similar_patterns = self._find_similar_scan_patterns(repo_analysis)
        
        # Configure agents based on learnings
        if similar_patterns:
            # Adjust agent priorities
            common_vulns = defaultdict(int)
            for pattern in similar_patterns:
                for vuln_type in pattern.get('vulnerability_types', []):
                    common_vulns[vuln_type] += 1
            
            # Recommend agent configurations
            if common_vulns.get('API_NO_AUTH_ENDPOINT', 0) > 3:
                recommendations['agent_config']['API_SECURITY'] = {
                    'priority': 'high',
                    'config': {'deep_scan': True}
                }
            
            if common_vulns.get('SECRETS_HARDCODED', 0) > 5:
                recommendations['agent_config']['SECRETS'] = {
                    'priority': 'critical',
                    'config': {'extended_patterns': True}
                }
        
        # Add optimization recommendations
        repo_size = repo_analysis.get('total_lines', 0)
        if repo_size > 100000:
            recommendations['scan_optimizations'].append({
                'type': 'use_sub_ceo',
                'reason': 'Large repository - use Sub-CEO for file prioritization'
            })
        
        # Add expected patterns
        language_dist = repo_analysis.get('languages', {})
        if 'Python' in language_dist:
            recommendations['expected_patterns'].append({
                'type': 'SAST_PYTHON_SPECIFIC',
                'likelihood': 'high'
            })
        
        return recommendations
    
    def _find_similar_scan_patterns(self, repo_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find patterns from similar repository scans using Athena"""
        try:
            # Extract repository characteristics
            language = repo_analysis.get('primary_language', 'unknown')
            repo_size = repo_analysis.get('total_lines', 0)
            frameworks = repo_analysis.get('frameworks', [])
            
            # Build similarity query
            query = f"""
            SELECT
                scan_id,
                repository_url,
                repository_analysis,
                finding_patterns,
                performance_metrics,
                scan_date,
                CAST(
                    (CASE
                        WHEN JSON_EXTRACT_SCALAR(repository_analysis, '$.primary_language') = '{language}' THEN 0.3
                        ELSE 0
                    END) +
                    (CASE
                        WHEN ABS(CAST(JSON_EXTRACT_SCALAR(repository_analysis, '$.total_lines') AS DOUBLE) - {repo_size}) < 5000 THEN 0.2
                        ELSE 0
                    END) +
                    (CASE
                        WHEN CARDINALITY(ARRAY_INTERSECT(
                            CAST(JSON_EXTRACT(repository_analysis, '$.frameworks') AS ARRAY<VARCHAR>),
                            ARRAY{frameworks}
                        )) > 0 THEN 0.5
                        ELSE 0
                    END) AS DOUBLE
                ) AS similarity_score
            FROM security_scans
            WHERE scan_date >= CURRENT_DATE - INTERVAL '90' DAY
                AND repository_url != '{repo_analysis.get('repository_url', '')}'
            ORDER BY similarity_score DESC
            LIMIT 10
            """
            
            # Execute query
            query_id = self.athena.start_query_execution(
                QueryString=query,
                QueryExecutionContext={'Database': self.database_name},
                ResultConfiguration={'OutputLocation': f's3://{os.environ["FINDINGS_BUCKET"]}/athena-results/'}
            )['QueryExecutionId']
            
            # Wait for query completion
            max_wait = 30  # seconds
            start_time = time.time()
            while time.time() - start_time < max_wait:
                status = self.athena.get_query_execution(QueryExecutionId=query_id)
                state = status['QueryExecution']['Status']['State']
                
                if state == 'SUCCEEDED':
                    # Get results
                    results = self.athena.get_query_results(QueryExecutionId=query_id)
                    
                    similar_patterns = []
                    for row in results['ResultSet']['Rows'][1:]:  # Skip header
                        data = row['Data']
                        if len(data) >= 7:
                            scan_data = {
                                'scan_id': data[0].get('VarCharValue', ''),
                                'repository_url': data[1].get('VarCharValue', ''),
                                'repository_analysis': json.loads(data[2].get('VarCharValue', '{}')),
                                'finding_patterns': json.loads(data[3].get('VarCharValue', '[]')),
                                'performance_metrics': json.loads(data[4].get('VarCharValue', '{}')),
                                'scan_date': data[5].get('VarCharValue', ''),
                                'similarity_score': float(data[6].get('VarCharValue', '0'))
                            }
                            if scan_data['similarity_score'] > 0.3:  # Minimum similarity threshold
                                similar_patterns.append(scan_data)
                    
                    return similar_patterns
                    
                elif state in ['FAILED', 'CANCELLED']:
                    logger.error(f"Query failed: {status['QueryExecution']['Status'].get('StateChangeReason', 'Unknown')}")
                    break
                    
                time.sleep(1)
            
            logger.warning("Query timeout - returning empty results")
            return []
            
        except Exception as e:
            logger.error(f"Error finding similar patterns: {e}")
            # Fallback to basic pattern matching if Athena fails
            return self._fallback_pattern_matching(repo_analysis)
    
    def _fallback_pattern_matching(self, repo_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fallback pattern matching when Athena is unavailable"""
        # Return common patterns based on language/framework
        language = repo_analysis.get('primary_language', 'unknown').lower()
        
        common_patterns = {
            'python': [
                {
                    'pattern_type': 'sql_injection',
                    'detection_rate': 0.15,
                    'false_positive_rate': 0.05,
                    'recommended_rules': ['python.lang.security.audit.sqli.flask-mysql-sqli']
                },
                {
                    'pattern_type': 'hardcoded_secrets',
                    'detection_rate': 0.20,
                    'false_positive_rate': 0.10,
                    'recommended_rules': ['generic.secrets.security.detected-aws-key']
                }
            ],
            'javascript': [
                {
                    'pattern_type': 'xss',
                    'detection_rate': 0.25,
                    'false_positive_rate': 0.08,
                    'recommended_rules': ['javascript.lang.security.detect-non-literal-regexp']
                },
                {
                    'pattern_type': 'insecure_dependencies',
                    'detection_rate': 0.30,
                    'false_positive_rate': 0.02,
                    'recommended_rules': ['dependency-check']
                }
            ],
            'java': [
                {
                    'pattern_type': 'deserialization',
                    'detection_rate': 0.10,
                    'false_positive_rate': 0.03,
                    'recommended_rules': ['java.lang.security.audit.unsafe-deserialization']
                },
                {
                    'pattern_type': 'weak_crypto',
                    'detection_rate': 0.12,
                    'false_positive_rate': 0.05,
                    'recommended_rules': ['java.lang.security.audit.crypto.weak-hash']
                }
            ]
        }
        
        return [{
            'scan_id': 'fallback',
            'repository_url': 'common_patterns',
            'finding_patterns': common_patterns.get(language, []),
            'similarity_score': 0.5
        }]
    
    def _load_scan_metadata(self, scan_id: str) -> Dict[str, Any]:
        """Load scan metadata from DynamoDB"""
        try:
            response = self.scan_table.get_item(Key={'scan_id': scan_id})
            return response.get('Item', {})
        except Exception as e:
            print(f"Error loading scan metadata: {e}")
            return {}
    
    def _load_scan_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Load aggregated findings from S3"""
        try:
            key = f"processed/{scan_id}/aggregated_findings.json"
            response = s3_client.get_object(Bucket=self.results_bucket, Key=key)
            data = json.loads(response['Body'].read())
            return data.get('findings', [])
        except Exception as e:
            print(f"Error loading findings: {e}")
            return []
    
    def _load_feedback(self, scan_id: str) -> Dict[str, Any]:
        """Load user feedback on scan results"""
        try:
            # Check if feedback exists
            key = f"feedback/{scan_id}/user_feedback.json"
            response = s3_client.get_object(Bucket=self.results_bucket, Key=key)
            return json.loads(response['Body'].read())
        except:
            # No feedback available
            return {}
    
    def _store_learnings(self, scan_id: str, learnings: Dict[str, Any]):
        """Store learnings in S3 and DynamoDB"""
        try:
            # Store detailed learnings in S3
            key = f"learnings/{scan_id}/scan_learnings.json"
            s3_client.put_object(
                Bucket=self.results_bucket,
                Key=key,
                Body=json.dumps(learnings, indent=2),
                ContentType='application/json'
            )
            
            # Store summary in DynamoDB for quick access
            self.learning_table.put_item(
                Item={
                    'pattern_id': f"scan_{scan_id}",
                    'pattern_type': 'scan_learning',
                    'scan_id': scan_id,
                    'effectiveness': learnings['effectiveness'],
                    'performance': learnings['performance'],
                    'recommendation_count': len(learnings['recommendations']),
                    'timestamp': learnings['timestamp'],
                    'ttl': int((datetime.utcnow() + timedelta(days=365)).timestamp())
                }
            )
        except Exception as e:
            print(f"Error storing learnings: {e}")


def lambda_handler(event, context):
    """Lambda handler for learning from results"""
    try:
        action = event.get('action', 'learn')
        
        engine = LearningEngine()
        
        if action == 'learn':
            # Learn from completed scan
            scan_id = event['scan_id']
            learnings = engine.learn_from_scan(scan_id)
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Learning completed',
                    'scan_id': scan_id,
                    'patterns_found': len(learnings['patterns']['false_positives']) + 
                                    len(learnings['patterns']['true_positives']),
                    'recommendations': len(learnings['recommendations'])
                })
            }
            
        elif action == 'recommend':
            # Get recommendations for new scan
            repo_analysis = event['repo_analysis']
            recommendations = engine.get_scan_recommendations(repo_analysis)
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Recommendations generated',
                    'recommendations': recommendations
                })
            }
            
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': f'Unknown action: {action}'
                })
            }
            
    except Exception as e:
        print(f"Error in learning engine: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }