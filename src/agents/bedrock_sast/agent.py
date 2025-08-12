"""
Bedrock-powered SAST Agent - Fully AI-based security analysis
"""
import os
import json
import boto3
from typing import Dict, List, Any
from datetime import datetime
import base64

# Initialize Bedrock client
bedrock_runtime = boto3.client('bedrock-runtime', region_name='us-east-1')
s3_client = boto3.client('s3')


class BedrockSASTAgent:
    """AI-powered SAST agent using AWS Bedrock foundation models"""
    
    def __init__(self):
        self.model_id = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-sonnet-20240229-v1:0')
        self.results_bucket = os.environ.get('RESULTS_BUCKET')
        
    def scan(self, repository_path: str, scan_id: str) -> Dict[str, Any]:
        """Perform AI-based security scan using Bedrock"""
        findings = []
        
        # Process repository files
        for root, dirs, files in os.walk(repository_path):
            for file in files:
                if self._should_scan_file(file):
                    file_path = os.path.join(root, file)
                    file_findings = self._analyze_file_with_ai(file_path, repository_path)
                    findings.extend(file_findings)
        
        # AI-based aggregation and deduplication
        aggregated_findings = self._ai_aggregate_findings(findings)
        
        # Generate attack paths using AI
        attack_paths = self._generate_attack_paths(aggregated_findings)
        
        return {
            'scan_id': scan_id,
            'agent_type': 'BEDROCK_SAST',
            'timestamp': datetime.utcnow().isoformat(),
            'findings': aggregated_findings,
            'attack_paths': attack_paths,
            'ai_confidence': self._calculate_confidence(aggregated_findings)
        }
    
    def _analyze_file_with_ai(self, file_path: str, repo_root: str) -> List[Dict[str, Any]]:
        """Use Bedrock to analyze file for security vulnerabilities"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code_content = f.read()
            
            # Skip very large files
            if len(code_content) > 100000:  # 100KB limit per file
                code_content = code_content[:100000]
            
            relative_path = os.path.relpath(file_path, repo_root)
            
            # Construct prompt for security analysis
            prompt = f"""You are an expert security researcher analyzing code for vulnerabilities.

Analyze the following code file for security vulnerabilities:

File: {relative_path}
```
{code_content}
```

Identify ALL security vulnerabilities including but not limited to:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Authentication/Authorization issues
- Cryptographic weaknesses
- Buffer overflows
- Race conditions
- Information disclosure
- Business logic flaws

For each vulnerability found, provide:
1. Vulnerability type
2. Severity (CRITICAL/HIGH/MEDIUM/LOW)
3. Exact line number(s)
4. Vulnerable code snippet
5. Explanation of the vulnerability
6. Exploitation scenario
7. Remediation suggestion
8. CWE ID if applicable

Format your response as a JSON array of findings. If no vulnerabilities are found, return an empty array.

Important: Be thorough and precise. False negatives are worse than false positives."""

            # Call Bedrock
            response = bedrock_runtime.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4096,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.1,  # Low temperature for consistent results
                    "top_p": 0.9
                })
            )
            
            response_body = json.loads(response['body'].read())
            ai_response = response_body.get('content', [{}])[0].get('text', '[]')
            
            # Parse AI response
            try:
                findings_data = json.loads(ai_response)
                if not isinstance(findings_data, list):
                    findings_data = []
            except json.JSONDecodeError:
                # Try to extract JSON from response
                import re
                json_match = re.search(r'\[[\s\S]*\]', ai_response)
                if json_match:
                    try:
                        findings_data = json.loads(json_match.group())
                    except:
                        findings_data = []
                else:
                    findings_data = []
            
            # Format findings
            findings = []
            for finding in findings_data:
                findings.append({
                    'finding_id': self._generate_finding_id(file_path, finding),
                    'file_path': relative_path,
                    'vulnerability_type': finding.get('vulnerability_type', 'UNKNOWN'),
                    'severity': finding.get('severity', 'MEDIUM'),
                    'line_number': finding.get('line_number', 0),
                    'code_snippet': finding.get('code_snippet', ''),
                    'description': finding.get('explanation', ''),
                    'exploitation': finding.get('exploitation_scenario', ''),
                    'remediation': finding.get('remediation_suggestion', ''),
                    'cwe_id': finding.get('cwe_id', ''),
                    'ai_confidence': 0.95,  # High confidence for Bedrock
                    'detection_method': 'AI_BEDROCK'
                })
            
            return findings
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {str(e)}")
            return []
    
    def _ai_aggregate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use AI to aggregate and deduplicate findings"""
        if not findings:
            return []
        
        # Group similar findings
        findings_json = json.dumps(findings[:100])  # Limit for token size
        
        prompt = f"""You are a security expert reviewing scan results.

Given these security findings, perform the following tasks:
1. Identify and merge duplicate findings
2. Group related findings that form attack chains
3. Adjust severity based on exploitability and context
4. Remove false positives based on context

Findings:
{findings_json}

Return a JSON array of aggregated findings with duplicates removed and severities adjusted based on real exploitability."""

        try:
            response = bedrock_runtime.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4096,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.1
                })
            )
            
            response_body = json.loads(response['body'].read())
            ai_response = response_body.get('content', [{}])[0].get('text', '[]')
            
            aggregated = json.loads(ai_response)
            return aggregated if isinstance(aggregated, list) else findings
            
        except Exception as e:
            print(f"Aggregation error: {str(e)}")
            return findings
    
    def _generate_attack_paths(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use AI to generate attack paths from findings"""
        if not findings:
            return []
        
        findings_summary = []
        for f in findings[:20]:  # Limit for prompt size
            findings_summary.append({
                'type': f.get('vulnerability_type'),
                'severity': f.get('severity'),
                'file': f.get('file_path')
            })
        
        prompt = f"""As a security expert, analyze these vulnerabilities and identify potential attack paths.

Vulnerabilities found:
{json.dumps(findings_summary, indent=2)}

Create realistic attack scenarios showing how an attacker could chain these vulnerabilities together.
For each attack path, provide:
1. Attack name
2. Steps in order
3. Vulnerabilities exploited at each step
4. Overall impact
5. Likelihood of success

Format as JSON array of attack paths."""

        try:
            response = bedrock_runtime.invoke_model(
                modelId=self.model_id,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 2048,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.3
                })
            )
            
            response_body = json.loads(response['body'].read())
            ai_response = response_body.get('content', [{}])[0].get('text', '[]')
            
            attack_paths = json.loads(ai_response)
            return attack_paths if isinstance(attack_paths, list) else []
            
        except Exception as e:
            print(f"Attack path generation error: {str(e)}")
            return []
    
    def _should_scan_file(self, filename: str) -> bool:
        """Determine if file should be scanned"""
        # AI can analyze any text file
        extensions = {'.py', '.js', '.java', '.cs', '.go', '.rb', '.php', '.c', '.cpp', 
                     '.h', '.hpp', '.ts', '.jsx', '.tsx', '.vue', '.swift', '.kt', '.rs',
                     '.sol', '.vy', '.yaml', '.yml', '.json', '.xml', '.conf', '.ini'}
        return any(filename.endswith(ext) for ext in extensions)
    
    def _generate_finding_id(self, file_path: str, finding: Dict[str, Any]) -> str:
        """Generate unique finding ID"""
        import hashlib
        content = f"{file_path}{finding.get('vulnerability_type', '')}{finding.get('line_number', 0)}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]
    
    def _calculate_confidence(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall confidence score"""
        if not findings:
            return 1.0
        
        # Bedrock provides high confidence results
        total_confidence = sum(f.get('ai_confidence', 0.95) for f in findings)
        return total_confidence / len(findings)


def handler(event, context):
    """Lambda handler for Bedrock SAST agent"""
    agent = BedrockSASTAgent()
    
    # Extract parameters from event
    repository_path = event.get('repository_path', '/tmp/repo')
    scan_id = event.get('scan_id', 'unknown')
    
    # Perform scan
    results = agent.scan(repository_path, scan_id)
    
    # Upload results to S3
    if agent.results_bucket:
        s3_key = f"scans/{scan_id}/bedrock_sast_results.json"
        s3_client.put_object(
            Bucket=agent.results_bucket,
            Key=s3_key,
            Body=json.dumps(results, indent=2),
            ContentType='application/json'
        )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'scan_id': scan_id,
            'findings_count': len(results['findings']),
            'attack_paths_count': len(results['attack_paths']),
            'ai_confidence': results['ai_confidence']
        })
    }