"""
AI Security Scanner client for GitHub Actions
"""
import os
import json
import time
import requests
from typing import Dict, Any, Optional
import boto3
from datetime import datetime

class AISecurityScanner:
    """Client for invoking AI Security Scanner"""
    
    def __init__(self):
        # AWS clients
        self.lambda_client = boto3.client('lambda')
        self.s3_client = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        
        # Configuration
        self.api_endpoint = os.environ.get('SECURITY_API_ENDPOINT')
        self.lambda_function = os.environ.get('CEO_LAMBDA_ARN', 'SecurityAuditCEOAgent')
        self.scan_table = os.environ.get('SCAN_TABLE', 'SecurityScans')
        self.results_bucket = os.environ.get('RESULTS_BUCKET', 'security-scan-results')
        
        # If API endpoint provided, use API mode
        self.use_api = bool(self.api_endpoint)
    
    def run_scan(self, repository_path: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run security scan and wait for results"""
        
        if self.use_api:
            return self._run_scan_via_api(repository_path, scan_config)
        else:
            return self._run_scan_via_lambda(repository_path, scan_config)
    
    def _run_scan_via_api(self, repository_path: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run scan via REST API"""
        
        # Prepare request
        api_url = f"{self.api_endpoint}/scan"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {os.environ.get("API_KEY", "")}'
        }
        
        payload = {
            'repository_url': scan_config['repository_url'],
            'branch': scan_config['branch'],
            'scan_options': scan_config['scan_options']
        }
        
        # Submit scan request
        response = requests.post(api_url, json=payload, headers=headers)
        response.raise_for_status()
        
        scan_result = response.json()
        scan_id = scan_result['scan_id']
        
        # Poll for results
        return self._wait_for_scan_completion(scan_id)
    
    def _run_scan_via_lambda(self, repository_path: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Run scan via direct Lambda invocation"""
        
        # Invoke CEO Lambda
        response = self.lambda_client.invoke(
            FunctionName=self.lambda_function,
            InvocationType='RequestResponse',
            Payload=json.dumps(scan_config)
        )
        
        result = json.loads(response['Payload'].read())
        
        if 'errorMessage' in result:
            raise Exception(f"Lambda error: {result['errorMessage']}")
        
        scan_id = result['scan_id']
        
        # Wait for scan completion
        return self._wait_for_scan_completion(scan_id)
    
    def _wait_for_scan_completion(self, scan_id: str, timeout: int = 600) -> Dict[str, Any]:
        """Wait for scan to complete and return results"""
        
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Check scan status
            scan_status = self._get_scan_status(scan_id)
            
            if scan_status['status'] == 'COMPLETED':
                # Get full results
                return self._get_scan_results(scan_id, scan_status)
            elif scan_status['status'] == 'FAILED':
                raise Exception(f"Scan failed: {scan_status.get('error_message', 'Unknown error')}")
            
            # Show progress
            print(f"⏳ Scan in progress... ({scan_status['status']})")
            time.sleep(10)
        
        raise Exception(f"Scan timeout after {timeout} seconds")
    
    def _get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status from DynamoDB"""
        
        if self.use_api:
            # Check via API
            api_url = f"{self.api_endpoint}/scan/{scan_id}/status"
            response = requests.get(api_url)
            response.raise_for_status()
            return response.json()
        else:
            # Check via DynamoDB
            table = self.dynamodb.Table(self.scan_table)
            response = table.get_item(Key={'scan_id': scan_id})
            
            if 'Item' not in response:
                raise Exception(f"Scan {scan_id} not found")
            
            return response['Item']
    
    def _get_scan_results(self, scan_id: str, scan_status: Dict[str, Any]) -> Dict[str, Any]:
        """Get complete scan results"""
        
        # Base result from scan status
        result = {
            'scan_id': scan_id,
            'status': 'completed',
            'total_findings': scan_status.get('total_findings', 0),
            'critical_findings': scan_status.get('critical_findings', 0),
            'high_findings': scan_status.get('high_findings', 0),
            'medium_findings': 0,
            'low_findings': 0,
            'business_risk_score': scan_status.get('business_risk_score', 0),
            'ai_confidence_score': scan_status.get('ai_confidence_score', 0),
            'risk_level': self._determine_risk_level(scan_status),
            'findings': []
        }
        
        # Try to get detailed results from S3
        try:
            if scan_status.get('s3_key'):
                s3_response = self.s3_client.get_object(
                    Bucket=self.results_bucket,
                    Key=scan_status['s3_key']
                )
                detailed_results = json.loads(s3_response['Body'].read())
                
                # Extract additional information
                result['findings'] = detailed_results.get('findings', [])[:20]  # Top 20 findings
                result['executive_summary'] = self._extract_executive_summary(detailed_results)
                result['recommendations'] = self._extract_recommendations(detailed_results)
                result['report_url'] = f"https://{self.results_bucket}.s3.amazonaws.com/{scan_status['s3_key']}"
                
                # Count findings by severity
                if 'statistics' in detailed_results:
                    stats = detailed_results['statistics']
                    result['medium_findings'] = stats.get('by_severity', {}).get('MEDIUM', 0)
                    result['low_findings'] = stats.get('by_severity', {}).get('LOW', 0)
                
        except Exception as e:
            print(f"⚠️  Warning: Could not load detailed results: {str(e)}")
        
        return result
    
    def _determine_risk_level(self, scan_status: Dict[str, Any]) -> str:
        """Determine overall risk level"""
        if scan_status.get('critical_findings', 0) > 0:
            return 'CRITICAL'
        elif scan_status.get('high_findings', 0) > 0:
            return 'HIGH'
        elif scan_status.get('business_risk_score', 0) > 50:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _extract_executive_summary(self, results: Dict[str, Any]) -> str:
        """Extract executive summary from results"""
        if 'ai_insights' in results:
            insights = results['ai_insights']
            if 'executive_summary' in insights:
                return insights['executive_summary']
            elif 'overall_posture' in insights:
                return insights['overall_posture']
        
        # Fallback summary
        stats = results.get('statistics', {})
        return f"Scan found {stats.get('total_findings', 0)} security issues with risk score {stats.get('business_risk_score', 0)}/100"
    
    def _extract_recommendations(self, results: Dict[str, Any]) -> list:
        """Extract top recommendations"""
        recommendations = []
        
        # From AI insights
        if 'ai_insights' in results:
            insights = results['ai_insights']
            if 'key_recommendations' in insights:
                recommendations.extend(insights['key_recommendations'][:3])
            elif 'immediate_actions' in insights:
                recommendations.extend(insights['immediate_actions'][:3])
        
        # From remediation plan
        if not recommendations and 'remediation_plan' in results:
            plan = results['remediation_plan']
            if 'immediate_actions' in plan:
                for action in plan['immediate_actions'][:3]:
                    recommendations.append(action.get('action', ''))
        
        # Fallback recommendations
        if not recommendations:
            if results.get('statistics', {}).get('by_severity', {}).get('CRITICAL', 0) > 0:
                recommendations.append("Fix critical vulnerabilities immediately")
            if results.get('statistics', {}).get('by_severity', {}).get('HIGH', 0) > 0:
                recommendations.append("Address high severity findings within 24 hours")
            recommendations.append("Review all security findings and implement fixes")
        
        return recommendations[:5]


# Standalone mode for testing
if __name__ == '__main__':
    scanner = AISecurityScanner()
    
    # Test configuration
    test_config = {
        'repository_url': 'https://github.com/example/repo',
        'branch': 'main',
        'scan_options': {
            'scan_type': 'full',
            'business_context': 'normal'
        }
    }
    
    try:
        result = scanner.run_scan('.', test_config)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {str(e)}")