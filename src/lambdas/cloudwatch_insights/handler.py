"""
CloudWatch Insights Lambda - Analyze logs for security patterns
"""
import json
import os
import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Any


logs_client = boto3.client('logs')
s3_client = boto3.client('s3')


def handler(event, context):
    """
    Analyze CloudWatch logs for security patterns and anomalies
    
    Args:
        event: Lambda event containing log group names and query parameters
        context: Lambda context
        
    Returns:
        Analysis results
    """
    try:
        # Extract parameters
        log_groups = event.get('log_groups', [])
        time_range_hours = event.get('time_range_hours', 24)
        security_patterns = event.get('patterns', DEFAULT_SECURITY_PATTERNS)
        
        # Set time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)
        
        # Run security queries
        findings = []
        
        for pattern in security_patterns:
            query_result = run_insights_query(
                log_groups,
                pattern['query'],
                start_time,
                end_time
            )
            
            if query_result['results']:
                findings.append({
                    'pattern': pattern['name'],
                    'severity': pattern['severity'],
                    'count': len(query_result['results']),
                    'samples': query_result['results'][:5],  # First 5 samples
                    'description': pattern['description']
                })
        
        # Generate summary
        summary = {
            'scan_time': datetime.utcnow().isoformat(),
            'log_groups': log_groups,
            'time_range_hours': time_range_hours,
            'total_findings': len(findings),
            'critical_findings': len([f for f in findings if f['severity'] == 'critical']),
            'high_findings': len([f for f in findings if f['severity'] == 'high']),
            'findings': findings
        }
        
        # Store results
        if findings:
            store_results(summary)
        
        return {
            'statusCode': 200,
            'body': json.dumps(summary)
        }
        
    except Exception as e:
        print(f"Error in CloudWatch Insights analysis: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def run_insights_query(log_groups: List[str], query: str, 
                      start_time: datetime, end_time: datetime) -> Dict[str, Any]:
    """Run CloudWatch Insights query"""
    try:
        # Start query
        response = logs_client.start_query(
            logGroupNames=log_groups,
            startTime=int(start_time.timestamp()),
            endTime=int(end_time.timestamp()),
            queryString=query
        )
        
        query_id = response['queryId']
        
        # Wait for query to complete
        status = 'Running'
        while status == 'Running':
            response = logs_client.get_query_results(queryId=query_id)
            status = response['status']
            
            if status == 'Running':
                time.sleep(1)
        
        return {
            'status': status,
            'results': response.get('results', []),
            'statistics': response.get('statistics', {})
        }
        
    except Exception as e:
        print(f"Query error: {str(e)}")
        return {'status': 'Failed', 'results': [], 'error': str(e)}


def store_results(summary: Dict[str, Any]):
    """Store analysis results in S3"""
    try:
        bucket = os.environ.get('RESULTS_BUCKET')
        key = f"cloudwatch-insights/{datetime.utcnow().strftime('%Y/%m/%d')}/analysis-{int(datetime.utcnow().timestamp())}.json"
        
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(summary, indent=2),
            ContentType='application/json'
        )
        
    except Exception as e:
        print(f"Error storing results: {str(e)}")


# Default security patterns to search for
DEFAULT_SECURITY_PATTERNS = [
    {
        'name': 'Failed Authentication',
        'query': '''
        fields @timestamp, @message
        | filter @message like /(?i)(failed|invalid|unauthorized|denied).*(?i)(auth|login|password)/
        | stats count() by bin(5m)
        ''',
        'severity': 'high',
        'description': 'Failed authentication attempts'
    },
    {
        'name': 'SQL Injection Attempts',
        'query': '''
        fields @timestamp, @message
        | filter @message like /(?i)(union.*select|drop.*table|insert.*into|update.*set)/
        | stats count() by bin(5m)
        ''',
        'severity': 'critical',
        'description': 'Potential SQL injection attempts'
    },
    {
        'name': 'Privilege Escalation',
        'query': '''
        fields @timestamp, @message
        | filter @message like /(?i)(sudo|admin|root|privilege|escalat)/
        | stats count() by bin(5m)
        ''',
        'severity': 'critical',
        'description': 'Potential privilege escalation attempts'
    },
    {
        'name': 'Data Exfiltration',
        'query': '''
        fields @timestamp, @message
        | filter @message like /(?i)(download|export|transfer).*(?i)(database|data|file)/
        | stats count() by bin(5m)
        ''',
        'severity': 'high',
        'description': 'Potential data exfiltration'
    }
]