#!/usr/bin/env python3
"""
Test script for Hephaestus integration with the threat security framework.
This script demonstrates how to trigger Hephaestus analysis through different entry points.
"""

import json
import boto3
import os
from datetime import datetime

# Configuration
REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
STACK_PREFIX = os.environ.get('STACK_PREFIX', 'AISecurityAudit')

# Initialize AWS clients
sns_client = boto3.client('sns', region_name=REGION)
events_client = boto3.client('events', region_name=REGION)
lambda_client = boto3.client('lambda', region_name=REGION)

def test_sns_trigger():
    """Test triggering Hephaestus via SNS"""
    print("\n=== Testing SNS Trigger ===")
    
    # Get SNS topic ARN (you'll need to provide this)
    topic_arn = f"arn:aws:sns:{REGION}:YOUR_ACCOUNT_ID:security-scan-requests-{STACK_PREFIX}-SNS"
    
    message = {
        "message_type": "hephaestus_analysis",
        "repository_url": "https://github.com/example/test-repo",
        "branch": "main",
        "scan_type": "full",
        "max_vulnerabilities": 5,
        "enable_evolution": True
    }
    
    try:
        response = sns_client.publish(
            TopicArn=topic_arn,
            Message=json.dumps(message),
            MessageAttributes={
                'scan_enabled': {
                    'DataType': 'String',
                    'StringValue': 'true'
                }
            }
        )
        print(f"✓ SNS message published: {response['MessageId']}")
        return response['MessageId']
    except Exception as e:
        print(f"✗ Failed to publish SNS message: {e}")
        return None


def test_eventbridge_trigger():
    """Test triggering Hephaestus via EventBridge"""
    print("\n=== Testing EventBridge Trigger ===")
    
    event = {
        'Source': 'custom.security',
        'DetailType': 'Hephaestus Analysis Request',
        'Detail': json.dumps({
            'repository_url': 'https://github.com/example/test-repo',
            'branch': 'main',
            'scan_type': 'targeted'
        })
    }
    
    try:
        response = events_client.put_events(Entries=[event])
        if response['FailedEntryCount'] == 0:
            print(f"✓ EventBridge event sent successfully")
            return response['Entries'][0]['EventId']
        else:
            print(f"✗ Failed to send EventBridge event: {response}")
            return None
    except Exception as e:
        print(f"✗ Failed to send EventBridge event: {e}")
        return None


def test_direct_lambda_invoke():
    """Test invoking AI Security Analyzer Lambda directly"""
    print("\n=== Testing Direct Lambda Invoke ===")
    
    function_name = f"{STACK_PREFIX}-Lambda-AISecurityAnalyzerLambda"
    
    payload = {
        "action": "hephaestus_cognitive",
        "payload": {
            "repository_url": "https://github.com/example/test-repo",
            "branch": "main",
            "scan_type": "full",
            "max_vulnerabilities": 3
        }
    }
    
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='Event',  # Async
            Payload=json.dumps(payload)
        )
        print(f"✓ Lambda invoked successfully: Status {response['StatusCode']}")
        return response.get('StatusCode') == 202
    except Exception as e:
        print(f"✗ Failed to invoke Lambda: {e}")
        return None


def verify_api_endpoint():
    """Verify API Gateway endpoint configuration"""
    print("\n=== API Gateway Endpoint ===")
    print(f"Endpoint: POST https://YOUR_API_ID.execute-api.{REGION}.amazonaws.com/v1/ai/hephaestus-cognitive")
    print("Headers: Content-Type: application/json, Authorization: AWS4-HMAC-SHA256...")
    print("Body:")
    print(json.dumps({
        "action": "hephaestus_cognitive",
        "payload": {
            "repository_url": "https://github.com/your-org/your-repo",
            "branch": "main"
        }
    }, indent=2))


def main():
    """Run all integration tests"""
    print("=== Hephaestus Integration Test Suite ===")
    print(f"Region: {REGION}")
    print(f"Stack Prefix: {STACK_PREFIX}")
    print(f"Timestamp: {datetime.utcnow().isoformat()}")
    
    # Note: Update these with your actual AWS account ID and resource names
    print("\n⚠️  Note: Update the script with your AWS account ID and resource names before running")
    
    # Run tests (commented out to prevent accidental triggers)
    # test_sns_trigger()
    # test_eventbridge_trigger()
    # test_direct_lambda_invoke()
    
    # Show API endpoint info
    verify_api_endpoint()
    
    print("\n=== Test Configuration ===")
    print("1. SNS Topic: Update topic_arn in test_sns_trigger()")
    print("2. Lambda Function: Update function_name in test_direct_lambda_invoke()")
    print("3. API Gateway: Use AWS CLI or SDK with proper IAM credentials")
    
    print("\n=== Monitoring ===")
    print(f"CloudWatch Logs: /aws/lambda/{STACK_PREFIX}-Lambda-AISecurityAnalyzerLambda")
    print(f"DynamoDB Table: SecurityScans")
    print(f"S3 Results: s3://YOUR-RESULTS-BUCKET/hephaestus-results/")


if __name__ == "__main__":
    main()